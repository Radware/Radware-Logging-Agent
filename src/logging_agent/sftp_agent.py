import asyncio
import os
from typing import Dict, List, Optional, TYPE_CHECKING

from .file_agent import FileQueueAgent

try:  # pragma: no cover - optional dependency imported lazily
    import asyncssh
    from asyncssh import sftp as asyncssh_sftp
except ImportError:  # pragma: no cover - handled gracefully in start()
    asyncssh = None
    asyncssh_sftp = None

if TYPE_CHECKING:  # pragma: no cover - used for type checking only
    import asyncssh as asyncssh_module


if asyncssh_sftp is not None:

    class _TrackedFile(asyncssh_sftp.LocalFile):
        """Wrap AsyncSSH LocalFile to trigger callbacks when uploads finish."""

        def __init__(self, agent: "SFTPAgent", relative_path: str, file_obj):
            super().__init__(file_obj)
            self._agent = agent
            self._relative_path = relative_path

        async def close(self) -> None:  # pragma: no cover - exercised via agent logic
            await super().close()
            try:
                self._agent._handle_upload_complete(self._relative_path)
            except Exception:
                self._agent.logger.exception("Failed to enqueue uploaded file %s", self._relative_path)

else:  # pragma: no cover - ensures module imports even without asyncssh

    class _TrackedFile:  # type: ignore[too-many-ancestors]
        pass


class SFTPAgent(FileQueueAgent):
    """Run an embedded SFTP service and enqueue completed uploads."""

    def __init__(self, agent_config: dict) -> None:
        if asyncssh is None:
            raise ImportError("asyncssh is required for the SFTPAgent")

        settings = agent_config.get("sftp_settings", {})
        completion = settings.get("completion_strategy")
        drop_directory = settings.get("drop_directory", "")
        super().__init__(
            agent_config,
            root_path=drop_directory,
            completion_strategy=completion,
            input_type="sftp",
        )

        listen_settings = settings.get("listen", {})
        self.listen_host = listen_settings.get("host", "")
        self.listen_port = int(listen_settings.get("port", 0))
        self.host_keys = settings.get("host_keys", [])
        self.polling_interval = int(settings.get("polling_interval_seconds", 5))

        self.credential_policy = settings.get("credential_policy", {})
        self.credential_mode = (self.credential_policy.get("mode") or "static").lower()

        self._static_passwords: Dict[str, str] = {}
        self._public_keys: Dict[str, List["asyncssh_module.SSHKey"]] = {}
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._shutdown_event: Optional[asyncio.Event] = None
        self._server: Optional["asyncssh_module.SSHAcceptor"] = None

        self._parse_credentials()

    def _parse_credentials(self) -> None:
        users = self.credential_policy.get("users", [])
        if self.credential_mode == "static":
            self._static_passwords = {
                user["username"]: user["password"]
                for user in users
                if user.get("username") and user.get("password")
            }
        elif self.credential_mode == "public_key":
            key_map: Dict[str, List["asyncssh_module.SSHKey"]] = {}
            for user in users:
                username = user.get("username")
                if not username:
                    continue
                keys = []
                for entry in user.get("authorized_keys", []):
                    try:
                        keys.append(asyncssh.import_public_key(entry))
                    except Exception as exc:  # pragma: no cover - defensive logging
                        self.logger.error("Invalid authorized key for %s: %s", username, exc)
                if keys:
                    key_map[username] = keys
            self._public_keys = key_map
        else:
            raise ValueError(f"Unsupported credential mode: {self.credential_mode}")

    def start(self) -> None:
        self.logger.info("Starting SFTPAgent on %s:%s", self.listen_host or "0.0.0.0", self.listen_port)
        self._start_worker_threads()

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._shutdown_event = asyncio.Event()

        try:
            self._loop.run_until_complete(self._serve())
        finally:
            try:
                self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            finally:
                asyncio.set_event_loop(None)
                self._loop.close()
                self._loop = None

        # Drain any remaining files discovered during shutdown
        self._scan_for_files()
        self._await_worker_completion()
        self.logger.info("SFTPAgent stopped for %s", self.root_path)

    async def _serve(self) -> None:
        assert asyncssh is not None
        assert self._shutdown_event is not None

        server_kwargs = {
            "host": self.listen_host,
            "port": self.listen_port,
            "server_factory": self._create_ssh_server_factory(),
            "server_host_keys": self.host_keys,
            "sftp_factory": self._create_sftp_server,
            "allow_scp": False,
            "process_factory": None,
            "session_factory": None,
            "password_auth": self.credential_mode == "static",
            "public_key_auth": self.credential_mode == "public_key",
        }

        self._server = await asyncssh.listen(**server_kwargs)
        self.logger.info("SFTP server listening on port %s", self._server.get_port())

        while not self.stop_event.is_set():
            self._scan_for_files()
            try:
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=self.polling_interval)
                break
            except asyncio.TimeoutError:
                continue

        if self._server:
            self._server.close()
            await self._server.wait_closed()

    def stop(self) -> None:
        self.logger.info("Stopping SFTPAgent for %s", self.root_path)
        super().stop()
        if self._loop and self._shutdown_event:
            self._loop.call_soon_threadsafe(self._shutdown_event.set)

    def _create_ssh_server_factory(self):
        agent = self

        class _SFTPSSHServer(asyncssh.SSHServer):
            def connection_made(self, conn):  # pragma: no cover - authentication only
                self._conn = conn

            def password_auth_supported(self) -> bool:
                return agent.credential_mode == "static"

            async def validate_password(self, username: str, password: str) -> bool:
                expected = agent._static_passwords.get(username)
                return expected is not None and expected == password

            def public_key_auth_supported(self) -> bool:
                return agent.credential_mode == "public_key"

            async def validate_public_key(self, username: str, key: "asyncssh_module.SSHKey") -> bool:
                allowed = agent._public_keys.get(username, [])
                return any(key == candidate for candidate in allowed)

        return _SFTPSSHServer

    def _create_sftp_server(self, chan: "asyncssh_module.SSHServerChannel") -> "asyncssh_module.SFTPServer":
        agent = self

        class _UploadAwareServer(asyncssh.SFTPServer):
            def __init__(self, channel):
                super().__init__(channel, chroot=os.fsencode(agent.root_path))

            def open(self, path, pflags, attrs):
                file_obj = super().open(path, pflags, attrs)
                if not agent._is_write_mode(pflags):
                    return file_obj
                relative = os.fsdecode(path)
                return _TrackedFile(agent, relative, file_obj)

            def open56(self, path, desired_access, flags, attrs):  # pragma: no cover - depends on client version
                file_obj = super().open56(path, desired_access, flags, attrs)
                if not agent._is_write_mode_v56(desired_access, flags):
                    return file_obj
                relative = os.fsdecode(path)
                return _TrackedFile(agent, relative, file_obj)

        return _UploadAwareServer(chan)

    def _is_write_mode(self, pflags: int) -> bool:
        write_flags = (
            asyncssh_sftp.FXF_WRITE
            | asyncssh_sftp.FXF_CREAT
            | asyncssh_sftp.FXF_TRUNC
            | asyncssh_sftp.FXF_APPEND
        )
        return bool(pflags & write_flags)

    def _is_write_mode_v56(self, desired_access: int, flags: int) -> bool:
        if desired_access & (asyncssh_sftp.ACE4_WRITE_DATA | asyncssh_sftp.ACE4_APPEND_DATA):
            return True
        disposition = flags & asyncssh_sftp.FXF_ACCESS_DISPOSITION
        return disposition in {
            asyncssh_sftp.FXF_CREATE_NEW,
            asyncssh_sftp.FXF_CREATE_TRUNCATE,
            asyncssh_sftp.FXF_OPEN_OR_CREATE,
            asyncssh_sftp.FXF_TRUNCATE_EXISTING,
        }

    def _resolve_relative_path(self, relative_path: str) -> str:
        normalized = os.path.normpath(relative_path).lstrip(os.sep)
        absolute = os.path.abspath(os.path.join(self.root_path, normalized))
        if not self._is_within_root(absolute):
            raise ValueError(f"Upload path {relative_path} escapes drop directory")
        return absolute

    def _handle_upload_complete(self, relative_path: str) -> None:
        try:
            absolute_path = self._resolve_relative_path(relative_path)
        except ValueError as exc:
            self.logger.error("Rejected upload outside drop directory: %s", exc)
            return

        if not os.path.exists(absolute_path):
            self.logger.debug("Uploaded path no longer exists: %s", absolute_path)
            return

        self._queue_file(absolute_path)
