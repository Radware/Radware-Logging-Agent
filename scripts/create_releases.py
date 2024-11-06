import os
import tarfile
from tarfile import TarInfo

def generate_release(version_number):
    # Define the base path for the release content
    base_path = "rla"

    # Create releases folder if it doesn't exist
    releases_folder = "releases"
    os.makedirs(releases_folder, exist_ok=True)

    # Path for the tar.gz file
    release_filename = f"rla_v{version_number}.tar.gz"
    release_path = os.path.join(releases_folder, release_filename)

    # Create a tar.gz file
    with tarfile.open(release_path, "w:gz") as tar:
        # Add clean rla.yaml as rla.yaml under the base_path
        tar.add("config/rla.yaml", arcname=f"{base_path}/rla.yaml")

        # Add other specified files under the base_path directly
        specific_files = [
            "src/radware_logging_agent.py",
            "install/install_rla.sh",
            "docs/README.md",
            "requirements.txt",
            "install/uninstall.sh"
        ]
        for filename in specific_files:
            arcname = f"{base_path}/{os.path.basename(filename)}"
            tar.add(filename, arcname=arcname)

        # Function to exclude __pycache__ directories and unwanted files
        def exclude_unwanted(tarinfo):
            if "__pycache__" in tarinfo.name or tarinfo.name.endswith('.md'):
                return None
            return tarinfo

        # Add src directory contents, applying exclusion rules
        for root, dirs, files in os.walk("src"):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.join(base_path, os.path.relpath(file_path, start="src"))
                tar.add(file_path, arcname=arcname, filter=exclude_unwanted)

        # Handle Dockerfile specifically
        tar.add("docker/Dockerfile", arcname=f"{base_path}/Dockerfile")

        # Add the rest of the docker directory contents under rla/docker
        for root, dirs, files in os.walk("docker"):
            for file in files:
                if file != "Dockerfile":  # Exclude the Dockerfile since it's handled separately
                    file_path = os.path.join(root, file)
                    arcname = os.path.join(base_path, "docker", os.path.relpath(file_path, start="docker"))
                    tar.add(file_path, arcname=arcname, filter=exclude_unwanted)

        # Add an empty 'ssl' directory to the tar.gz with specified permissions
        ssl_info = TarInfo(name=f"{base_path}/ssl/")
        ssl_info.type = tarfile.DIRTYPE
        ssl_info.mode = 0o755  # Readable and accessible to the owner and readable by others
        tar.addfile(ssl_info)

        # Add 'extras' folder and its subfolders and files, applying exclusion rules
        for root, dirs, files in os.walk("extras"):
            for file in files:
                file_path = os.path.join(root, file)
                # Adjust arcname to prepend the 'extras' folder under 'rla/'
                arcname = os.path.join(base_path, "extras", os.path.relpath(file_path, start="extras"))
                tar.add(file_path, arcname=arcname, filter=exclude_unwanted)

    print(f"Release generated: {release_path}")

# Example usage
generate_release("1.3.1")
