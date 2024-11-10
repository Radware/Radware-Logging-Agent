import os
import shutil

def update_dev_environment(version_number):
    base_path = f"dev_env/rla_{version_number}"

    # Check if the target directory exists
    if not os.path.exists(base_path):
        print(f"Target directory {base_path} does not exist. Please set up the environment first.")
        return

    # Copy specific files directly to the base_path
    files_to_copy = [
        "src/radware_logging_agent.py",
        "install/install_rla.sh",
        "docs/README.md",
        "requirements.txt",
        "install/uninstall.sh"
    ]
    for filename in files_to_copy:
        shutil.copy(filename, os.path.join(base_path, os.path.basename(filename)))

    # Handle Dockerfile specifically
    shutil.copy("docker/Dockerfile", os.path.join(base_path, "Dockerfile"))

    # Recreate and copy src directory contents
    src_dir = "src/logging_agent"
    dest_src_dir = os.path.join(base_path, "logging_agent")
    if os.path.exists(dest_src_dir):
        shutil.rmtree(dest_src_dir)
    shutil.copytree(src_dir, dest_src_dir, ignore=shutil.ignore_patterns('*__pycache__*', '*.md'))

    # Recreate and copy docker directory contents
    docker_dir = "docker"
    dest_docker_dir = os.path.join(base_path, "docker")
    if os.path.exists(dest_docker_dir):
        shutil.rmtree(dest_docker_dir)
    os.makedirs(dest_docker_dir, exist_ok=True)
    for item in os.listdir(docker_dir):
        s = os.path.join(docker_dir, item)
        d = os.path.join(dest_docker_dir, item)
        if os.path.isdir(s):
            shutil.copytree(s, d, ignore=shutil.ignore_patterns('*__pycache__*', '*.md'))
        else:
            if item != 'Dockerfile':  # Avoid copying Dockerfile again
                shutil.copy2(s, d)

    # Ensure the 'ssl' directory is present
    ssl_path = os.path.join(base_path, "ssl")
    os.makedirs(ssl_path, exist_ok=True)

    # Print completion message
    print(f"Development environment updated at: {base_path}")

# Example usage
update_dev_environment("1.2.1")
