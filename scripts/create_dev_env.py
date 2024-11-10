import os
import shutil

def setup_dev_environment(version_number):
    base_path = f"dev_env/rla_{version_number}"

    # Create the base directory if it doesn't exist
    os.makedirs(base_path, exist_ok=True)

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

    # Copy rla.yaml configuration file
    shutil.copy("config/rla.yaml", os.path.join(base_path, "rla.yaml"))

    # Handle Dockerfile specifically
    shutil.copy("docker/Dockerfile", os.path.join(base_path, "Dockerfile"))

    # Copy src directory contents to base_path directly
    src_dir = "src/logging_agent"
    dest_src_dir = os.path.join(base_path, "logging_agent")
    if os.path.exists(dest_src_dir):
        shutil.rmtree(dest_src_dir)
    shutil.copytree(src_dir, dest_src_dir, ignore=shutil.ignore_patterns('*__pycache__*', '*.md'))

    # Copy docker directory contents to base_path/docker
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

    # Create an empty 'ssl' directory
    ssl_path = os.path.join(base_path, "ssl")
    os.makedirs(ssl_path, exist_ok=True)

    # Print completion message
    print(f"Development environment setup at: {base_path}")

# Example usage
setup_dev_environment("1.3.1")
