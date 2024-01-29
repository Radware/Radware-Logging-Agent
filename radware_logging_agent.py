# Main entry point for the Radware Logging Agents

# Import the function to start the local agent from the local_agent module
import argparse
from logging_agent.local_agent import start_local_agent
from logging_agent.config_reader import Config
from logging_agent.config_verification import verify_configuration

def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description="Radware Logging Agents")
    parser.add_argument('--verify', action='store_true', help='Verify the configuration and exit')

    # Parse arguments
    args = parser.parse_args()

    # Load the configuration
    config = Config().config

    if args.verify:
        # Perform configuration verification only and exit
        if verify_configuration(config):
            print("Configuration verification successful.")
        else:
            print("Configuration verification failed. Please check the logs for more details.")
    else:
        # Start the local agent
        start_local_agent()

if __name__ == "__main__":
    main()