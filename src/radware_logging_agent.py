# Main entry point for the Radware Logging Agents

import argparse
import os
from logging_agent.local_agent import start_local_agent
from logging_agent.config_reader import Config
from logging_agent.config_verification import verify_configuration
from logging_agent.logging_config import get_logger

def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description="Radware Logging Agents")
    parser.add_argument('--verify', action='store_true', help='Verify the configuration and exit')

    # Parse arguments
    args = parser.parse_args()

    # Load the configuration
    config = Config().config
    agents_config = [Config().get_agent_config(agent_name) for agent_name in Config().get_all_agent_names()]

    if args.verify:
        # Set environment variable to adjust logging behavior
        os.environ['RLA_VERIFY_MODE'] = '1'
        # Perform configuration verification only and exit
        if verify_configuration(config, agents_config):
            print("Configuration verification successful.")
        else:
            print("Configuration verification failed. Please check the logs for more details.")
    else:
        # Unset environment variable to ensure standard logging behavior
        os.environ['RLA_VERIFY_MODE'] = '0'
        # Initialize logger for use in the else branch
        logger = get_logger('radware_logging_agent')

        # Determine if configuration verification is enabled
        verify_mode = config['debug'].get('config_verification', True)

        # Check if configuration verification should be skipped
        if not verify_mode:
            logger.info("Configuration verification is disabled. Skipping...")
            start_local_agent()
            return

        # Perform configuration verification using standard logging
        if verify_configuration(config, agents_config):
            # Only start the local agent if the configuration verification is successful
            start_local_agent()
        else:
            # Since we're not in verification mode, use the logger for error messaging
            logger.error(
                "Configuration verification failed. Please check the logs for more details. The agent will not start.")


if __name__ == "__main__":
    main()
