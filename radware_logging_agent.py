# Main entry point for the Radware Logging Agent

# Import the function to start the local agent from the local_agent module
from logging_agent.local_agent import start_local_agent

if __name__ == "__main__":
    # Call the function to start the local agent
    # This function initializes and starts the necessary components for log processing
    start_local_agent()