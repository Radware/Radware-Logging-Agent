import threading
from .sqs_agent import SQSAgent  # Assuming SQSAgent is the refactored class
from .config_reader import Config
from .logging_config import get_logger
from .field_mappings import FieldMappings  # Import the FieldMappings singleton


# Load configuration using the Config singleton
config = Config().config

# Initialize logger for this module
logger = get_logger('local_agent')


def start_agents(agents_config):
    """Starts multiple agents based on their configurations."""
    agents = []
    for agent_config in agents_config:
        agent_type = agent_config.get('type')
        if agent_type == 'sqs':
            print(agent_config)
            agent = SQSAgent(agent_config)
        else:
            # Handle other types or log an error
            continue

        agent_thread = threading.Thread(target=agent.start)
        agent_thread.daemon = True
        agent_thread.start()
        agents.append((agent, agent_thread))

    return agents


def stop_agents(agents):
    """Stops all running agents."""
    for agent, agent_thread in agents:
        agent.stop()  # Assuming each agent has a stop method
        agent_thread.join()

def start_local_agent():
    logger.debug("Starting local agent.")

    # Get the names of all agents from the configuration
    agent_names = Config().get_all_agent_names()

    # Load field mappings for all products
    products = Config().get_all_products()
    output_format = config['output'].get('output_format', 'json')
    FieldMappings.load_field_mappings(products, output_format)

    # Load configurations for each agent and start them
    agents_config = [Config().get_agent_config(agent_name) for agent_name in agent_names]
    agents = start_agents(agents_config)

    try:
        # Keep the main thread running while agents are active
        while any(agent_thread.is_alive() for _, agent_thread in agents):
            threading.Event().wait(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received. Stopping agents...")
        stop_agents(agents)

# Entry point for the script
if __name__ == "__main__":
    start_local_agent()
