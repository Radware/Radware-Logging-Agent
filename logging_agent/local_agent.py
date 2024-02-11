import threading
import time
from .sqs_agent import SQSAgent  # Adjust import as needed
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
            agent = SQSAgent(agent_config)
        else:
            logger.error(f"Unsupported agent type: {agent_type}")
            continue  # Skip unsupported agent types

        agent_thread = threading.Thread(target=agent.start)
        agent_thread.daemon = True
        agent_thread.start()
        agents.append((agent, agent_thread))

    return agents

def stop_agents(agents):
    """Stops all running agents."""
    for agent, agent_thread in agents:
        logger.info(f"Stopping agent: {agent}")
        agent.stop()  # Signal the agent to stop
        agent_thread.join(timeout=10)  # Wait for the agent to stop, with timeout

        if agent_thread.is_alive():
            logger.warning(f"Agent {agent} did not stop gracefully within the timeout period.")

def start_local_agent():
    logger.info("Starting local agent.")

    products = Config().get_all_products()
    output_format = config['output'].get('output_format', 'json')
    FieldMappings.load_field_mappings(products, output_format)

    # Load configurations for each agent and start them
    agents_config = [Config().get_agent_config(agent_name) for agent_name in Config().get_all_agent_names()]
    agents = start_agents(agents_config)

    try:
        # Keep the main thread running while agents are active
        while any(agent_thread.is_alive() for _, agent_thread in agents):
            threading.Event().wait(1)
    except KeyboardInterrupt:
        logger.info("Shutdown signal received. Attempting to stop all agents gracefully...")
        stop_agents(agents)
        logger.info("All agents have been stopped or timed out.")

if __name__ == "__main__":
    start_local_agent()
