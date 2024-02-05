import pytest
from unittest.mock import MagicMock
import pytest
import threading
from logging_agent.local_agent import start_local_agent, start_agents, stop_agents
from unittest.mock import Mock, patch

@pytest.fixture
def mock_sqs_agent():
    with patch('logging_agent.local_agent.SQSAgent') as mock:
        yield mock


@pytest.fixture
def mock_config():
    with patch('logging_agent.local_agent.Config') as MockConfig:
        mock_instance = MockConfig.return_value
        mock_instance.config = {
            'output': {'output_format': 'json'},
            'agents': [{'name': 'agent1', 'type': 'sqs'}, {'name': 'agent2', 'type': 'sqs'}]
        }
        yield mock_instance


def test_start_agents_with_sqs_agents(mock_sqs_agent, mock_config):
    agents_config = [{'name': 'agent1', 'type': 'sqs'}, {'name': 'agent2', 'type': 'sqs'}]
    agents = start_agents(agents_config)
    assert len(agents) == 2
    # Additional assertions can go here

def test_start_local_agent(mock_config, mock_sqs_agent):
    with patch('threading.Thread') as MockThread:
        MockThread.return_value.is_alive.return_value = False
        start_local_agent()
        # Verify start_agents and any other expected interactions


@pytest.fixture
def mock_agent_and_thread():
    mock_agent = MagicMock()
    mock_thread = MagicMock()
    return mock_agent, mock_thread


def test_stop_agents_calls_stop_and_joins_threads(mock_agent_and_thread):
    mock_agent, mock_thread = mock_agent_and_thread
    agents = [(mock_agent, mock_thread)]

    stop_agents(agents)

    # Check that stop was called on each agent
    mock_agent.stop.assert_called_once()

    # Check that join was called on each thread
    mock_thread.join.assert_called_once()
