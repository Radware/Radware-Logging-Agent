#!/bin/bash

# Populate the configuration file from the template using environment variables for agent1
envsubst < /usr/src/app/rla.yaml.template > /usr/src/app/rla.yaml

# Check for additional agents and append their configurations
i=2
while : ; do
    # Check if the current agent should be added
    if [ -z "$(eval echo \${AGENT${i}_SQS_QUEUE_NAME})" ]; then
        break
    fi

    # Read environment variables for each agent configuration
    num_threads=$(eval echo \${AGENT${i}_NUM_THREADS:-5})  # Default to 5 threads if not specified
    agent_product=$(eval echo \${AGENT${i}_PRODUCT:-"cloud_waap"})  # Default product
    agent_type=$(eval echo \${AGENT${i}_TYPE:-"sqs"})  # Default type
    queue_name=$(eval echo \${AGENT${i}_SQS_QUEUE_NAME})
    delete_on_failure=$(eval echo \${AGENT${i}_DELETE_ON_FAILURE:-false})  # Default to false

    # Logs configuration
    access=$(eval echo \${AGENT${i}_LOG_ACCESS:-true})
    waf=$(eval echo \${AGENT${i}_LOG_WAF:-true})
    bot=$(eval echo \${AGENT${i}_LOG_BOT:-true})
    ddos=$(eval echo \${AGENT${i}_LOG_DDOS:-true})
    webddos=$(eval echo \${AGENT${i}_LOG_WEBDDOS:-true})
    csp=$(eval echo \${AGENT${i}_LOG_CSP:-true})

    # Append configuration for this agent
    cat << EOF >> /usr/src/app/rla.yaml
  - name: "agent$i"
    type: "$agent_type"
    num_worker_threads: $num_threads
    product: "$agent_product"
    sqs_settings:
      queue_name: "$queue_name"
      delete_on_failure: $delete_on_failure
    logs:
      Access: $access
      WAF: $waf
      Bot: $bot
      DDoS: $ddos
      WebDDoS: $webddos
      CSP: $csp
EOF

    # Increment to check for the next agent
    ((i++))
done

# Start the application
exec python ./radware_logging_agent.py
