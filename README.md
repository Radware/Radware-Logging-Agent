# Radware Logging Agents (RLA)

RLA is a log processing tool designed to streamline the integration of Radware products with Security Information and Event Management (SIEM) systems. In its first major release, RLA is focuses on robust support of Radware Cloud WAAP logs, utilizing the Cloud WAAP's capability to export security and access logs to an AWS S3 Bucket.


## Features

### Log Ingestion
- **Multi-Agent Architecture**: Supports multiple agents, each with distinct configurations for targeted log processing.
- **Cloud WAAP Integration**: Efficiently ingests logs from Radware Cloud WAAP exported to AWS S3.
- **Versatile Log Handling**: Capable of processing various log types including Access, WAF, Bot, DDoS, and Web DDoS.

### Log Processing and Conversion
- **Dynamic Format Conversion**: Converts logs to multiple formats such as JSON, ndJSON, CEF, and LEEF, with customizable options.
- **Selective Log Processing**: Provides the ability to filter and process specific log types, enhancing control over log ingestion.

### Log Enrichment
- **Enhanced Information**: Adds valuable enrichments to logs, improving their utility and integration with SIEM systems.

### Customization and Flexibility
- **Configurable Homogenization**: Optional normalization of log fields across different log types for consistency.
- **Customizable Timestamp and Severity Formats**: Allows specific settings for timestamp and log severity formats in output logs.
- **Adaptable Output Configurations**: Supports various output methods and customization for delimiters and other format-specific settings.

## Configuration

Configure RLA through the `rla.yaml` file, which includes settings for AWS SQS integration, output formats, log types, and output methods.

### Sample Configuration
```yaml
aws_credentials:
  access_key_id: 'your_access_key'
  secret_access_key: 'your_secret_key'
  region: 'your_region'

agents:
  - name: "cloud_waap"
    type: "sqs"
    num_worker_threads: 5
    product: "cloud_waap"
    sqs_settings:
      queue_name: 'your_sqs_queue_name'
      delete_on_failure: false
    logs:
      Access: true
      WAF: true
      Bot: true
      DDoS: true
      WebDDoS: true
      CSP: false

output:
  output_format: 'json'  # Supports 'json', 'ndjson', 'cef', 'leef'
  type: 'tcp'
  destination: 'your_destination_address'
```

## Installation on Linux

To install the Radware Logging Agent on a Linux system, follow these steps:

1. **Clone the Repository**: 
   First, clone the repository from GitHub:
   ```bash
   git clone https://github.com/Radware/Radware-Logging-Agent.git
   cd Radware-Logging-Agent
   ```
2. **Run the Installation Script**:
   The repository includes a script setup_rla.sh which automates the installation process:
   ```bash
   chmod +x setup_rla.sh
   ./setup_rla.sh
   ```
   Follow the instructions provided by the script. It will guide you through installing Python 3.8 or higher, pip3, and other necessary components.
3. **Configure rla.yaml**:
   After installation, configure the rla.yaml file according to your environment and requirements.
4. **Start the Service**:
   Once configured, you can start the Radware Logging Agent using the systemd service:
   ```bash
   sudo systemctl start rla.service
   ```
   

## Roadmap / Future Plans

The Radware Logging Agent is continually evolving, with plans to expand its capabilities and support a wider range of functionalities. Here's what's on the horizon:

### Near-Term Goals
- **Cloud WAAP API Integration**: In addition to the current AWS S3 support, we plan to introduce Cloud WAAP API as another input option. This enhancement will provide more flexibility in how logs are ingested from Radware Cloud WAAP.

### Long-Term Vision
- **Expanding Input Options**: Future updates aim to incorporate additional input methods such as SCP, TCP, and HTTP. This expansion will facilitate the support of a broader range of Radware products.
- **Support for Additional Radware Products**: Our goal is to extend RLA's capabilities to include more Radware products, enriching and customizing their logs for optimal SIEM integration.
- **Versatile Protocol Support**: We're committed to enabling easy log transmission through various protocols, ensuring seamless integration with diverse SIEM systems.

Stay tuned for these exciting developments as we continue to enhance the Radware Logging Agent's functionalities to meet the evolving needs of our users.
