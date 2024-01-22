# Radware Logging Agent (RLA)

RLA is a log processing tool designed to streamline the integration of Radware products with Security Information and Event Management (SIEM) systems. In its first major release, RLA is focuses on robust support of Radware Cloud WAAP logs, utilizing the Cloud WAAP's capability to export security and access logs to an AWS S3 Bucket.


## Features

### Log Ingestion
- **Cloud WAAP Integration**: Ingests logs from Radware Cloud WAAP exported to AWS S3.
- **Support for Multiple Log Types**: Handles various log types including Access, WAF, Bot, DDoS, and Web DDoS logs.

### Log Processing and Conversion
- **Format Conversion**: Converts logs to multiple formats such as JSON, ndJSON, CEF, and LEEF.
- **Log Type Filtering**: Option to skip specific log types, allowing selective log ingestion.

### Log Enrichment
- Provides various enrichments to logs for enhanced information and SIEM integration.

### Customization and Configuration
- **Homogenization**: Optionally homogenizes log fields for consistency across different log types.
- **Timestamp Format Customization**: Allows for the customization of timestamp formats in the output logs.
- **Customizable Log Delimiter**: Supports setting custom delimiters for different output formats.
- **Severity Format Customization**: Provides options to customize the format of severity levels in logs.


## Configuration

Configure RLA through the `rla.yaml` file, which includes settings for AWS SQS integration, output formats, log types, and output methods.

### Sample Configuration
```yaml
sqs_access_key_id: 'your_access_key'
sqs_secret_access_key: 'your_secret_key'
sqs_region: 'your_region'
sqs_name: 'your_queue_name'
output_format: 'json'  # Supports 'json', 'ndjson', 'cef', 'leef'
logs:
  cloud_waap:
    Access: true
    WAF: true
    Bot: true
    DDoS: true
    WebDDoS: true
output:
  type: 'tcp'  # Options: 'http', 'https', 'udp', 'tcp', 'tls'
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
