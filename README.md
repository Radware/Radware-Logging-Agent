# Radware Logging Agents (RLA)

RLA is a log processing tool designed to streamline the integration of Radware products with Security Information and Event Management (SIEM) systems. In its first major release, RLA is focuses on robust support of Radware Cloud WAAP logs, utilizing the Cloud WAAP's capability to export security and access logs to an AWS S3 Bucket.


## Features

### Log Ingestion
- **Multi-Agent Architecture**: Supports multiple agents, each with distinct configurations for targeted log processing.
- **Cloud WAAP Integration**: Efficiently ingests logs from Radware Cloud WAAP exported to AWS S3.
- **Versatile Log Handling**: Capable of processing various log types including Access, WAF, Bot, DDoS, and Web DDoS.

### Log Processing and Conversion
- **Dynamic Format Conversion**: Converts logs to multiple formats such as JSON, CEF, and LEEF, with customizable options.
- **Selective Log Processing**: Provides the ability to filter and process specific log types, enhancing control over log ingestion.

### Log Enrichment
- **Enhanced Information**: Adds valuable enrichments to logs, improving their utility and integration with SIEM systems.

### Customization and Flexibility
- **Configurable Homogenization**: Optional normalization of log fields across different log types for consistency.
- **Customizable Timestamp and Severity Formats**: Allows specific settings for timestamp and log severity formats in output logs.
- **Adaptable Output Configurations**: Supports various output methods and customization for delimiters and other format-specific settings.

# Configuration

## General Configuration Options

- **log_file**: Specify the path for the RLA's log file. This is where RLA will write its operational logs.
- **output_directory**: Define the directory to store temporary files during log processing.
- **log_directory**: Set the directory for storing RLA's log files.
- **logging_levels**: Choose the logging level for RLA's internal logs. Options: `INFO`, `WARNING`, `DEBUG`, `ERROR`.

## AWS Credentials

Configure AWS credentials to allow RLA to interact with AWS services such as SQS and S3.

- **access_key_id**: Your AWS Access Key ID for authentication.
- **secret_access_key**: Your AWS Secret Access Key for authentication.
- **region**: The AWS region where the SQS queue and S3 bucket are located.

## Agent Configuration

Define settings for each log collection agent.

- **name**: Assign a unique name for each agent.
- **type**: Define the type of log source. Currently, "sqs" is supported.
- **num_worker_threads**: Set the number of worker threads for processing messages.
- **product**: Specify the product type associated with this agent. Currently supports 'cloud_waap'.
- **sqs_settings**:
  - **queue_name**: The name of the SQS queue to poll for messages.
  - **delete_on_failure**: Determine whether to delete messages from the queue if processing fails (true/false).
- **logs**: Enable or disable specific log types for processing, such as `Access`, `WAF`, `Bot`, `DDoS`, `WebDDoS`, and `CSP`.

## Output Configuration

Configure how and where processed logs are sent.

- **output_format**: Choose the format for the output logs. Supported formats: `json`, `cef`, `leef`.
- **type**: Select the transport protocol for sending logs. Options: `http`, `https`, `tcp`, `udp`, `tls`.
- **destination**: Specify the destination where logs are to be sent, including the port if necessary.

## Format-Specific Configurations

Customize output settings for each supported log format.

### JSON Format Options

- **time_format**: Choose the format for timestamps. Options include 'ISO8601', 'epoch_ms_str', 'epoch_ms_int', 'MM dd yyyy HH:mm:ss'.
- **unify_fields**: Optionally normalize log fields across different log types for consistency (true/false).

### CEF and LEEF Format Options

- **delimiter**: Specify the delimiter used to separate events (commonly "\n").
- **time_format** and **severity_format**: Customize the representation of timestamps and severity levels in the logs.
- **syslog_header**: Configure the generation and content of syslog headers, specifying the source of the host field (`product`, `application`, `tenant`).

## TLS Configuration

Settings for secure TCP communication using TLS.

- **verify**: Whether to verify the server's SSL certificate (true/false).
- **ca_cert**: Path to the CA certificate file.
- **client_cert**: Path to the client's SSL certificate.
- **client_key**: Path to the client's SSL key.

## HTTP/HTTPS Configuration

Customize settings for log transmission over HTTP or HTTPS, including batch processing, authentication, and custom headers.

- **batch**: Enable or disable batch processing. When true, multiple log events are grouped into a single HTTP request.
- **authentication**: Specify authentication details for secure endpoint access. Supported methods: `none`, `basic`, `bearer`.
- **custom_headers**: Define additional headers to be included in the HTTP request.

For detailed explanations and additional configuration options, refer to the official RLA documentation or support resources.

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
  output_format: 'json'  # Supports 'json', 'cef', 'leef'
  type: 'tcp'
  destination: 'your_destination_address'
```

## Installation on Linux

To install the Radware Logging Agent on a Linux system, follow these steps:

1. **Clone the Repository**: 
   Download the latest release package from the [Releases](https://github.com/Radware/Radware-Logging-Agent/releases) section of the Radware Logging Agent GitHub repository. Look for the package named like `rla_{latest_release}.tar.gz`, where `{latest_release}` indicates the version number.
2. **Run the Installation Script**:
   Once you have downloaded the latest release package, extract it and run the included installation script. Remember to replace `{latest_release}` with the actual version number you downloaded. This script automates the setup process, installing all necessary components.
   ```bash
   tar -zxvf rla_{latest_release}.tar.gz
   cd rla
   chmod +x install.sh
   sudo ./install.sh
   ```
3. **Configure rla.yaml**:
After installation, you'll need to configure the `rla.yaml` file to suit your specific environment and requirements. Use the following command to edit the configuration file:
    ```bash
    sudo vi /etc/rla/rla.yaml
     ```
    Ensure that you correctly set all necessary configuration options according to your deployment needs.

4. **Using Certificates**:
If your setup requires certificates, ensure they are correctly placed in the desired directory and have the appropriate ownership settings. Use the following command to change the ownership of the certificate files to the rla user and group, replacing <your_certificate_file> with the actual file name of your certificate:
    ```bash
    sudo chown rla:rla <your_certificate_file>
    ```
    Repeat this command for each certificate file you need to use with the Radware Logging Agent.
5. **Start the Service**:
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
