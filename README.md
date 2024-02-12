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

## Log Format Examples

This section provides examples of logs processed by the Radware Logging Agent, showcasing the original JSON format, enriched JSON, CEF (Common Event Format), and LEEF (Log Event Extended Format) versions for different log types.

### Cloud WAAP - Access Log

#### Original JSON
```json
{
    "accept_language": "en-US,en;q=0.9",
    "action": "Allowed",
    "application_id": "cb696959b-2f53-41f2-87ad-9c5810313a74",
    "application_name": "MyApp",
    "cookie": "-",
    "country_code": "US",
    "destination_ip": "10.22.79.113",
    "destination_port": 443,
    "directory": "/user",
    "host": "myapp.radware.net",
    "http_bytes_in": 535,
    "http_bytes_out": 7607,
    "http_method": "POST",
    "protocol": "https",
    "referrer": "-",
    "request": "POST /user/login HTTP/1.1",
    "request_time": "0.114",
    "response_code": 200,
    "source_ip": "10.1.154.77",
    "source_port": 43834,
    "tenant_name": "MyAccount",
    "time": "27/Jan/2024:00:49:40 +0000",
    "user_agent": "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    "x-forwarded-for": "-"
}
```
#### enriched(homogenized) JSON
```json
{
    "accept_language": "en-US,en;q=0.9",
    "action": "Allowed",
    "application_id": "cb69699b-2f53-41f2-87ad-9c5810313a74",
    "application_name": "MyApp",
    "country_code": "US",
    "destination_ip": "66.22.79.113",
    "destination_port": 443,
    "directory": "/user",
    "host": "myapp.radware.net",
    "http_bytes_in": 535,
    "http_bytes_out": 7607,
    "http_method": "POST",
    "http_version": "HTTP/1.1",
    "log_type": "Access",
	"protocol": "https",
    "request": "https://myapp.radware.net/user/login",
    "request_time": "0.114",
    "response_code": 200,
    "source_ip": "10.1.154.77",
    "source_port": 43834,
    "tenant_name": "MyAccount",
    "time": "2024-27-02T00:49:40.000Z",
    "uri": "/user/login",
    "user_agent": "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko"
}
```
#### CEF
```bash
2024-12-02T08:50:40.100Z  Cloud WAAP CEF:0|Radware|Cloud WAAP|1.0|Access|Access Log|Info| rt=2024-27-01T00:49:40.000Z act=Allowed dhost=myapp.radware.net src=10.1.154.77 dst=10.22.79.113 spt=43834 dpt=443 app=https request=https://myapp.radware.net/user/login uri=/user/login method=POST in=535 out=7607 requestClientApplication=Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko rdwrCldDirectory=/user rdwrCldAcceptLanguage=en-US,en;q\=0.9 rdwrCldRequestTime=0.114 rdwrCldResponseCode=200 rdwrCldCountryCode=US rdwrCldApplicationId=cb69699b-2f53-41f2-87ad-9c5810313a74 rdwrCldApplicationName=MyApp rdwrCldTenantName=MyAccount rdwrCldHttpVersion=HTTP/1.1
```
#### LEEF
```bash
2024-12-02T08:50:40.100Z  Cloud WAAP LEEF:2.0|Radware|Cloud WAAP|1.0|Access|eventTime=2024-27-01T00:49:40.000Z	action=Allowed	dhost=myapp.radware.net	src=10.1.154.77	dst=10.22.79.113	srcPort=43834	dstPort=443	proto=https	url=https://myapp.radware.net/user/login	uri=/user/login	method=POST	bytesIn=535	bytesOut=7607	userAgent=Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko	responseCode=200	rdwrCldDirectory=/user	rdwrCldAcceptLanguage=en-US,en;q\=0.9	rdwrCldRequestTime=0.114	rdwrCldCountryCode=US	rdwrCldApplicationId=cb69699b-2f53-41f2-87ad-9c5810313a74	rdwrCldApplicationName=MyApp	rdwrCldTenantName=MyAccount	rdwrCldHttpVersion=HTTP/1.1
```


### Cloud WAAP - WAF Log

#### WAF - Original JSON
```json
{
    "action": "Blocked",
    "applicationName": "MyApp",
    "appPath": "/api/auth",
    "destinationIp": "10.35.101.159",
    "destinationPort": "54009",
    "directory": "/api",
    "enrichmentContainer": {
        "applicationId": "cb69699b-2f53-41f2-87ad-9c5810313a74",
        "contractId": "63qwe674-e83d-4fae-909d-84b309ba0cd9",
        "geoLocation.countryCode": "US",
        "tenant": "75292c55-9212-4714-babe-851b29de7cab"
    },
    "externalIp": "10.160.218.10",
    "host": "myapp.radware.net",
    "method": "POST",
    "protocol": "HTTP",
    "receivedTimeStamp": "1706313459865",
    "request": "POST /api/auth HTTP/1.1\r\nAccept-Encoding: gzip\r\nHost: myapp.radware.net\r\nContent-Length: 0\r\nUser-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0\r\naccept: application/json\r\nx-remote-ip: 128.160.218.10\r\ncontent-type: application/json\r\nNotBot: True\r\nAuthorization: Basic dGVzdF91c2VyOjEyMzQ1Ng==\r\nCookie: uzmx=17063028541647068335-3f843db00cc4acfa31; AWSALB=5CC+YSlWg; AWSALBCORS=5CC\r\nShieldSquare-Response: 0\r\n\r\n",
    "role": "public",
    "security": true,
    "severity": "High",
    "sourceIp": "10.160.218.10",
    "sourcePort": "59289",
    "targetModule": "API Security Module",
    "title": "API request method not allowed",
    "transId": "2669954742",
    "URI": "/api/auth",
    "user": "public",
    "vhost": "myapp.radware.net",
    "violationCategory": "API Security Violation",
    "violationDetails": "A user attempted to access an API endpoint using an HTTP Method that is not allowed.\n\r\nDescription:\r\nAPI Security Violation Detected.\nEndpoint:  /api/auth\nMethod: POST\nViolation: Invalid Method.\nInvalid method\n\r\nSuggestion: Revise API Security settings if needed\r\nModule: API Security\r\nError Number: -216\r\n\nAuthenticated as Public\n",
    "violationType": "API Security Violation",
    "webApp": "App_MyAccount_MyApp"
}
```
#### WAF - enriched(homogenized) JSON
```json
{
    "action": "Blocked",
    "application_id": "cb69699b-2f53-41f2-87ad-9c5810313a74",
    "application_name": "MyApp",
    "appPath": "/api/auth",
    "category": "API Security Violation",
    "contract_id": "63qwe674-e83d-4fae-909d-84b309ba0cd9",
    "cookie": "uzmx=17063028541647068335-3f843db00cc4acfa31; AWSALB=5CC+YSlWg; AWSALBCORS=5CC",
    "country_code": "US",
    "destination_ip": "10.160.218.10",
    "destination_port": "54009",
    "directory": "/api",
    "headers": "Accept-Encoding: gzip; Host: myapp.radware.net; Content-Length: 0; User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0; accept: application/json; x-remote-ip: 10.160.218.10; content-type: application/json; ShieldSquare-Response: 0",
    "host": "myapp.radware.net",
    "http_method": "POST",
    "http_version": "HTTP/1.1",
	"log_type": "WAF",
    "name": "API request method not allowed",
    "protocol": "HTTP",
	"product": "Cloud WAAP",
    "reason": "A user attempted to access an API endpoint using an HTTP Method that is not allowed.\n\r\nDescription:\r\nAPI Security Violation Detected.\nEndpoint:  /api/auth\nMethod: POST\nViolation: Invalid Method.\nInvalid method\n\r\nSuggestion: Revise API Security settings if needed\r\nModule: API Security\r\nError Number: -216\r\n\nAuthenticated as Public\n",
    "referrer": "",
    "request": "http://myapp.radware.net/api/auth",
    "role": "public",
    "security": true,
    "severity": "High",
    "source_ip": "10.160.218.10",
    "source_port": "59289",
    "targetModule": "API Security Module",
    "tenant_id": "75292c55-9212-4714-babe-851b29de7cab",
    "tenant_name": "MyAccount",
    "time": "2024-26-01T00:49:40.000Z",
    "trans_id": "2669954742",
    "uri": "/api/auth",
    "user": "public",
    "user_agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
    "vhost": "myapp75292c55-9212.radware.net",
    "violationType": "API Security Violation",
    "webApp": "App_MyAccount_MyApp"
}
```
#### WAF - CEF
```bash
2024-12-02T08:48:40.000Z Cloud WAAP CEF:0|Radware|Cloud WAAP|1.0|WAF|API request method not allowed|High| rt=2024-26-01T00:49:40.000Z act=Blocked dhost=myapp.radware.net src=10.160.218.10 dst=10.160.218.10 spt=59289 dpt=54009 app=HTTP requestMethod=POST request=http://myapp.radware.net/api/auth uri=/api/auth reason=A user attempted to access an API endpoint using an HTTP Method that is not allowed.\\n\\r\\nDescription:\\r\\nAPI Security Violation Detected.\\nEndpoint:  /api/auth\\nMethod: POST\\nViolation: Invalid Method.\\nInvalid method\\n\\r\\nSuggestion: Revise API Security settings if needed\\r\\nModule: API Security\\r\\nError Number: -216\\r\\n\\nAuthenticated as Public\\n cat=API Security Violation requestClientApplication=Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0 requestCookies=uzmx\=17063028541647068335-3f843db00cc4acfa31; AWSALB\=5CC+YSlWg; AWSALBCORS\=5CC rdwrCldAppPath=/api/auth rdwrCldDestinationIp=10.35.101.159 rdwrCldDirectory=/api rdwrCldRole=public rdwrCldSecurity=True rdwrCldSeverity=High rdwrCldTargetModule=API Security Module rdwrCldUser=public rdwrCldVhost=myapp.radware.net rdwrCldViolationType=API Security Violation rdwrCldWebApp=App_MyAccount_MyApp rdwrCldTenantName=MyAccount rdwrCldApplicationName=MyApp rdwrCldTransId=2669954742 rdwrCldCountryCode=US rdwrCldApplicationId=cb69699b-2f53-41f2-87ad-9c5810313a74 rdwrCldContractId=63qwe674-e83d-4fae-909d-84b309ba0cd9 rdwrCldTenantId=75292c55-9212-4714-babe-851b29de7cab rdwrCldHttpVersion=HTTP/1.1 rdwrCldHeaders=Accept-Encoding: gzip; Host: myapp.radware.net; Content-Length: 0; User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0; accept: application/json; x-remote-ip: 10.160.218.10; content-type: application/json; ShieldSquare-Response: 0
```
#### WAF - LEEF
```bash
2024-12-02T08:48:40.000Z Cloud WAAP LEEF:2.0|Radware|Cloud WAAP|1.0|WAF|eventTime=2024-26-01T00:49:40.000Z	action=Blocked	dhost=myapp.radware.net	src=10.160.218.10	dst=10.160.218.10	srcPort=59289	dstPort=54009	proto=HTTP	method=POST	request=http://myapp.radware.net/api/auth	uri=/api/auth	name=API request method not allowed	reason=A user attempted to access an API endpoint using an HTTP Method that is not allowed.\\n\\r\\nDescription:\\r\\nAPI Security Violation Detected.\\nEndpoint:  /api/auth\\nMethod: POST\\nViolation: Invalid Method.\\nInvalid method\\n\\r\\nSuggestion: Revise API Security settings if needed\\r\\nModule: API Security\\r\\nError Number: -216\\r\\n\\nAuthenticated as Public\\n	cat=API Security Violation	cookie=uzmx\=17063028541647068335-3f843db00cc4acfa31; AWSALB\=5CC+YSlWg; AWSALBCORS\=5CC	userAgent=Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0	sev=High	rdwrCldAppPath=/api/auth	rdwrCldDirectory=/api	rdwrCldRole=public	rdwrCldSecurity=True	rdwrCldTargetModule=API Security Module	rdwrCldUser=public	rdwrCldVhost=myapp.radware.net	rdwrCldViolationType=API Security Violation	rdwrCldWebApp=App_MyAccount_MyApp	rdwrCldTenantName=MyAccount	rdwrCldApplicationName=MyApp	rdwrCldTransId=2669954742	rdwrCldCountryCode=US	rdwrCldApplicationId=cb69699b-2f53-41f2-87ad-9c5810313a74	rdwrCldContractId=63qwe674-e83d-4fae-909d-84b309ba0cd9	rdwrCldTenantId=75292c55-9212-4714-babe-851b29de7cab	rdwrCldHttpVersion=HTTP/1.1	rdwrCldHeaders=Accept-Encoding: gzip; Host: myapp.radware.net; Content-Length: 0; User-Agent: Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0; accept: application/json; x-remote-ip: 10.160.218.10; content-type: application/json; ShieldSquare-Response: 0
```

