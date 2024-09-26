# Project: Wazuh + SOAR + TheHive + Shuffle Automation Deployment on DigitalOcean

This project involves the deployment of a security monitoring and automation stack using Wazuh, TheHive, and Shuffle Automation. The stack is deployed on Digital Ocean droplets, with both Windows and Linux clients connected. For the Windows client, we are using VirtualBox.
Below are the step-by-step instructions to replicate this deployment.

## 1. Pre-requisites
- A Digital Ocean account to create droplets.
- Access to VirtualBox for Windows VM.
- SSH access to the droplets.
- Basic knowledge of working with Linux and VirtualBox.
- Internet connection for downloading necessary software.

## 2. Setting Up the Environment
### 2.1 Windows Virtual Machine on VirtualBox
- Download Windows 10 ISO from the [official site](https://www.microsoft.com/PT-BR/software-download/windows10).
- Create a VirtualBox VM:
  - Allocate 4 GB of RAM and 50 GB of storage.
  - Proceed with a custom installation, selecting "I don’t have a key" during installation.
  - Disable privacy settings if desired.
  - Choose a Domain Controller for login.
- Install necessary tools:
  - Install Google Chrome.
  - Download and install the Sysinternals Suite.

## 3. Setting Up the Droplet Firewall
- Create a firewall in Digital Ocean:
  - Go to **Networking -> Firewalls -> Create Firewall**.
  - Add a rule to allow SSH access only for **your IP address**.
- Edit Firewall Rules:
  - Assign the firewall to the droplet.
  - Ensure ports 80 and 443 are open for the Wazuh dashboard access.

## 4. Wazuh Manager Installation on Droplet (Ubuntu)
- Update the droplet:
```bash
sudo apt update -y && sudo apt upgrade -y
```

- Install Wazuh:
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

- Access Wazuh Dashboard:
  - Use the public IP of the droplet.
  - Make sure ports 80 and 443 are enabled for external access.
  - Make sure to save your Credentials for example:
    - User: admin
    - Password: YourCoolpasswordHer31!

## 5. Deploying TheHive
- Create a new droplet:
  - Ubuntu 22.04 with at least **8 GB RAM**, similar specs as the Wazuh droplet.
- Install TheHive: Follow the instructions provided at this repository:
  - TheHive Install Instructions
- Configure Cassandra:
  - Edit the Cassandra configuration:
```bash
nano /etc/cassandra/cassandra.yaml
```

  - Set `listen_address` and `rpc_address` to your public IP.
  - Update the seed IP in the seed provider section.
  - Restart Cassandra:
```bash
systemctl restart cassandra.service
```

- Configure Elasticsearch:
  - Edit the Elasticsearch configuration:
```bash
nano /etc/elasticsearch/elasticsearch.yml
```

  - Un-comment the necessary settings like `cluster.name`, `node.name`, and `network.host`.
- Configure TheHive:
  - Edit TheHive configuration:
```bash
sudo nano /etc/thehive/application.conf
```

  - Set the public IP and hostname.
  - Open necessary ports 7000, 9200, and 9000 in the firewall.
  - Start and enable TheHive service:
```bash
systemctl start thehive
systemctl enable thehive
```

## 6. Adding Wazuh Agent (Windows Client)
- Set Wazuh IP as the host (e.g., 142.93.55.98).
- Install Wazuh Agent on Windows:
  - Copy the Wazuh agent installation command and run it in PowerShell as Administrator.
  - Change the Network Adapter to Bridge Mode to allow communication with the Wazuh server on Digital Ocean.
  - Open required ports (1514 and 1515) in the firewall to allow the Windows VM to communicate with the Wazuh server.

## 7. Generating Telemetry (Windows Client)
- Edit Wazuh configuration file:
  - Find and modify the Wazuh configuration in the following path: `C:\Program Files (x86)\ossec\ossec.conf`
  - Back up the file before editing.
- Monitor Sysmon Events:
  - Navigate to **Event Viewer > Application > Microsoft > Windows > Sysmon > Operational** to monitor security events.
  - Edit the Wazuh configuration file to include Sysmon logs.
- Restart Wazuh Agent:
  - Restart the Wazuh agent service to apply the changes.

## 8. Testing with Mimikatz
- Download Mimikatz:
  - Disable security features and download Mimikatz from: `hxxps://github[.]com/gentilkiwi/mimikatz/releases/tag/2.2.0-20220919`.
  - Run Mimikatz on Windows VM and check if the event is captured by Wazuh.

## 9. Automating with Shuffle
- Set up Shuffle Automation to integrate with Wazuh for incident response.
- Configure the webhook and add it to Wazuh.
- Modify Wazuh configuration to include a rule to trigger on Mimikatz detection and send alerts via the webhook.
- Build the workflow:
  - Use Shuffle to automate the incident response process:
    - Send alert to TheHive.
    - Check reputation with VirusTotal.
    - Notify SOC analysts.

## 10. Integrating VirusTotal in Shuffle Automation

1. **Obtain VirusTotal API Key**:
   - Create an account at VirusTotal and obtain your API key.

2. **Configure Shuffle to query VirusTotal**:
   - In Shuffle, set the HTTP Method to **GET** and use the VirusTotal API to check the reputation of files.
   - Use a **Regex** expression to extract the SHA256 hash from the Mimikatz alert and send it to VirusTotal.

3. **Configure the request**:
   - Ensure that the request body contains the necessary data, particularly the hash value parsed from the alert.
   - In Shuffle, use the format `LIST` or `$sha256_regex_catcher.group_0.#` as the list for the SHA256 values.

4. **Test the workflow**:
   - Confirm that the workflow correctly fetches reputation data from VirusTotal.

## 11. Integrating with TheHive for Alerts

1. **Log in to TheHive**:
   - Create a new user or organization in TheHive if not already done.

2. **Configure API Key**:
   - In TheHive, generate an API Key for integration.
   - Save the API key and set up a connection between Shuffle and TheHive.

3. **Send Alerts to TheHive**:
   - In Shuffle, set up a workflow that sends the Mimikatz alert data to TheHive. Include the following:
     - The alert summary (e.g., Mimikatz detected on Host).
     - The process ID and command line extracted from Wazuh logs.
     - Severity (e.g., sev 2).
     - Tags such as MITRE ID **T1003** for credential dumping.

4. **Full JSON Structure for TheHive Alerts**:
```json
{
  "description": "Mimikatz detected from user $exec.text.win.system.computer",
  "flag": false,
  "pap": 2,
  "severity": 2,
  "source": "Wazuh",
  "sourceRef": "Rule: 100002",
  "status": "New",
  "summary": "Mimikatz activity detected on Host: $exec.text.win.system.computer and the process ID is: $exec.text.win.eventdata.processId and the command line is $exec.text.win.eventdata.commandLine",
  "tags": ["T1003"],
  "title": "Mimikatz Usage Detected",
  "tlp": 2,
  "type": "Internal",
  "date": "$exec.all_fields.data.win.eventdata.utcTime"
}
```

5. **Test the Workflow**:
   - Temporarily open all necessary ports (especially port 9000 for TheHive).
   - Rerun the workflow in Shuffle and check that an alert is successfully created in TheHive.

## 12. Sending Email Notifications

1. **Configure Email Integration in Shuffle**:
   - After the VirusTotal reputation check and TheHive alert creation, send an email notification to the SOC analyst.

2. **The email should contain**:
   - Host details (e.g., computer name).
   - Time of alert.
   - Severity level.
   - The SHA256 hash and VirusTotal report link.

3. **Verify Email Delivery**:
   - Check that the email is correctly sent and received, and that all details are included.

## 13. Automating SQL Injection Detection and Response

1. **Create SQL Injection Detection Rule in Wazuh**:
   - Define a rule for detecting SQL injection attacks.
   - Use Wazuh to log and trigger alerts when SQL injection attempts are made.

2. **Configure Active Response**:
   - Set up an Active Response in Wazuh to block the source IP of the SQL injection attempt.

   Example command to block IP:
```bash
/var/ossec/bin/agent_control -b <source_ip> -f firewall-drop0 -u 003
```

3. **Add to Shuffle Workflow**:
   - Extend the Shuffle workflow to include:
     - Extracting the source IP from the Wazuh alert.
     - Sending the source IP to VirusTotal for analysis.
     - Blocking the source IP if necessary.
     - Sending the alert to TheHive and notifying the SOC team via email.

4. **Test SQL Injection Response**:
   - Simulate an SQL injection attempt on the client machine.
   - Confirm that the active response blocks the IP and that all steps in the workflow (VirusTotal check, TheHive alert, email notification) are executed correctly.

## 14. Final Testing and Validation

1. **Test with Various Threat Scenarios**:
   - Use different types of attacks (e.g., Mimikatz, SQL Injection) to test the entire Wazuh, TheHive, and Shuffle setup.
   - Ensure all logs are captured, alerts are triggered, and responses are automated correctly.

2. **Monitor and Fine-tune**:
   - Regularly monitor the performance and adjust rules, workflows, and firewall settings as needed.
   - Make sure the automation flow works without interruptions.

This concludes the initial deployment and configuration of the Wazuh + SOAR + TheHive + Shuffle Automation stack. Follow these steps for future customization or to scale your deployment by adding more clients, rules, or automations.
