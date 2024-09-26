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
  - Add a rule to allow SSH access only for your IP address.
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
  - Credentials:
    - User: admin
    - Password: QFPv854P*YMcbJnJuj*ZooG9kQVfJI0V

## 5. Deploying TheHive
- Create a new droplet:
  - Ubuntu 22.04 with at least 8 GB RAM, similar specs as the Wazuh droplet.
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

This README provides an initial guide. Follow the instructions step-by-step, and don't hesitate to troubleshoot as required. The automation process will help you monitor and respond to security threats efficiently.
