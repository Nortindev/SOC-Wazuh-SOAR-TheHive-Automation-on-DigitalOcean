#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "Updating package lists..."
apt update

echo "Installing dependencies..."
apt install -y wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl software-properties-common python3-pip lsb-release
sleep 4s

echo "Installing Amazon Corretto Java 11..."
wget -qO- https://apt.corretto.aws/corretto.key | gpg --dearmor -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" | tee /etc/apt/sources.list.d/corretto.sources.list
apt update
apt install -y java-common java-11-amazon-corretto-jdk
echo 'JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"' | tee -a /etc/environment
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
sleep 4s

echo "Installing Cassandra..."
wget -qO - https://downloads.apache.org/cassandra/KEYS | gpg --dearmor -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" | tee /etc/apt/sources.list.d/cassandra.sources.list
apt update
apt install -y cassandra
sleep 4s

echo "Installing Elasticsearch..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
apt install -y apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-7.x.list
apt update
apt install -y elasticsearch
sleep 4s

echo "Configuring Elasticsearch (optional)..."
mkdir -p /etc/elasticsearch/jvm.options.d
cat <<EOL > /etc/elasticsearch/jvm.options.d/thehive.options
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
EOL
sleep 4s

echo "Installing TheHive..."
wget -O- https://archives.strangebee.com/keys/strangebee.gpg | gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.2 main' | tee /etc/apt/sources.list.d/strangebee.list
apt update
apt install -y thehive
sleep 4s

echo "TheHive installation completed successfully."
