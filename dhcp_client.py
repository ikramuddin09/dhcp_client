import os
import logging
import csv
import random
import psutil
import time
from scapy.all import *

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to get the active network interface
def get_active_interface():
    interfaces = psutil.net_if_addrs()
    for interface in interfaces:
        # Skip loopback and down interfaces
        if interface != 'lo' and psutil.net_if_stats()[interface].isup:
            return interface
    raise Exception("No active network interface found")

# Function to change MAC address
def change_mac_address(interface, mac_address):
    try:
        os.system(f"sudo ip link set dev {interface} address {mac_address}")
        logging.debug(f"Changed MAC address of {interface} to {mac_address}")
    except Exception as e:
        logging.error(f"Failed to change MAC address: {e}")

# Function to get original MAC address
def get_original_mac(interface):
    try:
        output = os.popen(f"cat /sys/class/net/{interface}/address").read()
        return output.strip()
    except Exception as e:
        logging.error(f"Failed to get original MAC address: {e}")
        raise

# Function to send DHCP discover and request
def dhcp_request(mac_address):
    try:
        conf.checkIPaddr = False  # Disable IP address checking
        transaction_id = random.randint(1, 0xFFFFFFFF)

        logging.debug(f"Generated transaction ID: {transaction_id}")

        # Create DHCPDISCOVER packet
        dhcp_discover = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
                        IP(src="0.0.0.0", dst="255.255.255.255") / \
                        UDP(sport=68, dport=67) / \
                        BOOTP(chaddr=bytes.fromhex(mac_address.replace(':', '')), xid=transaction_id) / \
                        DHCP(options=[("message-type", "discover"), "end"])

        logging.debug(f"Sending DHCPDISCOVER with MAC: {mac_address}")

        # Send DHCPDISCOVER and wait for DHCPOFFER
        dhcp_offer = srp1(dhcp_discover, timeout=5, verbose=False)

        if dhcp_offer is None:
            logging.warning(f"No DHCPOFFER received for MAC {mac_address}")
            return None

        logging.debug(f"Received DHCPOFFER: {dhcp_offer.summary()}")

        # Extract offered IP address and server IP from DHCPOFFER
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = dhcp_offer[IP].src

        # Create DHCPREQUEST packet
        dhcp_request = Ether(src=mac_address, dst="ff:ff:ff:ff:ff:ff") / \
                       IP(src="0.0.0.0", dst="255.255.255.255") / \
                       UDP(sport=68, dport=67) / \
                       BOOTP(chaddr=bytes.fromhex(mac_address.replace(':', '')), xid=transaction_id) / \
                       DHCP(options=[("message-type", "request"),
                                     ("requested_addr", offered_ip),
                                     ("server_id", server_ip), "end"])

        logging.debug(f"Sending DHCPREQUEST for IP: {offered_ip} from server: {server_ip}")

        # Send DHCPREQUEST and wait for DHCPACK
        dhcp_ack = srp1(dhcp_request, timeout=5, verbose=False)

        if dhcp_ack is None:
            logging.warning(f"No DHCPACK received for MAC {mac_address}")
            return None

        logging.debug(f"Received DHCPACK: {dhcp_ack.summary()}")

        # Extract network configuration parameters from DHCPACK
        params = {
            "mac_address": mac_address,
            "ip_address": dhcp_ack[BOOTP].yiaddr,
            "lease_time": None,
            "subnet_mask": None,
            "default_gateway": None,
            "dns_servers": []
        }

        for opt in dhcp_ack[DHCP].options:
            if opt[0] == "lease_time":
                params["lease_time"] = opt[1]
            elif opt[0] == "subnet_mask":
                params["subnet_mask"] = opt[1]
            elif opt[0] == "router":
                params["default_gateway"] = opt[1]
            elif opt[0] == "name_server":
                params["dns_servers"].append(opt[1])

        logging.debug(f"Extracted parameters: {params}")

        return params
    except Exception as e:
        logging.error(f"DHCP request failed: {e}")
        return None

# Function to store parameters in a CSV file
def store_parameters(params):
    try:
        file_exists = os.path.isfile('dhcp_clients.csv')

        with open('dhcp_clients.csv', 'a', newline='') as csvfile:
            fieldnames = ['mac_address', 'ip_address', 'lease_time', 'subnet_mask', 'default_gateway', 'dns_servers']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header only if the file does not exist
            if not file_exists:
                writer.writeheader()

            writer.writerow(params)
            logging.debug(f"Stored parameters for MAC {params['mac_address']}: {params}")
    except Exception as e:
        logging.error(f"Failed to store parameters: {e}")

# Main function
def main():
    try:
        # Read MAC addresses from a text file
        with open('mac_addresses.txt', 'r') as file:
            mac_addresses = [line.strip() for line in file.readlines()]

        interface = get_active_interface()
        logging.debug(f"Detected active interface: {interface}")

        original_mac = get_original_mac(interface)
        logging.debug(f"Original MAC address of {interface}: {original_mac}")

        for mac in mac_addresses:
            logging.debug(f"Changing MAC address to {mac}")
            change_mac_address(interface, mac)
            params = dhcp_request(mac)
            if params:
                store_parameters(params)
                logging.debug(f"Stored parameters for MAC {mac}")
            else:
                logging.warning(f"Failed to obtain IP for MAC {mac}")
            logging.debug(f"Reverting MAC address to original {original_mac}")
            change_mac_address(interface, original_mac)  # Revert to original MAC address
            time.sleep(1)  # Wait for a short interval before the next request
    except Exception as e:
        logging.error(f"An error occurred in the main function: {e}")

if __name__ == "__main__":
    main()