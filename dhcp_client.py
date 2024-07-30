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

# Function to create a virtual interface with a custom name
def create_virtual_interface(original_interface, virtual_interface_name):
    try:
        # Check if the virtual interface already exists
        interfaces = psutil.net_if_addrs()
        if virtual_interface_name in interfaces:
            logging.debug(f"Virtual interface {virtual_interface_name} already exists. Moving ahead...")
            return virtual_interface_name

        os.system(f"sudo ip link add link {original_interface} name {virtual_interface_name} type macvlan")
        os.system(f"sudo ip link set {virtual_interface_name} up")
        logging.debug(f"Created virtual interface {virtual_interface_name} linked to {original_interface}")
        return virtual_interface_name
    except Exception as e:
        logging.error(f"Failed to create virtual interface: {e}")
        raise

# Function to change MAC address
def change_mac_address(interface, mac_address):
    try:
        os.system(f"sudo ip link set dev {interface} address {mac_address}")
        logging.debug(f"Changed MAC address of {interface} to {mac_address}")
    except Exception as e:
        logging.error(f"Failed to change MAC address: {e}")

# Function to send DHCP discover and request
def dhcp_request(interface, mac_address):
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

        logging.debug(f"Sending DHCPDISCOVER on {interface} with MAC: {mac_address}")

        # Send DHCPDISCOVER and wait for DHCPOFFER
        dhcp_offer = srp1(dhcp_discover, iface=interface, timeout=5, verbose=False)

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

        logging.debug(f"Sending DHCPREQUEST on {interface} for IP: {offered_ip} from server: {server_ip}")

        # Send DHCPREQUEST and wait for DHCPACK
        dhcp_ack = srp1(dhcp_request, iface=interface, timeout=5, verbose=False)

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

        original_interface = get_active_interface()
        logging.debug(f"Detected active interface: {original_interface}")

        # Custom virtual interface name
        virtual_interface = f"{original_interface}_twgt"
        create_virtual_interface(original_interface, virtual_interface)

        for mac in mac_addresses:
            logging.debug(f"Changing MAC address of virtual interface {virtual_interface} to {mac}")
            change_mac_address(virtual_interface, mac)
            params = dhcp_request(virtual_interface, mac)
            if params:
                store_parameters(params)
                logging.debug(f"Stored parameters for MAC {mac}")
            else:
                logging.warning(f"Failed to obtain IP for MAC {mac}")
            time.sleep(1)  # Wait for a short interval before the next request

        # No removal of the virtual interface
    except Exception as e:
        logging.error(f"An error occurred in the main function: {e}")

if __name__ == "__main__":
    main()