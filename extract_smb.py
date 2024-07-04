from scapy.all import rdpcap
import json
import os

def get_pcap_file_path():
    while True:
        pcap_file = input("Please enter the path to the .pcap file: ")
        if os.path.isfile(pcap_file) and pcap_file.endswith('.pcap'):
            return pcap_file
        else:
            print("Invalid file path. Please provide a valid path to a .pcap file.")

# Get the pcap file path from the user
pcap_file = get_pcap_file_path()

# Load the pcap file
packets = rdpcap(pcap_file)

# Function to recursively extract packet layer details
def extract_packet_details(packet):
    details = {}
    while packet:
        layer_name = packet.__class__.__name__
        fields = {field.name: packet.getfieldval(field.name) for field in packet.fields_desc}
        details[layer_name] = fields
        packet = packet.payload
    return details

# Function to extract IP and port details
def extract_ip_port(packet):
    ip_src = None
    ip_dst = None
    port_src = None
    port_dst = None
    
    if 'IP' in packet:
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
    elif 'IPv6' in packet:
        ip_src = packet['IPv6'].src
        ip_dst = packet['IPv6'].dst
    
    if 'TCP' in packet:
        port_src = packet['TCP'].sport
        port_dst = packet['TCP'].dport
    elif 'UDP' in packet:
        port_src = packet['UDP'].sport
        port_dst = packet['UDP'].dport
    
    return ip_src, port_src, ip_dst, port_dst

# Iterate through packets and collect detailed information
all_details = []
file_write_details = []
file_read_details = []

# Containers to store IP and port details specific to each type of file
write_ip_port_details = []
read_ip_port_details = []

for i, packet in enumerate(packets):
    details = extract_packet_details(packet)
    all_details.append(details)
    
    # Extract IP and port details
    ip_src, port_src, ip_dst, port_dst = extract_ip_port(packet)
    
    # Check for write-related keys
    if 'SMB2_Create_Request' in details or 'SMB2_Create_Response' in details:
        file_write_details.append(details)
        if ip_src and port_src and ip_dst and port_dst:
            write_ip_port_details.append({
                "source_ip_address": ip_src,
                "source_port_number": port_src,
                "destination_ip_address": ip_dst,
                "destination_port_number": port_dst
            })
    
    # Check for read-related keys
    if 'SMB2_Read_Request' in details or 'SMB2_Read_Response' in details:
        file_read_details.append(details)
        if ip_src and port_src and ip_dst and port_dst:
            read_ip_port_details.append({
                "source_ip_address": ip_src,
                "source_port_number": port_src,
                "destination_ip_address": ip_dst,
                "destination_port_number": port_dst
            })

# Convert to JSON with readable formatting
file_write_json = json.dumps(file_write_details, indent=4, default=str)
file_read_json = json.dumps(file_read_details, indent=4, default=str)

# Create the folder if it does not exist
folder_name = 'extracted_original_files'
if not os.path.exists(folder_name):
    os.makedirs(folder_name)

# Get the current directory of the script
current_directory = os.path.dirname(os.path.abspath(__file__))

# Paths to save the JSON files
file_write_path = os.path.join(current_directory, folder_name, 'file_write.json')
file_read_path = os.path.join(current_directory, folder_name, 'file_read.json')

# Save JSON output to files
with open(file_write_path, 'w') as json_file_write:
    json_file_write.write(file_write_json)

with open(file_read_path, 'w') as json_file_read:
    json_file_read.write(file_read_json)

# Collect metadata
metadata = {
    "file_write.json": {
        "file_size": os.path.getsize(file_write_path),
        "ip_port_details": write_ip_port_details
    },
    "file_read.json": {
        "file_size": os.path.getsize(file_read_path),
        "ip_port_details": read_ip_port_details
    }
}

# Path to save the metadata JSON file
metadata_path = os.path.join(current_directory, 'metadata_of_extracted_file.json')

# Save metadata to JSON file
with open(metadata_path, 'w') as metadata_file:
    json.dump(metadata, metadata_file, indent=4)

print("All JSON files have been successfully created.")