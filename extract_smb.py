from scapy.all import rdpcap
import json
import re
import os
import math

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

# Function to reconstruct files from SMB Write Requests
def reconstruct_file(packets, filename):
    file_data = bytearray()
    for packet in packets:
        if 'SMB2_Write_Request' in packet:
            data = packet['SMB2_Write_Request'].Buffer
            file_data.extend(data)
    with open(filename, 'wb') as f:
        f.write(file_data)

# Iterate through packets and collect detailed information
all_details = []
file_write_details = []
file_read_details = []

# Containers to store IP and port details specific to each type of file
write_ip_port_details = []
read_ip_port_details = []

# Collect SMB write packets for file reconstruction
smb_write_packets = []

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

    # Collect SMB write packets
    if 'SMB2_Write_Request' in details:
        smb_write_packets.append(packet)

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

# Convert file size to KB, MB, etc.
def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

# Function to extract and decode file data from logs and find the file name
def extract_file_data_and_name(logs):
    file_data = b''
    file_name = ''
    for entry in logs:
        if len(entry) > 4 and entry[4][0] == "SMB2_Header":
            smb_header = entry[4][1]
            if smb_header.get("Command") == 8 and smb_header.get("Flags") == "SMB2_FLAGS_SERVER_TO_REDIR+SMB2_FLAGS_SIGNED":
                smb_read_response = entry[5][1]
                if "Data" in smb_read_response["Buffer"][0]:
                    data = smb_read_response["Buffer"][0][1]
                    if isinstance(data, str):
                        # Remove the leading "b'" and trailing "'" from the string
                        data = re.sub(r"^b'|'$", '', data)
                        data = data.encode('latin1').decode('unicode_escape').encode('latin1')
                    file_data += data
            elif smb_header.get("Command") == 5:  # Create Response
                smb_create_response = entry[5][1]
                if "Buffer" in smb_create_response and smb_create_response["Buffer"]:
                    buffer_entry = smb_create_response["Buffer"][0]
                    if "Name" in buffer_entry:
                        name = buffer_entry[1]
                        if isinstance(name, str):
                            name = re.sub(r"^b'|'$", '', name)
                            name = name.encode('latin1').decode('unicode_escape')
                        file_name = name

        # Extracting src, dst, sport, dport, and timestamp values
        for item in entry:
            if isinstance(item, list) and item[0] == "IP":
                ip_header = item[1]
                src = ip_header.get("src", "")
                dst = ip_header.get("dst", "")
            if isinstance(item, list) and item[0] == "TCP":
                tcp_header = item[1]
                sport = tcp_header.get("sport", 0)
                dport = tcp_header.get("dport", 0)
                for option in tcp_header.get("options", []):
                    if isinstance(option, list) and option[0] == "Timestamp":
                        timestamp = option[1]


    return file_data, file_name, src, dst, sport, dport, timestamp

# Function to recursively extract packet layer details
def extract_packet_details(packet):
    details = []
    while packet:
        layer_name = packet.__class__.__name__
        fields = {field.name: packet.getfieldval(field.name) for field in packet.fields_desc}
        details.append((layer_name, fields))
        packet = packet.payload
    return details

# Iterate through packets and print detailed information
details_list = []
for i, packet in enumerate(packets):
    details = extract_packet_details(packet)
    details_list.append(details)
logs = json.dumps(details_list, default=str)

# Paths to save the logs as a json file
with open('logs.json', 'w') as json_file_read:
    json_file_read.write(logs)

# Load the logs
with open('logs.json', 'r') as file:
    logs = json.load(file)

# Extract the file data and name
file_data, file_name, src, dst, sport, dport, timestamp = extract_file_data_and_name(logs)

# Cleaning the file name
clean_file_name = re.sub(r'\x00', '', file_name)  # remove null bytes

# Ensure the directory exists
os.makedirs(os.path.dirname(clean_file_name), exist_ok=True)

# Write the extracted data to an Excel file
with open(clean_file_name, 'wb') as f:
    f.write(file_data)

# Get file size in bytes
file_size = os.path.getsize(clean_file_name)

# Prepare metadata
metadata = {
    "FileName": clean_file_name,
    "FileSize": convert_size(file_size),
    "src": src,
    "dst": dst,
    "sport": sport,
    "dport": dport,
    "timestamp": timestamp
}

# Save metadata to JSON file
metadata_file = "metadata_of_extracted_file.json"
with open(metadata_file, 'w') as mf:
    json.dump(metadata, mf, indent=4)

print(f"{clean_file_name} has been reconstructed successfully.")
print(f"Metadata has been saved to {metadata_file}.")