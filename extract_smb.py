from scapy.all import rdpcap
import json
import re
import os
import math

def get_pcap_file_path():
    while True:
        pcap_file = input("Please enter the path to the .pcap file: ")
        # Normalize the path to handle different OS path formats
        pcap_file = os.path.normpath(pcap_file)
        if os.path.isfile(pcap_file) and pcap_file.endswith('.pcap'):
            return pcap_file
        else:
            print("Invalid file path. Please provide a valid path to a .pcap file.")

# Get the pcap file path
pcap_file = get_pcap_file_path()

# Load the pcap file
packets = rdpcap(pcap_file)

# Function to extract IP and port details
def extract_ip_port(packet):
    ip_src = None
    ip_dst = None
    port_src = None
    port_dst = None
    
    if packet.haslayer('IP'):
        ip_src = packet['IP'].src
        ip_dst = packet['IP'].dst
    elif packet.haslayer('IPv6'):
        ip_src = packet['IPv6'].src
        ip_dst = packet['IPv6'].dst
    
    if packet.haslayer('TCP'):
        port_src = packet['TCP'].sport
        port_dst = packet['TCP'].dport
    elif packet.haslayer('UDP'):
        port_src = packet['UDP'].sport
        port_dst = packet['UDP'].dport
    
    return ip_src, port_src, ip_dst, port_dst

# Collect SMB write packets for file reconstruction
smb_write_packets = []

# Function to recursively extract packet layer details
def extract_packet_details(packet):
    details = []
    while packet:
        layer_name = packet.__class__.__name__
        fields = {field.name: packet.getfieldval(field.name) for field in packet.fields_desc}
        details.append((layer_name, fields))
        packet = packet.payload
    return details

for packet in packets:
    # Collect SMB write packets
    if packet.haslayer('SMB2_Write_Request'):
        smb_write_packets.append(packet)

# Function to extract and decode file data from logs and find the file name
def extract_file_data_and_name(logs):
    file_data = b''
    file_name = b''
    src = ''
    dst = ''
    sport = 0
    dport = 0
    timestamp = []

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
            if isinstance(item, tuple) and item[0] == "IP":
                ip_header = item[1]
                src = ip_header.get("src", "")
                dst = ip_header.get("dst", "")
            if isinstance(item, tuple) and item[0] == "TCP":
                tcp_header = item[1]
                sport = tcp_header.get("sport", 0)
                dport = tcp_header.get("dport", 0)
                for option in tcp_header.get("options", []):
                    if isinstance(option, tuple) and option[0] == "Timestamp":
                        timestamp = option[1]

    return file_data, file_name.decode('latin1'), src, dst, sport, dport, timestamp

# Iterate through packets and collect detailed information
details_list = []
for packet in packets:
    details = extract_packet_details(packet)
    details_list.append(details)

# Extract the file data and name
file_data, file_name, src, dst, sport, dport, timestamp = extract_file_data_and_name(details_list)

# Cleaning the file name
clean_file_name = re.sub(r'\x00', '', file_name.split('\\')[-1])  # remove null bytes and folders
clean_file_path = os.path.join('extracted_original_files', clean_file_name)

# Ensure the directory exists
os.makedirs(os.path.dirname(clean_file_path), exist_ok=True)

# Write the extracted data to an Excel file
with open(clean_file_path, 'wb') as f:
    f.write(file_data)

# Function to convert file size to KB, MB, etc.
def convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"

# Get file size in bytes
file_size = os.path.getsize(clean_file_path)

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