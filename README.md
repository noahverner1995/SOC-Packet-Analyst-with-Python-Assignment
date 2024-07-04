# SOC/Packet Analyst with C/Python Assignment

## 1. Target File
**smb.pcap**

## 2. Goal

**Make a Program**

- **Reading the pcap file where SMBv2 packets occurred (above target file)**
- **Extracting attachments and metadata.**

## 3. What to Extract

1. SMB Write Request, Response (file write)
   - [Reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e7046961-3318-4350-be2a-a8d69bb59ce8)
2. SMB Read Request, Response (file read)
   - [Reference](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/320f04f3-1b28-45cd-aaa1-9e5aed810dca)

## 4. Condition

1. Parse SMB without using Wireshark.
2. Language should be C or Python.

## 5. Program Output

1. Extracted original files (attachments)
2. Metadata of extracted file
    - File name
    - File size
    - Source IP address
    - Source port number
    - Destination IP address
    - Destination port number

## Assignment Output

1. A folder containing extracted original files (When the code runs, it should create this)
2. A JSON file of Metadata of extracted files (When the code runs, it should create this)
3. Program code (on GitHub)
4. Runnable program. It should run without issues on our machine
5. Neat and well-organized code
6. README with instructions on how to run the program

## Instructions to Run the Program

1. **Ensure you have Python installed**: This program requires Python 3.6 or higher. You can download it from [here](https://www.python.org/downloads/).

2. **Install required packages**: The program uses the `scapy` library for packet processing. Install it using pip:
    ```bash
    pip install scapy
    ```

3. **Place the pcap file**: Ensure the `smb.pcap` file is available on your system. Note the file path for this file.

4. **Run the program**:
    - Save the provided Python script to a file, for example, `extract_smb.py`.
    - Open a terminal or command prompt.
    - Navigate to the directory where the script is saved.
    - Run the script:
      ```bash
      python extract_smb.py
      ```
    - You will be prompted to enter the path to the `.pcap` file. Provide the full path to `smb.pcap`.

5. **Output**:
    - The program will create a folder named `extracted_original_files` in the same directory as the script.
    - Inside this folder, you will find two JSON files: `file_write.json` and `file_read.json` containing the extracted data.
    - A metadata file named `metadata_of_extracted_file.json` will be created in the same directory as the script.

6. **Check the output**:
    - Ensure the `extracted_original_files` folder contains the expected JSON files.
    - Verify that `metadata_of_extracted_file.json` contains the correct metadata.

## Example

```Please enter the path to the .pcap file: C:\Users\ResetStoreX\Downloads\hyper hire technical test\smb.pcap```
```All JSON files have been successfully created.```

## Notes

- The program ensures that only valid ```.pcap``` files are processed.
- The output files are stored in the directory where the script is located for easy access.
- The script handles both ```SMB2 Write and Read requests and responses```, extracting relevant details into structured JSON files.