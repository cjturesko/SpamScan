# SpamScan

SpamScan is an automated tool for analyzing suspicious email attachments and sender domains. It extracts attachments from .eml files, generates SHA-256 hashes, and checks them against various security APIs to identify potential threats.

## Features

- Extracts attachments from .eml files
- Generates SHA-256 hashes for attachments
- Checks sender domains against MXToolbox blacklist
- Verifies attachment hashes using VirusTotal, MalShare, and MalwareBazaar APIs
- Logs results for easy review and action

## Prerequisites

1. **API Keys**: Obtain free API keys from the following services:
   - VirusTotal
   - MalShare
   - MXToolbox
   - Malware Hash Registry (commented out due to SSL error)

   Add these keys to your `config.ini` file.

2. **Folder Structure**: Create the following subdirectories in your SpamScan folder:
   ```
   SpamScan/
   ├── potential_spam/
   └── spam_attachments/
   ```

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/cjturesko/SpamScan.git
   cd SpamScan
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up your `config.ini` file with the obtained API keys.

## Usage

1. Place suspicious .eml files in the `potential_spam/` folder.

2. Run the scanner:
   ```
   python main.py
   ```

3. The script will perform the following actions:
   - Extract attachments from each .eml file
   - Generate SHA-256 hashes for extracted attachments
   - Log sender domains and attachment information in `hashes.txt`
   - Check sender domains against the MXToolbox blacklist
   - Check attachment hashes using VirusTotal, MalShare, and MalwareBazaar APIs
   - Display results and any security notices in the console

## Output

The tool generates two main outputs:

1. `hashes.txt`: Contains logged information in the format:
   ```
   domain.com|file.txt: 2340000
   ```

2. Console output: Displays detailed results of domain and hash checks, including any security notices requiring action.

## TODO

:heavy_check_mark: Check sender IP address to see if bad.
Scan for URLs in the emails.
   - Allow the user to decide which URLs are tested, to avoid unnessecary API calls/information leaks.

