SpamScan

This tool automates the process of extracting attachments from suspicious .eml files, generating SHA-256 hashes for the attachments, and checking the sender's domain and attachment hashes against various APIs.

Prerequisites

1. API Keys: Obtain the following free API keys and add them to your     config.ini file:

      VirusTotal/MalShare/MalwareBazaar/MXToolbox

3. Folder Structure: Inside the SpamScan folder, create two subfolders:
   
   ./potential_spam/ - Place suspicious .eml files here.
   
   ./spam_attachments/ - Extracted attachments will be saved here.

Usage

1. Place Suspicious Emails: Add any suspicious .eml files into the potential_spam/ folder.

2. Run the Scanner: Execute main.py to perform the following actions:

   - Extract attachments from each .eml file.
   - Generate a SHA-256 hash for every extracted attachment.
   - Log the sender’s domain and corresponding attachment information in hashes.txt:
     
     domain.com | file.txt: 2340000
     
Domain and Hash Checks: The tool will then:

- Check the sender's domain against the MXToolbox blacklist.
- Verify the attachment hash using VirusTotal, without uploading the file (to prevent accidental data leaks).
- Append the results to the RESULTS section in your config.ini file.
