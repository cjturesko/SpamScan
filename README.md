- Create a folder titled potential_spam & spam_attachments inside the SpamScan folder.
- Place suspicous .eml file into potential spam folder.
- Generate the required free API keys to run
    - VirusTotal
    - MalwareShare
    - MalwareBazar
    - MXTOOLBOX
- Run main.py
    - Will extract all attachments from the .eml
    - Generate a sha256 hash for any extracted attachments
    - Save the sender's domain next to attachment info in hashes.txt
          - domain.com|file.txt: 2340000
  
    - Uses hashes.txt to check:
          - Sender domain again MXTOOLBOX domain check
          - Check hash against VT (addings scans)
              - doesn't upload file to avoid accidental data leakage
          - Print out results as it goes & writes to RESULTS in config.ini
