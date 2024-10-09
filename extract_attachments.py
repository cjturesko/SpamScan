from __future__ import print_function
import os
from email.parser import Parser
import hashlib

def parse_message(filename):
    with open(filename) as f:
        return Parser().parse(f)

def find_attachments(message):
    found = []
    for part in message.walk():
        if 'content-disposition' not in part:
            continue
        cdisp = part['content-disposition'].split(';')
        cdisp = [x.strip() for x in cdisp]
        if cdisp[0].lower() != 'attachment':
            continue
        parsed = {}
        for kv in cdisp[1:]:
            key, _, val = kv.partition('=')
            if val.startswith('"'):
                val = val.strip('"')
            elif val.startswith("'"):
                val = val.strip("'")
            parsed[key] = val
        found.append((parsed, part))
    return found

def extract_sender_email(message):
    return message['From']

def sha256_hash_file(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_attachments(eml_filename, output_dir, hash_output_file):
    msg = parse_message(eml_filename)
    attachments = find_attachments(msg)
    sender_email = extract_sender_email(msg)
    print("Found {0} attachments...".format(len(attachments)))
    
    # Extract domain from sender email
    sender_domain = sender_email.split('@')[-1].strip('> ')
    
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    
    attachment_count = 1  # Counter for attachments without filenames
    
    for cdisp, part in attachments:
        cdisp_filename = cdisp.get('filename', f"attachment_{attachment_count}")
        cdisp_filename = os.path.normpath(cdisp_filename)
        if os.path.isabs(cdisp_filename):
            cdisp_filename = os.path.basename(cdisp_filename)
        
        towrite = os.path.join(output_dir, cdisp_filename)
        print(f"Writing {towrite}")
        
        # Get the payload (attachment data) and decode it
        data = part.get_payload(decode=True)
        
        # Check if the data is None (could happen if it's not decodable)
        if data is None:
            print(f"Warning: Could not decode attachment {cdisp_filename}. Skipping...")
            continue  # Skip this attachment if decoding fails

        # Write the decoded attachment data to the file
        with open(towrite, 'wb') as fp:
            fp.write(data)

        # Calculate the hash of the written file
        hash_value = sha256_hash_file(towrite)
        
        # Write the domain, filename, and hash to the output file
        with open(hash_output_file, 'a') as hash_file:
            hash_file.write(f"{sender_domain}|{cdisp_filename}: {hash_value}\n")
        
        attachment_count += 1  # Increment counter for next attachment

def process_eml_files(spam_folder, attachments_folder, hash_output_file):
    for filename in os.listdir(spam_folder):
        if filename.endswith(".eml"):
            eml_path = os.path.join(spam_folder, filename)
            print(f"Processing {eml_path}...")
            extract_attachments(eml_path, attachments_folder, hash_output_file)

def main():
    spam_folder = "./SpamScan/potential_spam"  # Replace with actual path
    attachments_folder = "./SpamScan/spam_attachments"  # Replace with actual path
    hash_output_file = "./SpamScan/hashes.txt"  # Path for the hash output file

    # Ensure the output file is empty before writing
    open(hash_output_file, 'w').close()

    process_eml_files(spam_folder, attachments_folder, hash_output_file)

if __name__ == '__main__':
    main()
