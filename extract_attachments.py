
from __future__ import print_function
import sys
import os
from email.parser import Parser
from collections import defaultdict
from calculate_hash import hash_files_in_folder


def parse_message(filename):
    with open(filename) as f:
        return Parser().parse(f)

def find_attachments(message):
    """
    Return a tuple of parsed content-disposition dict, message object
    for each attachment found.
    """
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

def extract_attachments(eml_filename, output_dir):
    msg = parse_message(eml_filename)
    attachments = find_attachments(msg)
    print("Found {0} attachments...".format(len(attachments)))
    if not os.path.isdir(output_dir):
        os.makedirs(output_dir)
    
    attachment_count = 1  # Counter for attachments without filenames
    
    for cdisp, part in attachments:
        # Assign a default filename if 'filename' key is missing
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
        
        attachment_count += 1  # Increment counter for next attachment


def process_eml_files(spam_folder, attachments_folder):
    # Save the hashes.txt file in the attachments folder
    hash_output_file = os.path.join(attachments_folder, "hashes.txt")
    
    # Loop through all .eml files in the "potential_spam" folder
    for filename in os.listdir(spam_folder):
        if filename.endswith(".eml"):
            eml_path = os.path.join(spam_folder, filename)
            print(f"Processing {eml_path}...")
            extract_attachments(eml_path, attachments_folder)

    return hash_output_file # return the path of the hash file
    

def main():
    # Define your directories
    spam_folder = "./potential_spam"  # Replace with actual path
    attachments_folder = "./spam_attachments"  # Replace with actual path

    # Process all .eml files and extract attachments
    process_eml_files(spam_folder, attachments_folder)

if __name__ == '__main__':
    main()
