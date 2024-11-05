import os
from email.parser import Parser
import hashlib
import configparser
import requests
import re
import time
import quopri

config = configparser.ConfigParser()
config.read('./SpamScan/config.ini')

VIRUSTOTAL_API_KEY = config['DEFAULT']['VT_API_KEY']
URLSCAN_API_KEY = config['DEFAULT']['URLSCAN_API_KEY']

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
    from_field = message['From']
    domain = re.search(r'<(.+?)>', from_field)
    if domain:
        return domain.group(1)
    else:
        return from_field # Return the whole field if not found
        
def extract_links(message):
    links = []
    
    for part in message.walk():
        # Only look at plain text or HTML parts
        if part.get_content_type() in ['text/plain', 'text/html']:
            payload = part.get_payload(decode=True)

            # Decode quoted-printable encoding if needed
            if part.get("Content-Transfer-Encoding") == "quoted-printable":
                decoded_content = quopri.decodestring(payload).decode(part.get_content_charset() or 'utf-8', errors='ignore')
            else:
                decoded_content = payload.decode(part.get_content_charset() or 'utf-8', errors='ignore')
            
            # Find links in the decoded content
            link_pattern = r'https?://[^\s<>"\']+|www\.[^\s<>"\']+'
            links.extend(re.findall(link_pattern, decoded_content))

    return links

def scan_url(url):
    api_url = 'https://urlscan.io/api/v1/scan/'
    headers = {
        'Content-Type': 'application/json',
        'API-KEY': URLSCAN_API_KEY
    }
    data = {
        "url": url, 
        "visibility": "private"
    }

    response = requests.post(api_url, headers=headers, json=data)
    if response.status_code == 200:
        result = response.json()
        uuid = result.get('uuid')
        print(f"URL scan submitted. UUID: {uuid}")
        time.sleep(5)  # wait 5 seconds before checking results
        get_scan_results(uuid)  # Check result in a separate function
    else:
        print(f"Error submitting scan: {response.status_code}, {response.text}")

# Function to retry checking the scan result (with retries and delay)
def get_scan_results(uuid):
    result_url = f"https://urlscan.io/api/v1/result/{uuid}"
    retries = 5
    delay = 5
    for attempt in range(retries):
        response = requests.get(result_url)

        if response.status_code == 200:
            result_data = response.json()
            verdicts = result_data.get('verdicts', {})
            #print("Verdicts:")
            display_verdicts(verdicts)
            break  # Scan is complete, exit loop
        elif response.status_code == 404:
            print(f"Attempt {attempt + 1}: Scan still processing, retrying in {delay} seconds...")
            time.sleep(delay)  # Wait before retrying
        else:
            print(f"Error: {response.status_code}, {response.text}")
            break  # Break out if there's another type of error

    else:
        print(f"Max retries reached. UUID {uuid} might still be processing. Check later.")

def display_verdicts(verdicts):
    if not verdicts:
        print("No verdicts found.")
        return
    # For the sections being displayed
    sections = {
        'Overall': verdicts.get('overall', {}),
        'URLScan': verdicts.get('urlscan', {}),
        'Engines': verdicts.get('engines', {}),
        'Community': verdicts.get('community', {})
    }

    # Display results for each section
    for section, data in sections.items():
        print(f"\n=== {section} Verdicts ===")
        score = data.get('score', 0)
        is_malicious = data.get('malicious', False)
        categories = data.get('categories', [])
        brands = data.get('bands', [])
        tags = data.get('tags', [])

        print(f"Score: {score}")
        print(f"Malicious: {is_malicious}")
        if categories:
            print(f"Categories: {', '.join(categories)}")
        if brands:
            print(f"Brands: {', '.join(brands)}")
        if tags:
            print(f"Tags: {', '.join(tags)}")

        # Special handling for 'Engines' and 'Community' subcategories
        if section == 'Engines':
            print(f"Engines Total: {data.get('enginesTotal', 0)}")
            print(f"Malicious Verdicts: {data.get('maliciousVerdicts', [])}")
            print(f"Benign Verdicts: {data.get('benignVerdicts', [])}")
        elif section == 'Community':
            print(f"Votes Total: {data.get('votesTotal', 0)}")
            print(f"Votes Malicious: {data.get('votesMalicious', 0)}")
            print(f"Votes Benign: {data.get('votesBenign', 0)}")

def extract_ip_and_spf(message):
    ip_address = None
    spf_result = None

    # Check SPF result
    spf_header = message.get('Received-SPF')
    if spf_header:
        spf_result = 'SPF Pass'
        if 'fail' in spf_header.lower():
            spf_result = 'SPF Fail'
        elif 'softfail' in spf_header.lower():
            spf_result = 'SPF Softfail'

    # Function to extract IP from a string
    def extract_ip(text):
        # This pattern matches IPv4 addresses
        ip_pattern = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
        match = re.search(ip_pattern, text)
        return match.group(0) if match else None

    # Try to find IP in various headers
    headers_to_check = [
        ('x-ms-exchange-organization-originalclientipaddress', lambda x: x),
        ('Received-SPF', lambda x: x.split('client-ip=')[1].split()[0] if 'client-ip=' in x else None),
        ('Received', lambda x: extract_ip(x))
    ]

    for header_name, extractor in headers_to_check:
        header_value = message.get(header_name)
        if header_value:
            if isinstance(header_value, list):
                for value in header_value:
                    ip = extractor(value)
                    if ip:
                        ip_address = ip
                        break
            else:
                ip = extractor(header_value)
                if ip:
                    ip_address = ip
                    break

        if ip_address:
            break

    # Strip any trailing semicolon or whitespace from the final IP address
    if ip_address:
        ip_address = ip_address.rstrip('; ')
    
    return ip_address, spf_result

def check_ip_address(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
        }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        last_analysis_results = data['data']['attributes']['last_analysis_results']

        print('*-*-*-IP Check Lookup-*-*-*')
        print(f"IP Address: {ip_address}")
        print('*-*-*-*-*-*-*-*-*-*-*-*-*-*')
        

        for company, result in last_analysis_results.items():
            if result['result'] in ['malware', 'suspicious']:
                print("Companies flagging as malware or suspicious:")
                print(f"   - {company}: {result['result']}")

    else:
        print(f"Error: Unable to check IP {response.status_code}")


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
    ip_address, spf_result = extract_ip_and_spf(msg)
    print(f"--Sender: {sender_email}")
    print(f"--IP Address: {ip_address}")
    print(f"SPF Result: {spf_result}")
    
    if ip_address:
        vt_results = check_ip_address(ip_address)
        if vt_results:
            print("IP Check Results: ")
            for result in vt_results:
                print(f" - {result}")
        else:
            print("IP Check Clean")

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
            
            msg = parse_message(eml_path)  # Parse the .eml file
            extract_attachments(eml_path, attachments_folder, hash_output_file)  # Process attachments
            
            # Extract and scan links
            links = extract_links(msg)
            if links:
                print("*-*-Links Found-*-*")
                for index, link in enumerate(links, start=1):
                    print(f"{index}. {link}")
                #Choose numbers for links to scan
                selected = input("Enter #,# or a/all for all ")
    
                if selected.lower() in ('all', 'a'):
                    selected_indices = list(range(1, len(links) + 1))  # Selects all indices
                else:
                    selected_indices = [int(num.strip()) for num in selected.split(',') if num.strip().isdigit()]
                #Process selected numbers
                for i in selected_indices:
                    if 1 <= i <= len(links):
                        link_to_scan = links[i - 1]
                        print(f"Scanning link: {link_to_scan}")
                        # Call URLScan API to check URL
                        scan_url(link_to_scan)
                
                    else:
                        print(f"Invalid selection: {i}")
            else:
                print("No Links in EML")
            
def main():
    spam_folder = "./SpamScan/potential_spam"  # Replace with actual path
    attachments_folder = "./SpamScan/spam_attachments"  # Replace with actual path
    hash_output_file = "./SpamScan/hashes.txt"  # Path for the hash output file

    # Ensure the output file is empty before writing
    open(hash_output_file, 'w').close()

    process_eml_files(spam_folder, attachments_folder, hash_output_file)

if __name__ == '__main__':
    main()
