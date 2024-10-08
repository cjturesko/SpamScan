
import configparser
import json
import requests
from extract_attachments import process_eml_files

config = configparser.ConfigParser()
config.read('./SpamScan/config.ini')

VIRUSTOTAL_API_KEY = config['DEFAULT']['VT_API_KEY']
MAL_SHARE_API_KEY = config['DEFAULT']['MAL_SHARE_API_KEY']
MAL_BAZAR_API_KEY = config['DEFAULT']['MAL_BAZAR_API_KEY']
MX_API_KEY = config['DEFAULT']['MX_API_KEY']
UURLSCAN_API_KEY = config['DEFAULT']['URLSCAN_API_KEY']
RESULTS = config['HASHES']['RESULTS_TXT']

def checkDomain(hashFile):
    with open(hashFile, "r") as file, open(RESULTS, 'w') as result_file:
        for entry in file:
            try:
                domainName, ending = entry.strip().split('|')
                url_base = 'https://mxtoolbox.com/api/v1/lookup/blacklist/'
                url = url_base + domainName
                headers = {
                     'Authorization': mx_api_key
                     }
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    print("Response 200")
                    responseData = response.json()
                else:
                    print("Response not 200!!")
                    continue

                failed = responseData.get('Failed', [])
                warnings = responseData.get('Warnings', [])

                if failed:
                    numFailed = len(failed)
                    print(f'Domain Failed: {numFailed} Times')
                    result_file.write(f"{domainName}|BLACKLIST FAIL - {numFailed}|{ending}\n")
                elif warnings:
                    numWarnings = len(warnings)
                    print(f'Domain Warning: {warnings}')
                    result_file.write(f"{domainName}|BLACKLIST WARNING - {numWarnings}|{ending}\n")
                else:
                    #write the line in again regardless since it's open & being overwritten.
                    result_file.write(f"{domainName}|NO BLACKLIST|{ending}\n")
                    print(f"The domain {domainName} is not blacklisted.")
          
            except ValueError as e:
                print(f"Error processing entry in Check_domain: {entry}")
                print(f"Error involving: {e}")

def process_hashes(hashFile, scanner):
    with open(hashFile, 'r') as file, open(RESULTS, 'w') as result_file:
        for entry in file:
            try:
                filename, hash_value = entry.strip().split(': ')
                result = scanner(hash_value)

                ####
                # Results specific to VT
                ####
                if result:
                    # Check if any engine marked the file as malicious
                    detected_engines = []
                    clean_engines = []

                    # Loop through the results
                    for engine, details in result.get("scans", {}).items():
                        if details['result'] is not None:  # Engine returned a result
                            detected_engines.append(engine)
                        else:
                            clean_engines.append(engine)

                    # Determine the status
                    if detected_engines:
                        status = "Malware Detected"
                        # Write the results to the file
                        result_file.write(f"{filename}: {hash_value} - {status} (Detected by: {', '.join(detected_engines)})\n")
                    else:
                        status = "Clean"
                        # Write the results to the file
                        result_file.write(f"{filename}: {hash_value} - {status}\n")
                else:
                    # Unknown Hash
                    result_file.write(f"{filename}: {hash_value} - Not Found")

            except ValueError:
                print(f"Error processing line: {entry.strip()}")
                

def scan_VT(hash_value):
    if VIRUSTOTAL_API_KEY == '-' or not VIRUSTOTAL_API_KEY:
         print('VirusTotal API Key blank --- skipped')

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        vtdata = response.json()
        return vtdata
    else:
        return None
    
def scan_MS(hash_value):
    url = f"https://malshare.com/api.php?api_key={MAL_SHARE_API_KEY}&action=search&query={hash_value}"
    response = requests.get(url)
    print(f"Scan_MS response = {response}")
    if ("Sample not found by hash" in response.content):
        print("MalShare didnt find a result")
    else:
        return response


def scan_MB(MAL_BAZAR_API_KEY):
    pass


def main():
    spam_folder = "./SpamScan/potential_spam"  # Replace with actual path
    attachments_folder = "./SpamScan/spam_attachments"  # Replace with actual path
    hash_file_path = "./SpamScan/hashes.txt" # Replace with hashes.txt location
    # Output path for results

    # Process all .eml files and extract attachments, and generate hashes
    process_eml_files(spam_folder, attachments_folder, hash_file_path)
    #hash_files_in_folder(attachments_folder, hash_file_path)
    
    process_hashes(hash_file_path,scan_VT)
    process_hashes(hash_file_path,scan_MS)
    

if __name__== '__main__':
     main()
