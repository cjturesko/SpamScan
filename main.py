
import configparser
import json
import requests
from extract_attachments import process_eml_files

config = configparser.ConfigParser()
config.read('./SpamScan/config.ini')

VIRUSTOTAL_API_KEY = config['DEFAULT']['VT_API_KEY']
MAL_SHARE_API_KEY = config['DEFAULT']['MAL_SHARE_API_KEY']
MX_API_KEY = config['DEFAULT']['MX_API_KEY']
URLSCAN_API_KEY = config['DEFAULT']['URLSCAN_API_KEY']
RESULTS = config['HASHES']['RESULTS_TXT']

def checkDomain(hashFile):
    with open(hashFile, "r") as file: #, open(RESULTS, 'w') as result_file:
        for entry in file:
            try:
                domainName, ending = entry.strip().split('|')
                url_base = 'https://mxtoolbox.com/api/v1/lookup/blacklist/'
                url = url_base + domainName
                headers = {
                     'Authorization': MX_API_KEY
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
                    print(f"{domainName}|BLACKLIST FAIL - {numFailed}|{ending}\n")
                    #result_file.write(f"{domainName}|BLACKLIST FAIL - {numFailed}|{ending}\n")
                elif warnings:
                    numWarnings = len(warnings)
                    print(f"{domainName}|BLACKLIST WARNING - {numWarnings}|{ending}\n")
                    #result_file.write(f"{domainName}|BLACKLIST WARNING - {numWarnings}|{ending}\n")
                else:
                    #write the line in again regardless since it's open & being overwritten.
                    #result_file.write(f"{domainName}|NO BLACKLIST|{ending}\n")
                    print(f"The domain {domainName} is not blacklisted.")
          
            except ValueError as e:
                print(f"Error processing entry in Check_domain: {entry}")
                print(f"Error involving: {e}")


def process_hashes(hashFile, scanner):
    with open(hashFile, 'r') as file:
        for entry in file:
            try:
                filename, hash_value = entry.strip().split(': ')
                result = scanner(hash_value)
                
                if result:
                    # will vary based on the api
                    print(f"Hash {hash_value} scanned successfully. Result: {result}\n")
                else:
                    print(f"Hash {hash_value} not found or error occurred.")
            except ValueError:
                print(f'Error proccessing hash {entry.strip()}')
                
def scan_VT(hash_value):
    if VIRUSTOTAL_API_KEY == '-' or not VIRUSTOTAL_API_KEY:
        print('VirusTotal API Key blank --- skipped')
        return

    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        vtdata = response.json()

        #Process VT results
        detected_engines = []
        clean_engines = []

        #Loop through results
        for engine, details in vtdata.get("data", {}).get("attributes", {}).get("last_analysis_results", {}).items():
            if details['result'] is not None: #engine returned a result
                detected_engines.append(engine)
            else:
                clean_engines.append(engine)

        #Determine the status
        if detected_engines:
            status = "Malware Detected"
            print(f"{status}: VT")
            print(f"Hash {hash_value} - {status} (Detected by: {', '.join(detected_engines)})")
            return f"Hash {hash_value} - {status} (Detected by: {', '.join(detected_engines)})"
        else:
            status = "Clean"
            print(f"{status}: VT")
            return f"Hash {hash_value} - {status}"

    else:
        return f"Hash {hash_value} - Not Found"

    
    
def scan_MS(hash_value):
    url = f"https://malshare.com/api.php?api_key={MAL_SHARE_API_KEY}&action=search&query={hash_value}"
    headers = {'User-Agent': 'MalShare API Tool v/0.1 beta'}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        try:
            response_data = json.loads(response.text)
            
            if not response_data:
                print("MalShare didnt find a result")
            else:
                print(f"Malshare found result {response_data}")
            return response_data
        except json.JSONDecodeError:
            print("Error: Response not JSON")
    else:
        print("Error with reply -- possible offline")

def scan_MHR(hash_value, mhr_un, mhr_pw):
    #issues with SSL but works
    #pass
    '''
    url = f"https://hash.cymru.com/v2/{hash_value}"
    print(f'MHR url: --  {url}')
    # Make the GET request to the MHR API
    response = requests.get(url, auth=HTTPBasicAuth(mhr_un, mhr_pw), verify=False)
    
    # Check if the response is successful (status code 200)
    if response.status_code == 200:
        try:
            # Parse the response as JSON (assuming it returns JSON data)
            data = response.json()
        except ValueError:
            print("Error: Unable to parse response as JSON")
            return

        # Check if the hash is found in the registry
        if data.get('sha1256') is None:
            print('Hash not found on Malware Hash Registry')
        else:
            print(f"Hash {data['sha1256']} found. AV Detection Rate: {data['antivirus_detection_rate']}")
    else:
        print(f"Error: Received status code {response.status_code}.")
    '''

def scan_MB(hash_value):
    url = "https://mb-api.abuse.ch/api/v1/"

    #data for the post request
    data = {
        'query': 'get_info',
        'hash': hash_value
    }

    #Make the post request
    response = requests.post(url, data=data)

    #check response data
    if response.status_code == 200:
        result = response.json()
        
        if result.get('query_status') == 'hash_not_found':
            # MB returns a hash_not_found
            return None
        if 'first_seen' in result:
            print('Malware Bazaar Found Reult')
        else:
            print(f"Malware Bazaar found result for {hash_value} but 'first_seen' is not found")

    else:
        print(f"Error: Received status code {response.status_code}. Message: {response.text}")
        return None
    
        


def main():
    spam_folder = "/Users/ixu/Projects/SecTools/SpamScan/potential_spam"  # Replace with actual path
    attachments_folder = "/Users/ixu/Projects/SecTools/SpamScan/spam_attachments"  # Replace with actual path
    hash_file_path = "/Users/ixu/Projects/SecTools/SpamScan/hashes.txt" # Replace with hashes.txt location
    # Output path for results

    # Process all .eml files and extract attachments, and generate hashes
    process_eml_files(spam_folder, attachments_folder, hash_file_path)
    #hash_files_in_folder(attachments_folder, hash_file_path)

    process_hashes(hash_file_path,scan_VT)
    print('--VirusTotal Scan Completed--\n')
    process_hashes(hash_file_path, lambda hash_value: scan_MS(hash_value))
    print('--Malshare Scan Completed--\n')
    process_hashes(hash_file_path, lambda hash_value: scan_MB(hash_value))
    print('--Malware Bazaar Scan Completed--\n')
    #process_hashes(hash_file_path, lambda hash_value: scan_MHR(hash_value))


    

if __name__== '__main__':
     main()
