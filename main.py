from extract_attachments import process_eml_files
from check_hash import run_munin_on_hashes
from calculate_hash import hash_files_in_folder

def main():
    # Define your directories
    spam_folder = "./SpamScan/potential_spam"
    attachments_folder = "./SpamScan/spam_attachments"
    munin_path = "./munin"
    hash_file_path = "./SpamScan/hashes.txt"
    output_file = "./SpamScan/hashes_results.txt"
    muninINI = "./munin/munin.ini"

    # Process all .eml files and extract attachments, and generate hashes
    process_eml_files(spam_folder, attachments_folder)
    hash_files_in_folder(attachments_folder, hash_file_path)
    
    # Run Munin on the hashes
    print(f"Running Munin on hashes...")
    run_munin_on_hashes(hash_file_path, munin_path, muninINI, output_file)

if __name__ == '__main__':
    main()
