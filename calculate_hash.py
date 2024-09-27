import os
import hashlib

def sha256_hash_file(file_path):
    # Calculate SHA-256 hash of a file.
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

def hash_files_in_folder(folder_path, output_file_path):
    # Generate SHA-256 hashes for all files in the specified folder
    with open(output_file_path, 'w') as output_file:
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path):
                hash_value = sha256_hash_file(file_path)
                output_file.write(f"{filename}: {hash_value}\n")
                print(f'{filename} : {hash_value}')

if __name__ == "__main__":
    folder = "./SpamScan/spam_attachments"
    output_file = "./SpamScan/hashes.txt"
    hash_files_in_folder(folder, output_file)