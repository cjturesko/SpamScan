
hashes = './SpamScan/hashes.txt'
munin = './munin'
muninINI = './munin.ini'
output = './SpamScan/hashes_results.txt'

import subprocess
import os

import subprocess

def run_munin_on_hashes(hash_file, munin_path, config_path, output_file_path):
    # Run the Munin command with the existing hash file
    try:
        result = subprocess.run(
            [f"{munin_path}/munin.py", "-f", hash_file, "-o", output_file_path],
            check=True, capture_output=True, text=True
        )
        print(f"Results saved to {output_file_path}.")
        print(f"Munin output: {result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Error processing hashes: {e.stderr}")
        print(f"e current value {e}")
        
run_munin_on_hashes(hashes, munin, muninINI, output)

