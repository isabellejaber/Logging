import subprocess
import sys
import logging

logger = logging.getLogger(__name__)
logging.basicConfig(filename='logs.log', encoding='utf-8', level=logging.DEBUG)

def run_command(command):
    try:
        # Run the command and capture both stdout and stderr
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Print stdout to the console
        print("Standard Output:")
        print(result.stdout)

    except subprocess.CalledProcessError as e:
        # Print and log stderr if the command fails
        print(f"Error occurred: {e.stderr}".rstrip('\n'))
        logging.error(f"Error occurred: {e.stderr}".rstrip('\n'))
        logging.info("PLEASE TRY AGAIN\n")

        # Optionally, exit with a non-zero status
        sys.exit(1)

if __name__ == "__main__":
    # Collect inputs dynamically
    mode = input("Enter mode (encrypt/decrypt): ").strip().lower()
    if mode != "encrypt" and mode != "decrypt":
        plaintext = ""
        key = ""
    else:
        plaintext = input(f"Enter text to {mode}: ").strip()
        key = input(f"Enter {mode}ion key: ").strip()

    # Construct command to run the main script with the provided arguments
    command = [
        'python3', 'encryptDecryptApplication.py',
        '-p', plaintext,
        '-k', key,
        mode
    ]

    # Run the command
    run_command(command)