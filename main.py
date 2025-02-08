import csv
import hashlib
import base58
import random
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import ecdsa
import time
from threading import Thread
from colorama import Fore, Style, init
from termcolor import colored

# Initialize colorama
init(autoreset=True)

# Function to print ASCII logo with multiple colors
def print_logo():
    logo = ```
***********************************
* ____       _            _       *
*|  _ \ _ __(_)_   ____ _| |_ ___ *
*| |_) | '__| \ \ / / _` | __/ _ \*
*|  __/| |  | |\ V / (_| | ||  __/*
*|_|   |_|__|_| \_/ \__,_|\__\___|*
*        | __ )| |_ ___           *
*        |  _ \| __/ __|          *
*        | |_) | || (__           *
*        |____/ \__\___|BitKeyHash*
***********************************
    for line in logo.split('\n'):
        colored_line = ''
        for char in line:
            if char in "*|":
                colored_line += colored(char, 'yellow')
            elif char.isalpha():
                colored_line += colored(char, 'cyan')
            else:
                colored_line += char
        print(colored_line)

# ---------------------------
# Helper Functions
# ---------------------------

def generate_private_key(start_range, end_range):
    """
    Generate a random private key within the given range.
    """
    return random.randint(start_range, end_range)


def private_key_to_public_key(private_key):
    """
    Derive the public key from the private key using ECDSA.
    """
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, 'big'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x04' + vk.to_string()  # Uncompressed public key format
    return public_key


def public_key_to_address(public_key):
    """
    Convert the public key to a Bitcoin wallet address.
    """
    # Step 1: SHA-256 hash of the public key
    sha256 = hashlib.sha256(public_key).digest()
    
    # Step 2: RIPEMD-160 hash of the SHA-256 hash
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    hashed_public_key = ripemd160.digest()
    
    # Step 3: Add network byte (0x00 for Bitcoin mainnet)
    network_byte = b'\x00' + hashed_public_key
    
    # Step 4: Double SHA-256 hash for checksum
    checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
    
    # Step 5: Append checksum to network byte
    binary_address = network_byte + checksum
    
    # Step 6: Encode in Base58
    wallet_address = base58.b58encode(binary_address)
    return wallet_address.decode('utf-8')


def process_batch(start_range, end_range, batch_size):
    """
    Generate a batch of private keys and their corresponding wallet addresses.
    """
    results = []
    for _ in range(batch_size):
        private_key = generate_private_key(start_range, end_range)
        public_key = private_key_to_public_key(private_key)
        wallet_address = public_key_to_address(public_key)
        results.append((private_key, wallet_address))
    return results


# ---------------------------
# Main Logic
# ---------------------------

def main():
    print_logo()

    START_RANGE = 1
    END_RANGE = 2**256 - 1  # Maximum possible private key value for Bitcoin

    NUM_WORKERS = 8  # Adjust based on your CPU cores or workload
    BATCH_SIZE = 10   # Number of keys to process in each batch

    # Prompt user for the total number of keys to generate
    total_keys = int(input("Enter the number of Bitcoin keys to generate: "))

    # Calculate the number of tasks (batches) based on batch size
    num_tasks = total_keys // BATCH_SIZE
    if total_keys % BATCH_SIZE != 0:
        num_tasks += 1  # Add one more batch for remaining keys

    task_queue = Queue()
    
    # Fill the task queue with batch sizes
    for _ in range(num_tasks):
        task_queue.put(BATCH_SIZE)

    results = []
    keys_generated = 0

    def worker():
        nonlocal keys_generated
        while not task_queue.empty():
            try:
                batch_size = task_queue.get_nowait()
                batch_results = process_batch(START_RANGE, END_RANGE, batch_size)
                results.extend(batch_results)
                keys_generated += len(batch_results)
            except Exception as e:
                print(f"{Fore.RED}Error in worker: {e}")

    # Function to report progress every minute
    def report_progress():
        while keys_generated < total_keys:
            print(f"{Fore.YELLOW}Keys generated so far: {keys_generated}/{total_keys}")
            time.sleep(10)

    # Start progress reporting in a separate thread
    progress_thread = Thread(target=report_progress)
    progress_thread.start()

    # Measure total execution time
    start_time = time.time()

    # Use ThreadPoolExecutor for parallelism
    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        executor.map(lambda _: worker(), range(NUM_WORKERS))

    # Wait for the progress thread to finish
    progress_thread.join()

    # Write results to CSV file
    with open('bitcoin_keys.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Private Key', 'Wallet Address'])
        writer.writerows(results)

    end_time = time.time()
    total_time = end_time - start_time

    print(f"{Fore.GREEN}CSV file generated successfully with {len(results)} keys!")
    print(f"{Fore.CYAN}Total time taken: {total_time:.2f} seconds")


if __name__ == "__main__":
    main()
