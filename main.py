import csv
import hashlib
import base58
import random
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
import ecdsa

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
    START_RANGE = 1
    END_RANGE = 2**256 - 1  # Maximum possible private key value for Bitcoin
    
    NUM_WORKERS = 8  # Adjust based on your CPU cores or workload
    NUM_TASKS = 1000  # Total number of keys to generate
    BATCH_SIZE = 10   # Number of keys to process in each batch

    task_queue = Queue()
    
    # Fill the task queue with batch sizes
    for _ in range(NUM_TASKS // BATCH_SIZE):
        task_queue.put(BATCH_SIZE)

    results = []

    def worker():
        while not task_queue.empty():
            try:
                batch_size = task_queue.get_nowait()
                batch_results = process_batch(START_RANGE, END_RANGE, batch_size)
                results.extend(batch_results)
            except Exception as e:
                print(f"Error in worker: {e}")

    # Use ThreadPoolExecutor for parallelism
    with ThreadPoolExecutor(max_workers=NUM_WORKERS) as executor:
        executor.map(lambda _: worker(), range(NUM_WORKERS))

    # Write results to CSV file
    with open('bitcoin_keys.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Private Key', 'Wallet Address'])
        writer.writerows(results)

    print("CSV file generated successfully!")


if __name__ == "__main__":
    main()
    
