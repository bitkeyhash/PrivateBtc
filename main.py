import csv
import hashlib
import base58
import ecdsa
import random
import threading
from multiprocessing import Process, Queue, Value, Lock
import time
import os  # Import os for signal handling


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
    # Secp256k1 curve parameters
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


def worker(task_queue, result_queue, start_range, end_range, running):
    """
    Worker function to generate private keys and derive addresses.  Takes a
    'running' Value to signal termination.
    """
    while running.value:  # Check the shared running flag
        try:
            # Use get with a timeout to allow checking 'running'
            task = task_queue.get(timeout=0.1)
            if task is None:  # Use a sentinel value to signal termination
                break
            
            # Generate private key
            private_key = generate_private_key(start_range, end_range)
            
            # Derive public key and wallet address
            public_key = private_key_to_public_key(private_key)
            wallet_address = public_key_to_address(public_key)
            
            # Put result into the result queue
            result_queue.put((private_key, wallet_address))
        except Exception as e:
            # More specific queue handling (Empty exception)
            if 'Empty' not in str(e): #check if the error is really an empty queue exception.
              print(f"Error in worker: {e}")
        


# ---------------------------
# Main Logic
# ---------------------------

def main():
    # Define the range for private key generation
    START_RANGE = 1
    END_RANGE = 2**256 - 1  # Maximum possible private key value for Bitcoin
    
    # Number of threads/processes
    NUM_WORKERS = 8  # Adjust based on your CPU cores
    
    # Task and result queues
    task_queue = Queue()
    result_queue = Queue()
    
    # Shared variable to signal workers to stop
    running = Value('b', True)  # 'b' for boolean, initialized to True
    
    # Fill the task queue with dummy tasks (one per worker iteration)
    NUM_TASKS = 1000000  # Adjust based on how many keys you want to generate
    for _ in range(NUM_TASKS):
        task_queue.put(1)  # Dummy task

    # Add sentinel values to signal workers to stop after processing tasks
    for _ in range(NUM_WORKERS):
      task_queue.put(None)

    
    # Start workers (using multiprocessing for better performance)
    processes = []
    for _ in range(NUM_WORKERS):
        p = Process(target=worker, args=(task_queue, result_queue, START_RANGE, END_RANGE, running))
        processes.append(p)
        p.start()
    
    try:
        # Wait for all workers to finish, with a timeout
        for p in processes:
            p.join(timeout=60)  # Timeout after 60 seconds (adjust as needed)
    except KeyboardInterrupt:
        print("Caught KeyboardInterrupt, terminating workers...")
        running.value = False  # Signal all workers to stop
        for p in processes:
            p.terminate() # Forcefully terminate the process
            p.join() # Wait for the process to clean up

    
    # Collect results and write to CSV
    with open('bitcoin_keys.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Private Key', 'Wallet Address'])  # Header
        
        while not result_queue.empty():
            private_key, wallet_address = result_queue.get()
            writer.writerow([private_key, wallet_address])
    
    print("CSV file generated successfully!")

if __name__ == "__main__":
    main()


