# 🎢 Welcome to Bitcoin Key Wonderland 🎢

![Alt Text](https://i.ibb.co/ycFnMbWX/Screenshot-2025-02-08-18-30-34-435-com-termux.jpg)

Welcome to the Bitcoin Key Wonderland, the most thrilling and fun-filled theme park for all crypto enthusiasts! Step right up and join the adventure of generating private keys and deriving Bitcoin addresses in the blink of an eye! Hold on tight, because you’re in for a wild ride!

## 🎠 Attractions

### 🎢 Private Key Roller Coaster
Experience the excitement of the Private Key Roller Coaster! Generate random private keys within the blink of an eye. Hold on tight as we take you through a whirlwind tour of cryptographic randomness!

### 🚀 ECDSA Launch Pad
Blast off with the ECDSA Launch Pad! Watch in awe as we derive public keys from your private keys using the amazing Elliptic Curve Digital Signature Algorithm (ECDSA). It’s a ride that’s out of this world!

### 🏰 Bitcoin Address Castle
Enter the majestic Bitcoin Address Castle, where public keys are transformed into Bitcoin wallet addresses through a magical process of hashing and encoding. See the wonder of cryptographic transformations happen right before your eyes!

## 🎟️ Getting Started

Before you embark on your adventure, make sure you have your ticket ready:

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/bitkeyhash/PrivateBtc.git
   cd PrivateBtc
   ```

2. **Install the Requirements:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the Adventure:**
   ```bash
   python main.py
   ```

## 🎡 How It Works

1. **Private Key Generation:**
   The Private Key Roller Coaster generates a random private key within the range of 1 to 2^256 - 1. It’s a thrilling drop from the highest heights of cryptographic possibilities!

2. **Public Key Derivation:**
   The ECDSA Launch Pad propels your private key to new heights, deriving the corresponding public key using the Secp256k1 curve. Watch as your key soars to new heights!

3. **Bitcoin Address Conversion:**
   The Bitcoin Address Castle performs a series of magical transformations:
   - SHA-256 hash of the public key
   - RIPEMD-160 hash of the SHA-256 hash
   - Addition of the network byte
   - Double SHA-256 hash for checksum
   - Base58 encoding for the final address

4. **CSV Output:**
   At the end of your adventure, receive a souvenir in the form of a CSV file containing all the private keys and wallet addresses you generated. A memory to cherish forever! Name of output csv :
   ```markdown
   bitcoin_keys.csv
   ```

## 🎢 Join the Fun

Join the fun and excitement at Bitcoin Key Wonderland! Generate as many keys as you want and explore the magic of cryptography in the most entertaining way possible. 

Step right up and start your adventure today!

Feel free to provide feedback or let me know if there are any changes you would like to make!
