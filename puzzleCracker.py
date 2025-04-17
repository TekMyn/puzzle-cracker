import hashlib
import base58
import random
import ecdsa
import binascii
import time
import os
import multiprocessing
from datetime import datetime

# Adding a little chaos – better randomness for the seed
random.seed(os.urandom(32))

# Converts a private key into WIF format – needed for wallet import
def private_key_to_wif(private_key_hex):
    extended_key = "80" + private_key_hex
    first_sha256 = hashlib.sha256(binascii.unhexlify(extended_key)).digest()
    second_sha256 = hashlib.sha256(first_sha256).digest()
    checksum = binascii.hexlify(second_sha256[:4]).decode('utf-8')
    extended_key_with_checksum = extended_key + checksum
    return base58.b58encode(binascii.unhexlify(extended_key_with_checksum)).decode('utf-8')

# Converts private key into its corresponding Bitcoin address
# Handles both compressed and uncompressed formats
def private_key_to_address(private_key_hex, compressed=True):
    sk = ecdsa.SigningKey.from_string(binascii.unhexlify(private_key_hex), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    if compressed:
        # This part compresses the public key based on the Y coordinate parity
        public_key = ('02' if vk.pubkey.point.y() % 2 == 0 else '03') + binascii.hexlify(vk.pubkey.point.x().to_bytes(32, 'big')).decode('utf-8')
    else:
        public_key = '04' + binascii.hexlify(vk.to_string()).decode('utf-8')
    
    # Standard hash160 (SHA256 + RIPEMD160)
    sha256_hash = hashlib.sha256(binascii.unhexlify(public_key)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    network_hash = b'\x00' + ripemd160.digest()
    checksum = hashlib.sha256(hashlib.sha256(network_hash).digest()).digest()[:4]
    return base58.b58encode(network_hash + checksum).decode('utf-8')

# The actual brute-force attempt within a given range
def search_range(start_int, end_int, target_address, queue, process_id):
    total_attempts = 0
    start_time = time.time()

    while True:
        # Generate a random private key within the range
        random_key_int = random.randint(start_int, end_int)
        random_key_hex = format(random_key_int, 'x').zfill(64)

        # Get both compressed and uncompressed addresses for coverage
        address_c = private_key_to_address(random_key_hex, compressed=True)
        address_u = private_key_to_address(random_key_hex, compressed=False)
        total_attempts += 1

        # Just printing progress every million tries so I know it’s working
        if total_attempts % 1_000_000 == 0:
            elapsed = time.time() - start_time
            print(f"Process {process_id}: {total_attempts} keys checked. Speed: {total_attempts / elapsed:.2f} keys/sec")

        # If there's a match (crazy lucky day?), store and return it
        if address_c == target_address or address_u == target_address:
            wif = private_key_to_wif(random_key_hex)
            queue.put((random_key_hex, wif, target_address))
            return

# Spawns multiple processes to speed up the search
def manager(ranges_to_search):
    queue = multiprocessing.Queue()
    processes = []

    # Looping over the range configs I defined below
    for i, (start_hex, end_hex, target_address, name) in enumerate(ranges_to_search):
        start_int, end_int = int(start_hex, 16), int(end_hex, 16)
        p = multiprocessing.Process(target=search_range, args=(start_int, end_int, target_address, queue, i))
        p.start()
        processes.append(p)

    # Blocking call – waits until one of the processes finds something
    found_key = queue.get()

    # Once found, stop everything else – mission accomplished
    for p in processes:
        p.terminate()

    # Saving the winner to a file – just in case I close the terminal
    with open("wallet.txt", "w") as f:
        f.write(f"Private Key: {found_key[0]}\nWIF: {found_key[1]}\nAddress: {found_key[2]}\n")
    print(f"FOUND! Private Key: {found_key[0]}, WIF: {found_key[1]}, Address: {found_key[2]}")

# Define the range and target address (this one's from the famous Bitcoin puzzle challenge)
ranges_to_search = [
    ("100000000000000000", "1fffffffffffffffff", "19vkiEajfhuZ8bs8Zu2jgmC6oqZbWqhxhG", "Puzzle 69")
]

# Typical Python main entry – kick off the search
if __name__ == "__main__":
    manager(ranges_to_search)
