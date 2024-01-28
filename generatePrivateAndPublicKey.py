import ecdsa
import hashlib

def generate_key_pair():
    # Generate a private key
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)

    # Get the corresponding public key
    public_key = private_key.get_verifying_key()

    # Convert keys to hexadecimal format
    private_key_hex = private_key.to_string().hex()
    public_key_hex = public_key.to_string().hex()

    return private_key_hex, public_key_hex

def generate_address(public_key_hex, network_type="mainnet"):
    # Hash the public key using SHA-256
    sha256_hash = hashlib.sha256(bytes.fromhex(public_key_hex)).digest()

    # Hash the result using RIPEMD-160
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

    # Determine the network byte based on the network type
    if network_type == "mainnet":
        network_byte = b'\x00'
    elif network_type == "testnet":
        network_byte = b'\x6f'  # Adjust this for the testnet network byte

    # Add network byte
    extended_hash = network_byte + ripemd160_hash

    # Calculate checksum using SHA-256 twice
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]

    # Concatenate the extended hash and checksum
    address_bytes = extended_hash + checksum

    # Encode the result in base58
    address = base58_encode(address_bytes)

    return address

def base58_encode(b):
    # Base58 encoding
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base_count = len(alphabet)

    encode = ''
    value = int.from_bytes(b, byteorder='big')

    while value > 0:
        value, remainder = divmod(value, base_count)
        encode = alphabet[remainder] + encode

    return encode

if __name__ == "__main__":
    private_key, public_key = generate_key_pair()

    print("Private Key:", private_key)
    print("Public Key:", public_key)

    # Specify the network type: "mainnet" or "testnet"
    network_type = "mainnet"
    address = generate_address(public_key, network_type)
    print(f"Address for {network_type}: {address}")
