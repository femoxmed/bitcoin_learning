import hashlib
import ecdsa
import secrets

class Keys:
    def __init__(self, private_key=None):
        self.private = private_key or self.generate_private()
        self.wif = self.private_to_wif(self.private)
        self.public = self.private_to_public(self.private)
        self.hash160 = self.public_to_hash160(self.public)
        self.address = self.hash160_to_address(self.hash160)

    def generate_private(self):
        while True:
            # Generate a random 32-byte (256-bit) hexadecimal number
            private_key = secrets.token_hex(32)
            max_val = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
            if int(private_key, 16) <= max_val:
                return private_key

    def private_to_wif(self, private_key, compress=True, mainnet=True):
        flag = '01' if compress else ''
        version = '80' if mainnet else 'EF'

        check = self.checksum(version + private_key + flag)
        wif = self.base58_encode(version + private_key + flag + check)

        return wif

    def private_to_public(self, private_key, compress=True):
        group = ecdsa.SECP256k1
        signing_key = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=group)
        verifying_key = signing_key.get_verifying_key()
        point = verifying_key.pubkey.point

        if compress:
            prefix = '02' if (point.y() % 2 == 0) else '03'
            public_key = prefix + self.byte32(hex(point.x())[2:])
        else:
            prefix = '04'
            public_key = prefix + self.byte32(hex(point.x())[2:]) + self.byte32(hex(point.y())[2:])

        return public_key

    def public_to_hash160(self, public_key):
        binary = bytes.fromhex(public_key)
        sha256_hash = hashlib.sha256(binary).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        return ripemd160_hash.hex()

    def hash160_to_address(self, hash160, address_type='p2pkh'):
        prefixes = {
            'p2pkh': '00',
            'p2sh': '05',
            'p2pkh_testnet': '6F',
            'p2sh_testnet': 'C4'
        }
        prefix = prefixes[address_type]
        checksum = self.checksum(prefix + hash160)
        address = self.base58_encode(prefix + hash160 + checksum)
        return address

    def hash256(self, hex_data):
        binary = bytes.fromhex(hex_data)
        hash1 = hashlib.sha256(binary).digest()
        hash2 = hashlib.sha256(hash1).digest()
        return hash2.hex()

    def checksum(self, hex_data):
        hash_result = self.hash256(hex_data)
        return hash_result[:8]

    def base58_encode(self, hex_data):
        chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        base_count = len(chars)
        value = int(hex_data, 16)
        encode = ''
        while value > 0:
            value, remainder = divmod(value, base_count)
            encode = chars[remainder] + encode
        return encode

    def byte32(self, data, size=32):
        return data.rjust(size*2, '0')

# Example usage
keys = Keys()

print("private:", keys.private)
print("public: ", keys.public)
print("hash160:", keys.hash160)
print("address:", keys.address)
