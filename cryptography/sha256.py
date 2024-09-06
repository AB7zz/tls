import hashlib

# Function to compute SHA-256 hash
def sha256_hash(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.digest()

# Example usage
if __name__ == "__main__":
    data = b"Hello, TLS!"
    hash_value = sha256_hash(data)
    print("SHA-256 Hash:", hash_value.hex())
