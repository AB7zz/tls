import hmac
import hashlib

# Function to compute HMAC using SHA-256
def compute_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()

# Example usage
if __name__ == "__main__":
    key = b'secret_key'
    message = b"Hello, TLS!"
    hmac_value = compute_hmac(key, message)
    print("HMAC:", hmac_value.hex())
