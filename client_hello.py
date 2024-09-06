import os
import struct
import hashlib

def generate_client_hello():
    version = b'\x03\x03'  # TLS 1.2
    random_bytes = os.urandom(32)  # 32 bytes of random data
    session_id = b''  # Empty session ID for a new session
    cipher_suites = b'\x00\x2F\x00\x35'  # Example cipher suites (TLS_RSA_WITH_AES_128_CBC_SHA256 and TLS_RSA_WITH_AES_256_CBC_SHA256)
    compression_methods = b'\x00'  # No compression

    hello_message = version + random_bytes + session_id + len(cipher_suites).to_bytes(2, 'big') + cipher_suites + len(compression_methods).to_bytes(1, 'big') + compression_methods
    return hello_message

# Example usage
if __name__ == "__main__":
    hello_message = generate_client_hello()
    print("Client Hello Message:", hello_message)
