import os
import struct

def generate_server_hello(client_hello):
    version = b'\x03\x03'  # TLS 1.2
    random_bytes = os.urandom(32)  # 32 bytes of random data
    session_id = b''  # Empty session ID for a new session
    cipher_suite = b'\x00\x2F'  # Example cipher suite (TLS_RSA_WITH_AES_128_CBC_SHA256)
    compression_method = b'\x00'  # No compression

    hello_message = version + random_bytes + session_id + len(cipher_suite).to_bytes(2, 'big') + cipher_suite + len(compression_method).to_bytes(1, 'big') + compression_method
    return hello_message

# Example usage
if __name__ == "__main__":
    client_hello = b''  # Placeholder, would normally come from the actual Client Hello
    server_hello = generate_server_hello(client_hello)
    print("Server Hello Message:", server_hello)
