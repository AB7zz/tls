from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Function to encrypt data using AES-128 in CBC mode
def aes_encrypt_cbc(plaintext, key):
    # Generate a random 16-byte IV (Initialization Vector)
    iv = os.urandom(16)

    # Create a Cipher object with AES algorithm, CBC mode, and the provided key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Initialize the encryption operation
    encryptor = cipher.encryptor()

    # Pad the plaintext to be a multiple of the block size (16 bytes for AES)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Return the IV and ciphertext (IV is needed for decryption)
    return iv, ciphertext

# Function to decrypt data using AES-128 in CBC mode
def aes_decrypt_cbc(iv, ciphertext, key):
    # Create a Cipher object with AES algorithm, CBC mode, and the provided key and IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Initialize the decryption operation
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding from the plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

# Example usage
if __name__ == "__main__":
    key = os.urandom(16)  # 16 bytes = 128 bits key
    plaintext = b"Hello, TLS!"

    # Encrypt
    iv, ciphertext = aes_encrypt_cbc(plaintext, key)
    print("Ciphertext:", ciphertext)

    # Decrypt
    decrypted_text = aes_decrypt_cbc(iv, ciphertext, key)
    print("Decrypted text:", decrypted_text.decode())
