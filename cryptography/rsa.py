from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA public and private keys
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Encrypt a message using RSA public key
def rsa_encrypt(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Decrypt a message using RSA private key
def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Example usage
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keypair()
    message = b"Hello, TLS!"

    # Encrypt
    ciphertext = rsa_encrypt(public_key, message)
    print("Ciphertext:", ciphertext)

    # Decrypt
    decrypted_message = rsa_decrypt(private_key, ciphertext)
    print("Decrypted message:", decrypted_message.decode())
