from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# Generate DH parameters and keys
def generate_dh_keypair():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Generate ECDH key pair
def generate_ecdh_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Compute shared secret using DH
def compute_dh_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

# Example usage
if __name__ == "__main__":
    # DH key exchange
    private_key_1, public_key_1 = generate_dh_keypair()
    private_key_2, public_key_2 = generate_dh_keypair()

    shared_secret_1 = compute_dh_shared_secret(private_key_1, public_key_2)
    shared_secret_2 = compute_dh_shared_secret(private_key_2, public_key_1)
    assert shared_secret_1 == shared_secret_2

    print("DH Shared Secret:", shared_secret_1.hex())
