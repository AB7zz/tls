from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    return parameters

def generate_dh_keypair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(peer_public_key)
    return shared_secret

# Example usage
if __name__ == "__main__":
    parameters = generate_dh_parameters()
    private_key_1, public_key_1 = generate_dh_keypair(parameters)
    private_key_2, public_key_2 = generate_dh_keypair(parameters)

    shared_secret_1 = compute_shared_secret(private_key_1, public_key_2)
    shared_secret_2 = compute_shared_secret(private_key_2, public_key_1)

    assert shared_secret_1 == shared_secret_2
    print("Shared Secret:", shared_secret_1.hex())
