import socket
import time
import os
import json
from cryptography_functions.rsa import rsa_encrypt
from cryptography_functions.dh_key_exchange import generate_dh_parameters, generate_dh_keypair, compute_shared_secret
from cryptography_functions.sha256 import sha256_hash
from cryptography_functions.certificate_verification import verify_certificate
from cryptography.hazmat.primitives import serialization
from colorama import Fore, Style, init

# Initialize colorama
init()

HOST = 'localhost'
PORT = 5000

def client_handshake(sock):
    # 1. Send ClientHello
    client_hello = {
        "version": "TLS 1.2",
        "random": os.urandom(32).hex(),
        "cipher_suites": ["TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384"],
        "compression_methods": ["null"]
    }
    client_hello_message = json.dumps(client_hello)
    print(f"{Fore.BLUE}Client: Sending ClientHello message: {client_hello}{Style.RESET_ALL}")
    sock.send(client_hello_message.encode())
    print(f"{Fore.GREEN}Client sent ClientHello{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 2. Receive ServerHello
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Client: Waiting to receive ServerHello message from server...{Style.RESET_ALL}")
    server_hello = sock.recv(1024).decode()
    print(f"{Fore.GREEN}Client received ServerHello: {server_hello}{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 3. Receive Server Certificate
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Client: Waiting to receive Server's certificate...{Style.RESET_ALL}")
    server_cert = sock.recv(2048)
    print(f"{Fore.GREEN}Client received Server's Certificate{Style.RESET_ALL}\n")
    print(f"{Fore.BLUE}Client: Validating the server's certificate{Style.RESET_ALL}")
    with open("cryptography_functions/server_cert.pem", "rb") as f:
        ca_cert = f.read()
    is_valid = verify_certificate(server_cert, ca_cert)
    if is_valid:
        print(f"{Fore.GREEN}Client: Certificate validated successfully{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}Client: Certificate validation failed{Style.RESET_ALL}")
        return
    # time.sleep(5)

    # 4. Receive ServerHelloDone
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Client: Waiting to receive ServerHelloDone message...{Style.RESET_ALL}")
    server_hello_done = sock.recv(1024).decode()
    print(f"{Fore.GREEN}Client received ServerHelloDone: {server_hello_done}{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 5. Generate DH parameters and keypair
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Client: Generating DH parameters and keypair...{Style.RESET_ALL}")
    dh_params = generate_dh_parameters()
    client_private_key, client_public_key = generate_dh_keypair(dh_params)
    print(f"{Fore.GREEN}Client generated DH parameters and keypair{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 6. Send DH parameters to server
    dh_params_bytes = dh_params.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    print(f"{Fore.BLUE}Client: Sending DH parameters to server...{Style.RESET_ALL}")
    sock.send(dh_params_bytes)
    print(f"{Fore.GREEN}Client sent DH parameters{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 7. Send Client's DH Public Key
    print("\n" + "="*50 + "\n")
    client_public_key_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"{Fore.BLUE}Client: Sending DH public key to server...{Style.RESET_ALL}")
    sock.send(client_public_key_bytes)
    print(f"{Fore.GREEN}Client sent DH public key{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 8. Receive Server's DH Public Key
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Client: Waiting to receive Server's DH public key...{Style.RESET_ALL}")
    server_public_key_bytes = sock.recv(2048)
    server_public_key = serialization.load_pem_public_key(server_public_key_bytes)
    print(f"{Fore.GREEN}Client received Server's DH public key{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 9. Compute shared secret
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Client: Computing shared secret...{Style.RESET_ALL}")
    client_shared_secret = compute_shared_secret(client_private_key, server_public_key) # will be used to pass data to and from server in encrypted format
    print(f"{Fore.GREEN}Client derived Shared Secret{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 10. Send Finished Message
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Client: Creating Finished message using SHA-256 hash...{Style.RESET_ALL}")
    client_finished_message = sha256_hash(
        client_hello.encode() +
        server_hello.encode() +
        server_cert +
        server_hello_done.encode()
    )
    print(f"{Fore.BLUE}Client: Sending Finished message: {client_finished_message}{Style.RESET_ALL}")
    sock.send(client_finished_message.encode())
    print(f"{Fore.GREEN}Client sent Finished message{Style.RESET_ALL}\n")
    # time.sleep(5)

    # 11. Receive Server Finished Message
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Client: Waiting to receive Server Finished message...{Style.RESET_ALL}")
    server_finished_message = sock.recv(1024).decode()
    expected_hash = sha256_hash(
        client_hello.encode() +
        server_hello.encode() +
        server_cert +
        server_hello_done.encode()
    )
    print(f"{Fore.GREEN}Client: Calculated expected hash: {expected_hash}{Style.RESET_ALL}")
    assert server_finished_message == expected_hash, "Finished message does not match"
    print(f"{Fore.GREEN}Client verified Server's Finished message{Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}TLS Handshake Completed Successfully on Client Side{Style.RESET_ALL}\n")

def start_client():
    print(f"{Fore.YELLOW}Client: Connecting to {HOST}:{PORT}{Style.RESET_ALL}\n")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        client_handshake(sock)

if __name__ == "__main__":
    start_client()
