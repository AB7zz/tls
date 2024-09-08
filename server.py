import socket
import time 
import os
from cryptography_functions.certificate_generation import generate_self_signed_cert
from cryptography_functions.dh_key_exchange import compute_shared_secret, generate_dh_keypair
from cryptography_functions.sha256 import sha256_hash
from cryptography.hazmat.primitives import serialization
from colorama import Fore, Style  
import json

HOST = 'localhost'
PORT = 5000

def server_handshake(conn):
    # Step 1: Receive ClientHello
    print(f"{Fore.BLUE}Server: Waiting to receive ClientHello message from client...{Style.RESET_ALL}")
    client_hello_message = conn.recv(1024).decode()
    client_hello = json.loads(client_hello_message)
    print(f"{Fore.GREEN}Server received ClientHello: {client_hello}{Style.RESET_ALL}")
    # time.sleep(5) 

    # Step 2: Send ServerHello
    print("\n" + "="*50 + "\n")  
    server_hello = {
        "version": client_hello["version"],  # Use client's TLS version
        "random": os.urandom(32).hex(),  # Server's random nonce
        "cipher_suite": client_hello["cipher_suites"][0],  # Select the first supported cipher suite
        "compression_method": client_hello["compression_methods"][0]  # Select the first compression method
    }
    server_hello_message = json.dumps(server_hello)
    print(f"{Fore.BLUE}Server: Sending ServerHello message with random value {Style.RESET_ALL}")
    conn.send(server_hello_message.encode())
    print(f"{Fore.GREEN}Server sent ServerHello{Style.RESET_ALL}")
    # time.sleep(5)

    # Step 3: Send Certificate
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Server: Generating self-signed certificate...{Style.RESET_ALL}")
    server_cert = generate_self_signed_cert()
    print(f"{Fore.BLUE}Server: Sending self-signed certificate...{Style.RESET_ALL}")
    conn.send(server_cert)
    print(f"{Fore.GREEN}Server sent Certificate{Style.RESET_ALL}")
    # time.sleep(5)

    # Step 4: Send ServerHelloDone
    print("\n" + "="*50 + "\n")
    server_hello_done = "ServerHelloDone"
    print(f"{Fore.BLUE}Server: Sending ServerHelloDone message...{Style.RESET_ALL}")
    conn.send(server_hello_done.encode())
    print(f"{Fore.GREEN}Server sent ServerHelloDone{Style.RESET_ALL}")
    # time.sleep(5)

    # Step 5: Receive Client's DH Parameters
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Server: Waiting to receive Client's DH parameters...{Style.RESET_ALL}")
    dh_params_bytes = conn.recv(2048)
    dh_params = serialization.load_pem_parameters(dh_params_bytes)
    print(f"{Fore.GREEN}Server received DH parameters from client{Style.RESET_ALL}")
    # time.sleep(5)

    # Step 6: Generate DH keypair
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Server: Generating DH keypair...{Style.RESET_ALL}")
    server_private_key, server_public_key = generate_dh_keypair(dh_params)
    # time.sleep(5)

    # Step 7: Send Server's DH Public Key
    print("\n" + "="*50 + "\n")
    server_public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print(f"{Fore.BLUE}Server: Sending DH public key to client...{Style.RESET_ALL}")
    conn.send(server_public_key_bytes)
    print(f"{Fore.GREEN}Server sent DH public key{Style.RESET_ALL}")
    # time.sleep(5)

    # Step 8: Receive Client's DH Public Key
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Server: Waiting to receive Client's DH public key...{Style.RESET_ALL}")
    client_public_key_bytes = conn.recv(2048)
    client_public_key = serialization.load_pem_public_key(client_public_key_bytes)
    print(f"{Fore.GREEN}Server received Client's DH public key{Style.RESET_ALL}")
    # time.sleep(5)

    # Step 9: Compute shared secret
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Server: Computing shared secret...{Style.RESET_ALL}")
    server_shared_secret = compute_shared_secret(server_private_key, client_public_key) # will be used to pass data to and from client in encrypted format
    print(f"{Fore.GREEN}Server derived Shared Secret{Style.RESET_ALL}")
    # time.sleep(5)

    # Step 10: Verify Finished Message
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Server: Waiting to receive Client Finished message...{Style.RESET_ALL}")
    client_finished_message = conn.recv(1024).decode()
    expected_hash = sha256_hash(
        server_hello_message.encode() +
        server_cert +
        server_hello_done.encode()
    )
    print(f"{Fore.GREEN}Server: Calculated expected hash: {expected_hash}{Style.RESET_ALL}")
    assert client_finished_message == expected_hash, "Finished message does not match"
    print(f"{Fore.GREEN}Server verified Finished message{Style.RESET_ALL}")
    # time.sleep(5)

    # Step 11: Send Server Finished Message
    print("\n" + "="*50 + "\n")
    print(f"{Fore.BLUE}Server: Creating Finished message using SHA-256 hash...{Style.RESET_ALL}")
    server_finished_message = sha256_hash(
        server_hello_message.encode() +
        server_cert +
        server_hello_done.encode()
    )
    print(f"{Fore.BLUE}Server: Sending Finished message: {server_finished_message}{Style.RESET_ALL}")
    conn.send(server_finished_message.encode())
    print(f"{Fore.GREEN}Server sent Finished message{Style.RESET_ALL}")
    # time.sleep(5)

    print(f"\n{Fore.CYAN}TLS Handshake Completed Successfully on Server Side{Style.RESET_ALL}\n")

def start_server():
    print(f"{Fore.BLUE}Server: Creating socket and binding to {HOST}:{PORT}{Style.RESET_ALL}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind((HOST, PORT))
        server_sock.listen(1)
        print(f"{Fore.GREEN}Server listening on {HOST}:{PORT}{Style.RESET_ALL}")
        
        conn, addr = server_sock.accept()
        with conn:
            print(f"{Fore.BLUE}Connected by {addr}{Style.RESET_ALL}")
            server_handshake(conn)

if __name__ == "__main__":
    start_server()
