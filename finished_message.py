import hashlib
import hmac

def create_finished_message(session_key, handshake_messages):
    # Hash all handshake messages
    handshake_hash = hashlib.sha256(handshake_messages).digest()
    # Create a HMAC with the session key and handshake hash
    hmac_value = hmac.new(session_key, handshake_hash, hashlib.sha256).digest()
    return hmac_value

# Example usage
if __name__ == "__main__":
    session_key = b'session_key_32_bytes_long__'
    handshake_messages = b'ClientHelloServerHello'

    finished_message = create_finished_message(session_key, handshake_messages)
    print("Finished Message:", finished_message.hex())
