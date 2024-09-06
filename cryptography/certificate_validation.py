from cryptography import x509
from cryptography.hazmat.backends import default_backend

def verify_certificate(cert_pem, ca_cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())

    # Here you'd normally use a certificate authority (CA) to verify the certificate.
    # For simplicity, this example just checks if the CA cert is the same as the certificate itself.
    if cert.issuer == ca_cert.subject:
        return True
    return False

# Example usage
if __name__ == "__main__":
    with open("server_cert.pem", "rb") as f:
        server_cert = f.read()
    with open("server_cert.pem", "rb") as f:
        ca_cert = f.read()

    is_valid = verify_certificate(server_cert, ca_cert)
    print("Certificate valid:", is_valid)
