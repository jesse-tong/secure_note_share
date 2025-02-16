from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64, keyring

# Name of the service to store the private key in the keyring (which will manage the private key securely)
keyring_service = 'key_exchange'

# Since SECP256R1 has been defined in the standard with fixed shared values, we can use it directly without having to store it in the database
# Generate an ephemeral private key for each participant
def generate_ephemeral_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key

# Serialize a public key for sharing
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Deserialize a public key received from others
def deserialize_public_key(pem_data):
    return serialization.load_pem_public_key(pem_data)

# Compute the shared secret
def compute_shared_secret(private_key, peer_public_key):
    return private_key.exchange(ec.ECDH(), peer_public_key)

# Derive a shared encryption key from the shared secret
def derive_key(shared_secret, salt=b"shared_salt", info=b'key_exchange'):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info
    ).derive(shared_secret)

def init_or_load_ephemeral_key(username: str, force_update=False):
    # Load the ephemeral key from the private key file if it exists, else generate a new one and save it
    def update_ephemeral_key(private_key):
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        keyring.set_password(keyring_service, username, private_key_pem.decode())
        return private_key
    
    if force_update:
        return update_ephemeral_key(generate_ephemeral_key())
    
    try:
        private_key_pem = keyring.get_password(keyring_service, username)
        if private_key_pem is None:
            raise FileNotFoundError
        private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        return private_key
    except FileNotFoundError:
        return update_ephemeral_key(generate_ephemeral_key())

