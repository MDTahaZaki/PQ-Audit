import logging
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Configure logging for enterprise environment
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("LegacyAuthBackend")


class EnterpriseAuthModule:
    """
    Legacy backend authentication module for enterprise infrastructure.
    Uses classical public-key cryptography algorithms.
    """
    def __init__(self):
        logger.info("Initializing EnterpriseAuthModule...")
        self.backend = default_backend()
        self._initialize_rsa()
        self._initialize_ecdh()
        self._initialize_ecdsa()

    def _initialize_rsa(self):
        """Generate a standard RSA-2048 key pair."""
        logger.info("Generating RSA-2048 key pair for general encryption...")
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

    def _initialize_ecdh(self):
        """Initialize ECDH key exchange using SECP256R1 (P-256)."""
        logger.info("Generating SECP256R1 key pair for ECDH key exchange...")
        self.ecdh_private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=self.backend
        )
        self.ecdh_public_key = self.ecdh_private_key.public_key()

    def _initialize_ecdsa(self):
        """Initialize ECDSA for digital signatures using SECP256R1."""
        logger.info("Generating SECP256R1 key pair for ECDSA signatures...")
        self.ecdsa_private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=self.backend
        )
        self.ecdsa_public_key = self.ecdsa_private_key.public_key()

    def encrypt_payload_rsa(self, payload: bytes) -> bytes:
        """Encrypts a payload using the RSA public key with OAEP padding."""
        logger.info("Encrypting payload via RSA-2048...")
        ciphertext = self.rsa_public_key.encrypt(
            payload,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def perform_ecdh_exchange(self, peer_public_key) -> bytes:
        """Performs ECDH key exchange with a peer's public key."""
        logger.info("Performing ECDH key exchange...")
        shared_key = self.ecdh_private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive a symmetric key from the shared secret
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake_data',
            backend=self.backend
        ).derive(shared_key)
        
        return derived_key

    def sign_token_ecdsa(self, token: bytes) -> bytes:
        """Signs an authentication token using ECDSA and SHA-256."""
        logger.info("Signing token via ECDSA...")
        signature = self.ecdsa_private_key.sign(
            token,
            ec.ECDSA(hashes.SHA256())
        )
        return signature


if __name__ == "__main__":
    logger.info("Starting legacy auth backend simulation.")
    auth_module = EnterpriseAuthModule()
    
    # 1. RSA Encryption Test
    dummy_payload = b"SECRET_ENTERPRISE_DATA"
    encrypted_data = auth_module.encrypt_payload_rsa(dummy_payload)
    logger.info(f"Successfully encrypted {len(dummy_payload)} bytes. Ciphertext size: {len(encrypted_data)} bytes.")
    
    # 2. ECDSA Signature Test
    auth_token = b"user_auth_token_xyz_123"
    signature = auth_module.sign_token_ecdsa(auth_token)
    logger.info(f"Successfully signed token. Signature size: {len(signature)} bytes.")
    
    # 3. ECDH Key Exchange Test (Simulating peer)
    peer_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    peer_public_key = peer_private_key.public_key()
    derived_symmetric_key = auth_module.perform_ecdh_exchange(peer_public_key)
    logger.info(f"Successfully derived {len(derived_symmetric_key)} byte symmetric key via ECDH.")
    
    logger.info("Legacy auth backend simulation completed.")
