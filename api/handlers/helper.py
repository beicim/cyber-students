import base64
import json
import os
import hashlib
import hmac
from typing import Tuple, Any
# Import keyring for secure storage and retrieval of the AES master key.
import keyring
# Import AESGCM for authenticated encryption with associated data.
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# Import hashes and PBKDF2HMAC for secure secret hashing.
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Define the keyring service and username names used for the AES master key.
KEYRING_SERVICE = 'student_registration'
KEYRING_USERNAME = 'aes_master_key'
# Define the number of iterations for PBKDF2 hashing.
HASH_ITERATIONS = 100_000
# Define the size of the AES master key in bytes (32 bytes = AES-256).
AES_KEY_SIZE = 32
# Define the size of the salt used for PBKDF2 hashing.
SALT_SIZE = 16
# Define the size of the AES-GCM nonce (12 bytes = 96 bits).
NONCE_SIZE = 12

# Retrieve or create the AES master key stored in the system keyring.
def get_master_key() -> bytes:
    # Attempt to read the base64-encoded master key from keyring.
    encoded_key = keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME)
    # If the key already exists, decode and return it.
    if encoded_key is not None:
        try:
            return base64.b64decode(encoded_key)
        except Exception:
            # If decoding fails, ignore the invalid value and create a new key.
            pass

    # Generate a new 32-byte AES-256 key when no valid key exists.
    master_key = os.urandom(AES_KEY_SIZE)
    # Encode the new key as base64 so it can be stored as a text password.
    encoded_key = base64.b64encode(master_key).decode('utf-8')
    # Store the encoded key in keyring for future retrieval.
    keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, encoded_key)
    # Return the raw AES key bytes.
    return master_key

# Derive a deterministic identifier for an email address using the AES master key.
# This identifier allows exact email lookup without storing the email address in plaintext.
def derive_email_id(email: str, master_key: bytes) -> str:
    if not isinstance(email, str):
        raise TypeError('Email must be a string')
    normalized = email.lower().strip().encode('utf-8')
    return hmac.new(master_key, normalized, hashlib.sha256).hexdigest()

# Derive a hash and salt from a secret string using PBKDF2 with SHA-256.
def hash_secret(secret: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    # Convert the secret to bytes for PBKDF2 input.
    secret_bytes = secret.encode('utf-8')
    # Create a new random salt when one is not provided.
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    # Build the PBKDF2HMAC object with SHA-256 and the configured iteration count.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=HASH_ITERATIONS,
    )
    # Derive the secret hash from the password and salt.
    secret_hash = kdf.derive(secret_bytes)
    # Return the derived hash and the salt used.
    return secret_hash, salt

# Verify a secret string against a stored hash and salt.
def verify_secret(secret: str, stored_hash: bytes, salt: bytes) -> bool:
    # Convert the secret to bytes for PBKDF2 input.
    secret_bytes = secret.encode('utf-8')
    # Build a PBKDF2 object with the same parameters used for hashing.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=HASH_ITERATIONS,
    )
    try:
        # Attempt to verify the secret against the stored hash.
        kdf.verify(secret_bytes, stored_hash)
        return True
    except Exception:
        # Verification failure or any exception means the secret is invalid.
        return False

# Encrypt a plaintext string using AES-GCM and return ciphertext and nonce bytes.
def encrypt_field(plaintext: Any, key: bytes) -> Tuple[bytes, bytes]:
    # If the plaintext is None, there is nothing to encrypt.
    if plaintext is None:
        return None, None
    # Serialize list or dict fields to JSON text before encryption.
    if isinstance(plaintext, (list, dict)):
        plaintext = json.dumps(plaintext)
    # Convert the plaintext string to bytes.
    plaintext_bytes = str(plaintext).encode('utf-8')
    # Create a new random nonce for AES-GCM.
    nonce = os.urandom(NONCE_SIZE)
    # Initialize AES-GCM with the provided key.
    aesgcm = AESGCM(key)
    # Encrypt the plaintext without associated data.
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    # Return the ciphertext and nonce so both can be stored.
    return ciphertext, nonce

# Decrypt a ciphertext using AES-GCM and return the original plaintext string.
def decrypt_field(ciphertext: bytes, nonce: bytes, key: bytes) -> str:
    # If ciphertext or nonce is missing, there is nothing to decrypt.
    if ciphertext is None or nonce is None:
        return None
    # Initialize AES-GCM with the provided key.
    aesgcm = AESGCM(key)
    # Perform authenticated decryption.
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    # Convert decrypted bytes back to a UTF-8 string.
    return plaintext_bytes.decode('utf-8')
