import os
import oqs

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# ALGORITHMS
# ============================================================

KEM_ALGORITHM = "ML-KEM-768"
SIG_ALGORITHM = "ML-DSA-65"


# ============================================================
# AES KEY DERIVATION
# ============================================================

def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    ML-KEM shared secret पासून AES-256 key तयार करतो.
    """

    return HKDF(
        algorithm=hashes.SHA3_256(),
        length=32,
        salt=None,
        info=b"QuantumSafe-AES-256-GCM",
    ).derive(shared_secret)


# ============================================================
# SHA3-256 HASH
# ============================================================

def calculate_hash(data: bytes) -> str:
    """
    SHA3-256 hash तयार करतो.
    Tamper Detection साठी वापरला जातो.
    """

    digest = hashes.Hash(hashes.SHA3_256())

    digest.update(data)

    return digest.finalize().hex()


# ============================================================
# ML-KEM-768 + AES-256-GCM ENCRYPTION
# ============================================================

def encrypt_data(data: bytes):
    """
    ML-KEM-768
        ↓
    Shared Secret
        ↓
    HKDF
        ↓
    AES-256-GCM
        ↓
    Encrypted Data
    """

    kem = oqs.KeyEncapsulation(KEM_ALGORITHM)

    # Generate ML-KEM key pair
    public_key = kem.generate_keypair()

    # Encapsulation
    ciphertext_kem, shared_secret = kem.encap_secret(
        public_key
    )

    # Export ML-KEM secret key
    secret_key = kem.export_secret_key()

    # Derive AES-256 key
    aes_key = derive_aes_key(shared_secret)

    # Generate AES-GCM nonce
    nonce = os.urandom(12)

    # AES-256-GCM encryption
    aes = AESGCM(aes_key)

    encrypted_data = aes.encrypt(
        nonce,
        data,
        None
    )

    # SHA3-256 hash of encrypted data
    data_hash = calculate_hash(
        encrypted_data
    )

    return {
        "kem_ciphertext": ciphertext_kem,
        "nonce": nonce,
        "encrypted_data": encrypted_data,
        "secret_key": secret_key,
        "data_hash": data_hash,
    }


# ============================================================
# ML-KEM-768 + AES-256-GCM DECRYPTION
# ============================================================

def decrypt_data(
    kem_ciphertext: bytes,
    nonce: bytes,
    encrypted_data: bytes,
    secret_key: bytes,
):
    """
    ML-KEM secret key वापरून encrypted data decrypt करतो.
    """

    kem = oqs.KeyEncapsulation(
        KEM_ALGORITHM,
        secret_key
    )

    # Decapsulation
    shared_secret = kem.decap_secret(
        kem_ciphertext
    )

    # Derive AES key
    aes_key = derive_aes_key(
        shared_secret
    )

    # AES-256-GCM decryption
    aes = AESGCM(aes_key)

    decrypted_data = aes.decrypt(
        nonce,
        encrypted_data,
        None
    )

    return decrypted_data


# ============================================================
# SHA3-256 INTEGRITY / TAMPER DETECTION
# ============================================================

def verify_hash(
    encrypted_data: bytes,
    expected_hash: str
) -> bool:
    """
    Encrypted data मध्ये tampering झाली आहे का
    ते तपासतो.
    """

    actual_hash = calculate_hash(
        encrypted_data
    )

    return actual_hash == expected_hash


# ============================================================
# ML-DSA-65 DIGITAL SIGNATURE
# ============================================================

def generate_signature_keys():
    """
    ML-DSA-65 public/private key pair तयार करतो.

    Returns:
        public_key
        secret_key
    """

    sig = oqs.Signature(
        SIG_ALGORITHM
    )

    public_key = sig.generate_keypair()

    secret_key = sig.export_secret_key()

    return public_key, secret_key


def sign_data(
    data: bytes,
    secret_key: bytes
):
    """
    ML-DSA-65 वापरून data वर
    digital signature तयार करतो.
    """

    sig = oqs.Signature(
        SIG_ALGORITHM,
        secret_key
    )

    signature = sig.sign(
        data
    )

    return signature


def verify_signature(
    data: bytes,
    signature: bytes,
    public_key: bytes
) -> bool:
    """
    ML-DSA-65 digital signature verify करतो.

    Returns:
        True  = Signature valid
        False = Signature invalid
    """

    sig = oqs.Signature(
        SIG_ALGORITHM
    )

    return sig.verify(
        data,
        signature,
        public_key
    )


# ============================================================
# CRYPTO CORE TEST
# ============================================================

if __name__ == "__main__":

    print("===================================")
    print(" QuantumSafe Crypto Core")
    print("===================================")

    print("ML-KEM Algorithm :", KEM_ALGORITHM)
    print("Signature Algorithm :", SIG_ALGORITHM)
    print("Symmetric Encryption : AES-256-GCM")
    print("Key Derivation : HKDF-SHA3-256")
    print("Integrity : SHA3-256")

    print("-----------------------------------")
    print("Crypto core loaded successfully.")
    print("-----------------------------------")