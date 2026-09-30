"""
tunneltwin.seal.signer -- Ed25519 Digital Signing and Verification.

Manages cryptographic keypairs and signs/verifies Merkle tree roots for tamper-evident attestation.
"""

from __future__ import annotations

import logging
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

log = logging.getLogger(__name__)

DEFAULT_KEY_DIR = Path(".keys")
PRIVATE_KEY_FILENAME = "ed25519_operator.key"
PUBLIC_KEY_FILENAME = "ed25519_operator.pub"


def get_or_create_keypair(key_dir: Path | None = None) -> tuple[ed25519.Ed25519PrivateKey, str]:
    """
    Load existing operator Ed25519 keypair or generate a new one.

    Returns:
        tuple[Ed25519PrivateKey, str]: (private_key_object, hex_encoded_public_key)
    """
    target_dir = key_dir or DEFAULT_KEY_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    priv_path = target_dir / PRIVATE_KEY_FILENAME
    pub_path = target_dir / PUBLIC_KEY_FILENAME

    if priv_path.exists() and pub_path.exists():
        raw_priv = priv_path.read_bytes()
        try:
            # Check if PEM or raw 32-byte seed
            if b"BEGIN PRIVATE KEY" in raw_priv:
                priv_key = serialization.load_pem_private_key(raw_priv, password=None)
                if isinstance(priv_key, ed25519.Ed25519PrivateKey):
                    pub_hex = pub_path.read_text(encoding="utf-8").strip()
                    return priv_key, pub_hex
            elif len(raw_priv) == 32:
                priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_priv)
                pub_hex = pub_path.read_text(encoding="utf-8").strip()
                return priv_key, pub_hex
        except Exception as e:
            log.warning("Failed to load existing key (%s), generating new one.", e)

    # Generate new keypair
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()

    raw_pub_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    pub_hex = raw_pub_bytes.hex()

    # Save private key in raw 32-byte binary
    raw_priv_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv_path.write_bytes(raw_priv_bytes)
    pub_path.write_text(pub_hex, encoding="utf-8")

    return priv_key, pub_hex


def sign_merkle_root(priv_key: ed25519.Ed25519PrivateKey, merkle_root: str) -> str:
    """Sign the Merkle root string using the operator Ed25519 private key."""
    signature_bytes = priv_key.sign(merkle_root.encode("utf-8"))
    return signature_bytes.hex()


def verify_signature(public_key_hex: str, merkle_root: str, signature_hex: str) -> bool:
    """Verify an Ed25519 signature over a Merkle root string."""
    try:
        pub_bytes = bytes.fromhex(public_key_hex.strip())
        sig_bytes = bytes.fromhex(signature_hex.strip())
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
        pub_key.verify(sig_bytes, merkle_root.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError, Exception):
        return False
