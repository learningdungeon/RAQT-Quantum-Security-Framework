# src/crypto/aes.py
"""
AES-256-GCM Authenticated Encryption

Provides symmetric encryption with authentication using AES-256 in GCM mode.
This is the standard for authenticated encryption with associated data (AEAD).
"""

import os
import secrets
from typing import Tuple, Optional
from dataclasses import dataclass

# Try to use cryptography library if available
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    # Fallback to simple XOR for demonstration (NOT SECURE for production)
    import hashlib


@dataclass
class AESKey:
    """AES-256 key."""
    key: bytes
    key_size: int = 256
    
    def __post_init__(self):
        if len(self.key) != 32:
            raise ValueError(f"AES-256 key must be 32 bytes, got {len(self.key)}")
    
    @classmethod
    def generate(cls) -> 'AESKey':
        """Generate a random AES-256 key."""
        return cls(secrets.token_bytes(32))
    
    @classmethod
    def from_bytes(cls, key_bytes: bytes) -> 'AESKey':
        """Create AESKey from bytes."""
        return cls(key_bytes)
    
    def to_bytes(self) -> bytes:
        """Export key as bytes."""
        return self.key


@dataclass
class AESGCMCiphertext:
    """AES-GCM encrypted ciphertext with nonce and tag."""
    ciphertext: bytes
    nonce: bytes
    tag: bytes
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes: nonce (12) + tag (16) + ciphertext."""
        return self.nonce + self.tag + self.ciphertext
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'AESGCMCiphertext':
        """Deserialize from bytes."""
        nonce = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        return cls(ciphertext=ciphertext, nonce=nonce, tag=tag)
    
    def __len__(self) -> int:
        return len(self.ciphertext) + len(self.nonce) + len(self.tag)


class AESGCMEncryption:
    """
    AES-256-GCM authenticated encryption.
    
    Provides:
    - Encryption: ciphertext, tag = encrypt(key, plaintext, aad)
    - Decryption: plaintext = decrypt(key, ciphertext, tag, aad, nonce)
    
    GCM mode provides both confidentiality and integrity.
    """
    
    def __init__(self, key: Optional[AESKey] = None):
        """
        Initialize AES-GCM encryption.
        
        Args:
            key: AESKey instance. If None, a random key is generated.
        """
        self.key = key or AESKey.generate()
        self._nonce_size = 12  # Recommended for GCM (96 bits)
        self._tag_size = 16    # 128-bit authentication tag
    
    @classmethod
    def from_key_bytes(cls, key_bytes: bytes) -> 'AESGCMEncryption':
        """Create AES-GCM instance from 32-byte key."""
        return cls(AESKey.from_bytes(key_bytes))
    
    def encrypt(
        self,
        plaintext: bytes,
        associated_data: Optional[bytes] = None
    ) -> AESGCMCiphertext:
        """
        Encrypt plaintext with AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt.
            associated_data: Additional authenticated data (not encrypted).
        
        Returns:
            AESGCMCiphertext containing nonce, ciphertext, and tag.
        """
        nonce = secrets.token_bytes(self._nonce_size)
        
        if HAS_CRYPTOGRAPHY:
            aesgcm = AESGCM(self.key.to_bytes())
            ciphertext = aesgcm.encrypt(
                nonce,
                plaintext,
                associated_data or b""
            )
            # In cryptography library, tag is appended to ciphertext
            # We need to separate them
            tag = ciphertext[-self._tag_size:]
            ciphertext = ciphertext[:-self._tag_size]
        else:
            # Fallback: XOR-based encryption (NOT SECURE - DEMO ONLY)
            # This is a placeholder. Production must use cryptography library.
            ciphertext, tag = self._encrypt_fallback(plaintext, nonce, associated_data)
        
        return AESGCMCiphertext(
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag
        )
    
    def decrypt(
        self,
        ciphertext_obj: AESGCMCiphertext,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Decrypt ciphertext with AES-256-GCM.
        
        Args:
            ciphertext_obj: AESGCMCiphertext containing nonce, ciphertext, tag.
            associated_data: Same AAD used during encryption.
        
        Returns:
            Decrypted plaintext.
        
        Raises:
            ValueError: If authentication fails (incorrect key or tampered data).
        """
        if HAS_CRYPTOGRAPHY:
            aesgcm = AESGCM(self.key.to_bytes())
            combined = ciphertext_obj.ciphertext + ciphertext_obj.tag
            plaintext = aesgcm.decrypt(
                ciphertext_obj.nonce,
                combined,
                associated_data or b""
            )
            return plaintext
        else:
            # Fallback (DEMO ONLY)
            return self._decrypt_fallback(ciphertext_obj, associated_data)
    
    def _encrypt_fallback(
        self,
        plaintext: bytes,
        nonce: bytes,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bytes]:
        """
        Fallback encryption (DEMO ONLY - NOT SECURE).
        Uses XOR with key-derived stream. For demonstration purposes only.
        """
        # This is NOT secure. Use cryptography library in production.
        key_material = self.key.to_bytes()
        
        # Derive encryption key using HKDF-like construction
        import hmac
        encryption_key = hmac.new(key_material, nonce, hashlib.sha3_256).digest()
        
        # Expand to plaintext length
        while len(encryption_key) < len(plaintext):
            encryption_key += hmac.new(encryption_key, b"expand", hashlib.sha3_256).digest()
        encryption_key = encryption_key[:len(plaintext)]
        
        # XOR encryption
        ciphertext = bytes([p ^ e for p, e in zip(plaintext, encryption_key)])
        
        # Simple tag (HMAC of ciphertext + associated_data)
        tag_data = ciphertext + (associated_data or b"")
        tag = hmac.new(key_material, tag_data, hashlib.sha3_256).digest()[:self._tag_size]
        
        return ciphertext, tag
    
    def _decrypt_fallback(
        self,
        ciphertext_obj: AESGCMCiphertext,
        associated_data: Optional[bytes] = None
    ) -> bytes:
        """
        Fallback decryption (DEMO ONLY - NOT SECURE).
        """
        import hmac
        key_material = self.key.to_bytes()
        
        # Verify tag
        tag_data = ciphertext_obj.ciphertext + (associated_data or b"")
        expected_tag = hmac.new(key_material, tag_data, hashlib.sha3_256).digest()[:self._tag_size]
        
        if not hmac.compare_digest(expected_tag, ciphertext_obj.tag):
            raise ValueError("Authentication failed: Invalid tag")
        
        # Derive encryption key
        encryption_key = hmac.new(key_material, ciphertext_obj.nonce, hashlib.sha3_256).digest()
        while len(encryption_key) < len(ciphertext_obj.ciphertext):
            encryption_key += hmac.new(encryption_key, b"expand", hashlib.sha3_256).digest()
        encryption_key = encryption_key[:len(ciphertext_obj.ciphertext)]
        
        # XOR decryption
        plaintext = bytes([c ^ e for c, e in zip(ciphertext_obj.ciphertext, encryption_key)])
        
        return plaintext
    
    def encrypt_to_bytes(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt and return serialized ciphertext (nonce + tag + ciphertext)."""
        ct = self.encrypt(plaintext, associated_data)
        return ct.to_bytes()
    
    def decrypt_from_bytes(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt from serialized ciphertext."""
        ct = AESGCMCiphertext.from_bytes(data)
        return self.decrypt(ct, associated_data)
    
    @property
    def key_bytes(self) -> bytes:
        """Get key as bytes."""
        return self.key.to_bytes()
    
    def __repr__(self) -> str:
        return f"AESGCMEncryption(key={'*' * 8})"


class AESGCMError(Exception):
    """Base exception for AES-GCM errors."""
    pass


class AuthenticationError(AESGCMError):
    """Raised when tag verification fails."""
    pass