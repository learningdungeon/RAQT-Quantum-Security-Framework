# src/crypto/kdf.py
"""
HKDF Key Derivation Function (RFC 5869)

HMAC-based Key Derivation Function for deriving cryptographic keys
from high-entropy sources (PUF seeds, DH shared secrets, etc.)
"""

import hashlib
import hmac
from typing import Optional
from dataclasses import dataclass


@dataclass
class KDFParameters:
    """HKDF parameters."""
    hash_algorithm: str
    hash_len: int
    salt: bytes
    info: bytes


class HKDF:
    """
    HMAC-based Key Derivation Function (HKDF) as defined in RFC 5869.
    
    HKDF follows the extract-then-expand paradigm:
    1. Extract: PRK = HMAC-Hash(salt, IKM)
    2. Expand: OKM = HKDF-Expand(PRK, info, L)
    
    This is NIST-compliant and suitable for deriving keys from PUF seeds.
    """
    
    def __init__(
        self,
        hash_algorithm: str = 'sha3_256',
        default_salt: Optional[bytes] = None,
        default_info: Optional[bytes] = None
    ):
        """
        Initialize HKDF.
        
        Args:
            hash_algorithm: Hash function ('sha256', 'sha3_256', 'sha512')
            default_salt: Default salt (if None, uses zeros)
            default_info: Default context info (if None, uses b"")
        """
        self.hash_algorithm = hash_algorithm
        self.default_salt = default_salt or b'\x00' * self._get_hash_len()
        self.default_info = default_info or b""
        self._hash_func = self._get_hash_function()
        self._hash_len = self._get_hash_len()
    
    def _get_hash_function(self):
        """Get hash function object."""
        if self.hash_algorithm == 'sha256':
            return hashlib.sha256
        elif self.hash_algorithm == 'sha3_256':
            return hashlib.sha3_256
        elif self.hash_algorithm == 'sha512':
            return hashlib.sha512
        else:
            raise ValueError(f"Unsupported hash: {self.hash_algorithm}")
    
    def _get_hash_len(self) -> int:
        """Get hash output length in bytes."""
        if self.hash_algorithm in ('sha256', 'sha3_256'):
            return 32
        elif self.hash_algorithm == 'sha512':
            return 64
        else:
            return 32
    
    def extract(self, ikm: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        HKDF-Extract: produce a pseudorandom key (PRK) from input keying material.
        
        Args:
            ikm: Input keying material (high-entropy source, e.g., PUF seed)
            salt: Optional salt (if None, uses default_salt)
        
        Returns:
            Pseudorandom key (PRK) of length hash_len.
        """
        if salt is None:
            salt = self.default_salt
        
        return hmac.new(salt, ikm, self._hash_func).digest()
    
    def expand(self, prk: bytes, info: Optional[bytes] = None, length: int = 32) -> bytes:
        """
        HKDF-Expand: produce output keying material (OKM) from a PRK.
        
        Args:
            prk: Pseudorandom key (from extract step)
            info: Optional context-specific information
            length: Desired output length in bytes
        
        Returns:
            Output keying material (OKM) of specified length.
        """
        if info is None:
            info = self.default_info
        
        n = (length + self._hash_len - 1) // self._hash_len
        okm = b""
        previous = b""
        
        for i in range(1, n + 1):
            previous = hmac.new(
                prk,
                previous + info + bytes([i]),
                self._hash_func
            ).digest()
            okm += previous
        
        return okm[:length]
    
    def derive(
        self,
        ikm: bytes,
        salt: Optional[bytes] = None,
        info: Optional[bytes] = None,
        length: int = 32
    ) -> bytes:
        """
        Full HKDF: extract then expand.
        
        Args:
            ikm: Input keying material
            salt: Optional salt
            info: Optional context information
            length: Desired output length
        
        Returns:
            Output keying material (OKM) of specified length.
        """
        prk = self.extract(ikm, salt)
        return self.expand(prk, info, length)
    
    def derive_multiple(
        self,
        ikm: bytes,
        contexts: dict,
        salt: Optional[bytes] = None,
        length: int = 32
    ) -> dict:
        """
        Derive multiple keys for different contexts (domain separation).
        
        Args:
            ikm: Input keying material
            contexts: Dict mapping names to info bytes
            salt: Optional salt
            length: Desired output length per key
        
        Returns:
            Dict mapping names to derived keys.
        """
        prk = self.extract(ikm, salt)
        results = {}
        for name, info in contexts.items():
            results[name] = self.expand(prk, info, length)
        return results
    
    def derive_pqc_seeds(
        self,
        puf_seed: bytes,
        node_id: str,
        salt: Optional[bytes] = None
    ) -> dict:
        """
        Derive PQC algorithm seeds from a PUF seed (domain separated).
        
        Args:
            puf_seed: Stable seed from PUF + fuzzy extractor
            node_id: Unique node identifier
            salt: Optional salt
        
        Returns:
            Dictionary with seeds for Dilithium, ML-KEM, AES, etc.
        """
        contexts = {
            'dilithium': f"Dilithium3-{node_id}".encode(),
            'mlkem': f"ML-KEM-768-{node_id}".encode(),
            'aes': f"AES-256-GCM-{node_id}".encode(),
            'sphincs': f"SPHINCS+-128f-{node_id}".encode(),
        }
        return self.derive_multiple(puf_seed, contexts, salt, length=32)
    
    def derive_session_key(
        self,
        shared_secret: bytes,
        node1_id: str,
        node2_id: str,
        length: int = 32
    ) -> bytes:
        """
        Derive a session key from a shared secret (e.g., after ML-KEM).
        
        Args:
            shared_secret: Shared secret from KEM
            node1_id: First node identifier
            node2_id: Second node identifier
            length: Desired key length
        
        Returns:
            Session key (e.g., for AES-256-GCM).
        """
        # Sort IDs for consistent context regardless of who initiates
        ids = sorted([node1_id, node2_id])
        info = f"RAQT-Session-{ids[0]}-{ids[1]}".encode()
        return self.derive(shared_secret, info=info, length=length)
    
    def __repr__(self) -> str:
        return f"HKDF(hash={self.hash_algorithm})"


# Convenience function
def hkdf_derive(
    ikm: bytes,
    salt: Optional[bytes] = None,
    info: Optional[bytes] = None,
    length: int = 32,
    hash_algorithm: str = 'sha3_256'
) -> bytes:
    """
    Derive a key using HKDF.
    
    Args:
        ikm: Input keying material
        salt: Optional salt
        info: Optional context information
        length: Desired output length
        hash_algorithm: Hash function to use
    
    Returns:
        Derived key material.
    """
    hkdf = HKDF(hash_algorithm=hash_algorithm)
    return hkdf.derive(ikm, salt, info, length)