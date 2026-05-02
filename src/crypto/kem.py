# src/crypto/kem.py
"""
Key Encapsulation Mechanism (KEM) Base Class

Defines the abstract interface for all KEM implementations.
Concrete implementations: ML-KEM (Kyber), Classic McEliece, etc.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional
from dataclasses import dataclass


@dataclass
class KEMKeypair:
    """KEM public/private keypair."""
    public_key: bytes
    secret_key: bytes
    ciphertext_size: int
    shared_secret_size: int
    public_key_size: int
    secret_key_size: int
    security_level: str


class KeyEncapsulationMechanism(ABC):
    """
    Abstract base class for Key Encapsulation Mechanisms.
    
    A KEM provides:
    - Key generation: (pk, sk) = keygen(seed)
    - Encapsulation: (ct, ss) = encaps(pk)
    - Decapsulation: ss = decaps(sk, ct)
    
    The shared secret (ss) can be used as a symmetric key for encryption.
    """
    
    @abstractmethod
    def keygen(self, seed: Optional[bytes] = None) -> KEMKeypair:
        """
        Generate a public-secret keypair.
        
        Args:
            seed: Optional seed for deterministic key generation.
                  If None, uses system randomness.
        
        Returns:
            KEMKeypair containing public and secret keys.
        """
        pass
    
    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate a shared secret using the recipient's public key.
        
        Args:
            public_key: Recipient's public key.
        
        Returns:
            Tuple of (ciphertext, shared_secret).
            The ciphertext is sent to the recipient.
            The shared secret is used as a symmetric key.
        """
        pass
    
    @abstractmethod
    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate the shared secret using the recipient's secret key.
        
        Args:
            secret_key: Recipient's secret key.
            ciphertext: Ciphertext from encapsulate().
        
        Returns:
            The shared secret (must match the one from encapsulate).
        """
        pass
    
    def validate_public_key(self, public_key: bytes) -> bool:
        """Validate public key format."""
        return len(public_key) > 0
    
    def validate_secret_key(self, secret_key: bytes) -> bool:
        """Validate secret key format."""
        return len(secret_key) > 0
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"


class KEMError(Exception):
    """Base exception for KEM errors."""
    pass


class InvalidPublicKeyError(KEMError):
    """Raised when public key is invalid."""
    pass


class InvalidCiphertextError(KEMError):
    """Raised when ciphertext is invalid."""
    pass
if __name__ == "__main__":
    print("=" * 50)
    print("KEM Base Module")
    print("=" * 50)
    print(f"KeyEncapsulationMechanism: {KeyEncapsulationMechanism.__name__}")
    print(f"KEMKeypair: {KEMKeypair.__name__}")
    print(f"KEMError: {KEMError.__name__}")
    print("\nThis is a base class module. Import it in your code.")
    print("Example: from crypto.kem import KeyEncapsulationMechanism")