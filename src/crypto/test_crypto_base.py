import sys
import os

# Add current directory to path
sys.path.insert(0, os.getcwd())

print("=" * 50)
print("Testing Crypto Base Modules")
print("=" * 50)
print(f"Current directory: {os.getcwd()}")
print(f"src exists: {os.path.exists('src')}")

# Test KEM
from src.crypto.kem import KeyEncapsulationMechanism, KEMKeypair
print("✓ kem.py loaded")



# Test KDF
from src.crypto.kdf import HKDF, hkdf_derive
print("✓ kdf.py loaded")

# Test AES
from src.crypto.aes import AESGCMEncryption, AESKey
print("✓ aes.py loaded")

print("\n" + "=" * 50)
print("All crypto base modules loaded successfully!")
print("=" * 50)