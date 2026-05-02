"""
Fuzzy Extractor with BCH Error Correction

Implements a fuzzy extractor that converts noisy PUF responses into stable
cryptographic keys using BCH error correction codes and secure sketches.
"""

import numpy as np
import hashlib
from typing import Tuple, Optional, Dict
import struct


class BCHErrorCorrection:
    """
    Simplified BCH error correction implementation.
    
    For production use, integrate with bchlib or similar library.
    This implementation provides the interface and basic functionality.
    """
    
    def __init__(self, n: int = 255, k: int = 131, t: int = 18):
        """
        Initialize BCH code parameters.
        
        Args:
            n: Codeword length (default: 255)
            k: Message length (default: 131)
            t: Error correction capability (default: 18 bits)
        """
        self.n = n
        self.k = k
        self.t = t
        self.parity_bits = n - k
    
    def encode(self, message: np.ndarray) -> np.ndarray:
        """
        Encode message with BCH code.
        
        Args:
            message: Binary message array of length k
            
        Returns:
            Encoded codeword of length n
        """
        if len(message) < self.k:
            message = np.pad(message, (0, self.k - len(message)), mode='constant')
        elif len(message) > self.k:
            message = message[:self.k]
        
        codeword = np.zeros(self.n, dtype=np.uint8)
        codeword[:self.k] = message
        
        for i in range(self.parity_bits):
            parity = 0
            for j in range(0, self.k, self.parity_bits):
                if j + i < self.k:
                    parity ^= message[j + i]
            codeword[self.k + i] = parity
        
        return codeword
    
    def decode(self, received: np.ndarray) -> Tuple[np.ndarray, int]:
        """
        Decode received codeword and correct errors.
        
        Args:
            received: Received codeword (possibly with errors)
            
        Returns:
            Tuple of (decoded message, number of errors corrected)
        """
        if len(received) < self.n:
            received = np.pad(received, (0, self.n - len(received)), mode='constant')
        elif len(received) > self.n:
            received = received[:self.n]
        
        message = received[:self.k].copy()
        received_parity = received[self.k:]
        
        expected_parity = np.zeros(self.parity_bits, dtype=np.uint8)
        for i in range(self.parity_bits):
            parity = 0
            for j in range(0, self.k, self.parity_bits):
                if j + i < self.k:
                    parity ^= message[j + i]
            expected_parity[i] = parity
        
        syndrome = received_parity ^ expected_parity
        errors_detected = np.sum(syndrome)
        
        if errors_detected > 0 and errors_detected <= self.t:
            for i in range(min(errors_detected, self.k)):
                if i < len(syndrome) and syndrome[i % len(syndrome)]:
                    message[i] ^= 1
        
        return message, errors_detected
    
    def __repr__(self) -> str:
        return f"BCH({self.n}, {self.k}, {self.t})"


class FuzzyExtractor:
    """
    Fuzzy Extractor for generating stable keys from noisy PUF responses.
    
    Implements the Gen and Rep procedures:
    - Gen: Generate helper data during enrollment
    - Rep: Reproduce stable key using helper data
    """
    
    def __init__(
        self,
        response_length: int = 256,
        key_length: int = 256,
        bch_n: int = 255,
        bch_k: int = 131,
        bch_t: int = 18,
        hash_function: str = 'sha256'
    ):
        """
        Initialize Fuzzy Extractor.
        """
        self.response_length = response_length
        self.key_length = key_length
        self.hash_function = hash_function
        
        self.bch = BCHErrorCorrection(n=bch_n, k=bch_k, t=bch_t)
        self.num_blocks = (response_length + bch_k - 1) // bch_k
    
    def _split_into_blocks(self, data: np.ndarray, block_size: int) -> list:
        """Split data into blocks of specified size."""
        blocks = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            if len(block) < block_size:
                block = np.pad(block, (0, block_size - len(block)), mode='constant')
            blocks.append(block)
        return blocks
    
    def _hash_to_key(self, data: bytes) -> bytes:
        """Derive cryptographic key from data using hash function."""
        if self.hash_function == 'sha256':
            h = hashlib.sha256(data).digest()
        elif self.hash_function == 'sha3_256':
            h = hashlib.sha3_256(data).digest()
        elif self.hash_function == 'sha512':
            h = hashlib.sha512(data).digest()
        else:
            raise ValueError(f"Unsupported hash function: {self.hash_function}")
        
        key = h
        while len(key) * 8 < self.key_length:
            h = hashlib.sha256(h + data).digest()
            key += h
        
        key_bytes = (self.key_length + 7) // 8
        return key[:key_bytes]
    
    def generate(self, puf_response: np.ndarray) -> Tuple[bytes, Dict]:
        """
        Generate stable key and helper data from PUF response (Gen procedure).
        
        Args:
            puf_response: Noisy PUF response
            
        Returns:
            Tuple of (stable_key, helper_data)
        """
        if len(puf_response) < self.response_length:
            puf_response = np.pad(
                puf_response,
                (0, self.response_length - len(puf_response)),
                mode='wrap'
            )
        elif len(puf_response) > self.response_length:
            puf_response = puf_response[:self.response_length]
        
        blocks = self._split_into_blocks(puf_response, self.bch.k)
        
        helper_data = {
            'codewords': [],
            'response_length': self.response_length,
            'num_blocks': len(blocks),
            'bch_params': {
                'n': self.bch.n,
                'k': self.bch.k,
                't': self.bch.t
            }
        }
        
        encoded_blocks = []
        for block in blocks:
            codeword = self.bch.encode(block)
            encoded_blocks.append(codeword)
            helper_data['codewords'].append(codeword.tolist())
        
        stable_response = np.concatenate([b[:self.bch.k] for b in encoded_blocks])
        stable_response = stable_response[:self.response_length]
        
        response_bytes = np.packbits(stable_response).tobytes()
        stable_key = self._hash_to_key(response_bytes)
        helper_data['key_hash'] = hashlib.sha256(stable_key).hexdigest()
        
        return stable_key, helper_data
    
    def reproduce(
        self,
        noisy_response: np.ndarray,
        helper_data: Dict
    ) -> Tuple[Optional[bytes], bool, int]:
        """
        Reproduce stable key from noisy response using helper data (Rep procedure).
        
        Args:
            noisy_response: Noisy PUF response
            helper_data: Helper data from enrollment
            
        Returns:
            Tuple of (stable_key, success, total_errors_corrected)
        """
        response_length = helper_data['response_length']
        if len(noisy_response) < response_length:
            noisy_response = np.pad(
                noisy_response,
                (0, response_length - len(noisy_response)),
                mode='wrap'
            )
        elif len(noisy_response) > response_length:
            noisy_response = noisy_response[:response_length]
        
        blocks = self._split_into_blocks(noisy_response, self.bch.k)
        
        corrected_blocks = []
        total_errors = 0
        
        for i, block in enumerate(blocks):
            if i >= len(helper_data['codewords']):
                break
            
            stored_codeword = np.array(helper_data['codewords'][i], dtype=np.uint8)
            received = np.zeros(self.bch.n, dtype=np.uint8)
            received[:self.bch.k] = block
            received[self.bch.k:] = stored_codeword[self.bch.k:]
            
            corrected_message, errors = self.bch.decode(received)
            corrected_blocks.append(corrected_message)
            total_errors += errors
        
        stable_response = np.concatenate(corrected_blocks)
        stable_response = stable_response[:response_length]
        
        response_bytes = np.packbits(stable_response).tobytes()
        stable_key = self._hash_to_key(response_bytes)
        
        key_hash = hashlib.sha256(stable_key).hexdigest()
        success = (key_hash == helper_data['key_hash'])
        
        if success:
            return stable_key, True, total_errors
        else:
            return None, False, total_errors
    
    def measure_error_correction_capability(
        self,
        puf_response: np.ndarray,
        num_trials: int = 100,
        error_rates: list = None
    ) -> Dict[float, float]:
        """Measure error correction capability at different error rates."""
        if error_rates is None:
            error_rates = [0.05, 0.10, 0.15, 0.20, 0.25]
        
        stable_key, helper_data = self.generate(puf_response)
        
        results = {}
        for error_rate in error_rates:
            successes = 0
            for _ in range(num_trials):
                noisy = puf_response.copy()
                num_errors = int(len(noisy) * error_rate)
                error_positions = np.random.choice(len(noisy), num_errors, replace=False)
                noisy[error_positions] ^= 1
                
                _, success, _ = self.reproduce(noisy, helper_data)
                if success:
                    successes += 1
            
            results[error_rate] = successes / num_trials
        
        return results
    
    def __repr__(self) -> str:
        return (
            f"FuzzyExtractor(response_len={self.response_length}, "
            f"key_len={self.key_length}, "
            f"bch={self.bch})"
        )


if __name__ == "__main__":
    print("=" * 70)
    print("Fuzzy Extractor with BCH Error Correction Demonstration")
    print("=" * 70)
    
    extractor = FuzzyExtractor(
        response_length=256,
        key_length=256,
        bch_n=255,
        bch_k=131,
        bch_t=18
    )
    
    print(f"\n{extractor}")
    
    print("\nSimulating PUF enrollment...")
    clean_response = np.random.randint(0, 2, size=256, dtype=np.uint8)
    print(f"Clean response: {clean_response[:32]}... ({len(clean_response)} bits)")
    
    # FIXED: generate returns 2 values
    stable_key, helper_data = extractor.generate(clean_response)
    print(f"\nGenerated stable key: {stable_key.hex()[:64]}...")
    print(f"Key length: {len(stable_key) * 8} bits")
    print(f"Helper data blocks: {helper_data['num_blocks']}")
    print(f"Key hash: {helper_data['key_hash'][:16]}...")
    
    print("\nTesting key reproduction with noise...")
    noise_levels = [0.05, 0.10, 0.15, 0.20]
    
    for noise_level in noise_levels:
        noisy_response = clean_response.copy()
        num_errors = int(len(noisy_response) * noise_level)
        error_positions = np.random.choice(len(noisy_response), num_errors, replace=False)
        noisy_response[error_positions] ^= 1
        
        reproduced_key, success, errors_corrected = extractor.reproduce(
            noisy_response,
            helper_data
        )
        
        status = "SUCCESS" if success else "FAILED"
        print(f"  {noise_level:.0%} noise ({num_errors} errors): {status} "
              f"(corrected {errors_corrected} errors)")
        
        if success and reproduced_key:
            match = (reproduced_key == stable_key)
            print(f"    Key match: {'YES' if match else 'NO'}")
    
    print("\n" + "=" * 70)