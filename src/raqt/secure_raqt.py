"""
Secure RAQT Protocol Implementation

Integrates the Remote Anonymous Quantum Transmission (RAQT) protocol with:
- PUF-based hardware authentication
- Post-Quantum Cryptography (Dilithium + ML-KEM)
- AES-256-GCM encryption for classical channels
- Tamper detection and monitoring
- AI-based anomaly detection for eavesdropping (Sentinel-Integrated)

Based on Christandl-Wehner 2004 anonymous quantum bit transmission protocol.
"""

import netsquid as ns
from netsquid.qubits import qubitapi as qapi
from netsquid.qubits.operators import H, CNOT, Z
import numpy as np
import hashlib
import hmac
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from enum import Enum
import json

# Import our security modules
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from puf.sram_puf import SRAMPUF
from puf.ro_puf import RingOscillatorPUF
from puf.arbiter_puf import ArbiterPUF
from puf.fusion import PUFFusion, FusionMethod
from puf.fuzzy_extractor import FuzzyExtractor
from crypto.pqc import PQCAuthenticationProtocol, PQCKeyDerivation

# Sentinel-Integrated AI Module
from ai.raqt_anomaly_detector import RAQTAnomalyDetector


class NodeState(Enum):
    """Node operational states"""
    UNINITIALIZED = "uninitialized"
    ENROLLED = "enrolled"
    AUTHENTICATED = "authenticated"
    READY = "ready"
    TRANSMITTING = "transmitting"
    COMPROMISED = "compromised"


class SecurityLevel(Enum):
    """Security levels for different operations"""
    LOW = 1      # Basic PUF authentication
    MEDIUM = 2   # PUF + Dilithium signatures
    HIGH = 3     # PUF + Dilithium + ML-KEM + AES-GCM
    CRITICAL = 4 # All security features + tamper monitoring


@dataclass
class SecurityMetrics:
    """Security and performance metrics"""
    authentication_time: float = 0.0
    key_derivation_time: float = 0.0
    encryption_time: float = 0.0
    puf_reliability: float = 0.0
    tamper_events: int = 0
    failed_authentications: int = 0
    successful_transmissions: int = 0
    total_transmissions: int = 0
    
    def to_dict(self) -> Dict:
        """Convert metrics to dictionary"""
        return {
            'authentication_time_ms': self.authentication_time * 1000,
            'key_derivation_time_ms': self.key_derivation_time * 1000,
            'encryption_time_ms': self.encryption_time * 1000,
            'puf_reliability': self.puf_reliability,
            'tamper_events': self.tamper_events,
            'failed_authentications': self.failed_authentications,
            'successful_transmissions': self.successful_transmissions,
            'total_transmissions': self.total_transmissions,
            'success_rate': self.successful_transmissions / max(1, self.total_transmissions)
        }


@dataclass
class SecureNode:
    """
    Secure quantum network node with PUF-based authentication
    and PQC-protected communication.
    """
    node_id: str
    security_level: SecurityLevel = SecurityLevel.HIGH
    
    # PUF components
    sram_puf: Optional[SRAMPUF] = None
    ro_puf: Optional[RingOscillatorPUF] = None
    arbiter_puf: Optional[ArbiterPUF] = None
    puf_fusion: Optional[PUFFusion] = None
    fuzzy_extractor: Optional[FuzzyExtractor] = None
    
    # PQC components
    pqc_protocol: Optional[PQCAuthenticationProtocol] = None
    
    # State management
    state: NodeState = NodeState.UNINITIALIZED
    puf_seed: Optional[bytes] = None
    helper_data: Optional[bytes] = None
    session_key: Optional[bytes] = None
    
    # Security metrics
    metrics: SecurityMetrics = field(default_factory=SecurityMetrics)
    
    # Tamper detection
    baseline_puf_response: Optional[bytes] = None
    tamper_threshold: float = 0.20  # 20% deviation triggers alert
    
    def __post_init__(self):
        """Initialize PUF and PQC components"""
        self._initialize_pufs()
        self._initialize_security()
    
    def _initialize_pufs(self):
        """Initialize all PUF types"""
        # Create PUF instances with realistic parameters
        self.sram_puf = SRAMPUF(
            cell_count=2048,
            response_bits=256,
            noise_level=0.15
        )
        
        self.ro_puf = RingOscillatorPUF(
            oscillator_pairs=128,
            frequency_range=(100e6, 150e6),
            noise_level=0.08
        )
        
        self.arbiter_puf = ArbiterPUF(
            delay_stages=64,
            delay_variation=1e-12,
            noise_level=0.11
        )
        
        # Create hybrid PUF fusion
        self.puf_fusion = PUFFusion(
            sram_puf=self.sram_puf,
            ro_puf=self.ro_puf,
            arbiter_puf=self.arbiter_puf,
            fusion_method=FusionMethod.WEIGHTED_AVERAGE,
            weights={'sram': 0.30, 'ro': 0.45, 'arbiter': 0.25}
        )
        
        # Create fuzzy extractor for stable key generation
        self.fuzzy_extractor = FuzzyExtractor(
            response_length=256,
            key_length=256
        )
    
    def _initialize_security(self):
        """Initialize PQC security protocols"""
        # Generate initial PUF response as seed
        start_time = time.time()
        puf_response = self.puf_fusion.generate_response()
        
        # Extract stable key using fuzzy extractor
        self.puf_seed, self.helper_data = self.fuzzy_extractor.generate(puf_response)
        self.metrics.key_derivation_time = time.time() - start_time
        
        # Initialize PQC protocol with PUF-derived seed
        self.pqc_protocol = PQCAuthenticationProtocol(
            node_id=self.node_id,
            puf_seed=self.puf_seed
        )
        
        # Store baseline for tamper detection
        self.baseline_puf_response = puf_response
        self.metrics.puf_reliability = self.puf_fusion.measure_reliability()
        
        self.state = NodeState.ENROLLED
    
    def authenticate(self, peer_public_keys: Dict[str, bytes]) -> Tuple[bool, Dict]:
        """
        Authenticate with peer node using PQC
        
        Args:
            peer_public_keys: Dictionary with 'dilithium' and 'mlkem' public keys
            
        Returns:
            Tuple of (success, authentication_data)
        """
        start_time = time.time()
        
        try:
            # Generate authentication challenge
            challenge = os.urandom(32)
            
            # Create authentication response
            auth_response = self.pqc_protocol.authenticate(challenge)
            
            # Verify peer's authentication (simulated)
            verified = self.pqc_protocol.verify_authentication(
                auth_response,
                challenge,
                peer_public_keys.get('dilithium')
            )
            
            if verified:
                # Establish session key using ML-KEM
                ciphertext = self.pqc_protocol.establish_session(
                    peer_public_keys.get('mlkem')
                )
                self.session_key = self.pqc_protocol.get_session_key()
                
                self.state = NodeState.AUTHENTICATED
                self.metrics.successful_transmissions = 1
            else:
                self.metrics.failed_authentications = 1
                
            self.metrics.authentication_time = time.time() - start_time
            
            return verified, {
                'auth_response': auth_response,
                'ciphertext': ciphertext if verified else None,
                'public_keys': self.pqc_protocol.get_public_keys()
            }
            
        except Exception as e:
            self.metrics.failed_authentications = 1
            return False, {'error': str(e)}
    
    def check_tamper(self) -> Tuple[bool, float]:
        """
        Check for physical tampering using PUF response deviation
        
        Returns:
            Tuple of (is_tampered, deviation_ratio)
        """
        current_response = self.puf_fusion.generate_response()
        
        # Calculate Hamming distance
        hamming_dist = sum(
            b1 != b2 
            for b1, b2 in zip(self.baseline_puf_response, current_response)
        )
        
        deviation = hamming_dist / len(self.baseline_puf_response)
        
        if deviation > self.tamper_threshold:
            self.state = NodeState.COMPROMISED
            self.metrics.tamper_events = 1
            return True, deviation
        
        return False, deviation
    
    def encrypt_classical_data(self, data: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt classical channel data using AES-256-GCM
        
        Args:
            data: Plaintext data to encrypt
            
        Returns:
            Tuple of (ciphertext, nonce, tag)
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        start_time = time.time()
        
        # Derive AES key from session key
        aes_key = hashlib.sha256(self.session_key).digest()
        aesgcm = AESGCM(aes_key)
        
        # Generate random nonce
        nonce = os.urandom(12)
        
        # Encrypt with authenticated encryption
        ciphertext = aesgcm.encrypt(nonce, data, None)
        
        self.metrics.encryption_time = time.time() - start_time
        
        # Split ciphertext and tag (last 16 bytes)
        return ciphertext[:-16], nonce, ciphertext[-16:]
    
    def decrypt_classical_data(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> Optional[bytes]:
        """
        Decrypt classical channel data using AES-256-GCM
        
        Args:
            ciphertext: Encrypted data
            nonce: Nonce used for encryption
            tag: Authentication tag
            
        Returns:
            Decrypted plaintext or None if verification fails
        """
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        try:
            # Derive AES key from session key
            aes_key = hashlib.sha256(self.session_key).digest()
            aesgcm = AESGCM(aes_key)
            
            # Decrypt and verify
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
            return plaintext
            
        except Exception:
            return None
    
    def get_status(self) -> Dict:
        """Get comprehensive node status"""
        return {
            'node_id': self.node_id,
            'state': self.state.value,
            'security_level': self.security_level.value,
            'puf_reliability': self.metrics.puf_reliability,
            'authenticated': self.state == NodeState.AUTHENTICATED,
            'session_established': self.session_key is not None,
            'metrics': self.metrics.to_dict()
        }


class SecureRAQTProtocol:
    """
    Secure RAQT Protocol with PUF+PQC integration and AI anomaly detection.
    
    Combines anonymous quantum transmission with hardware-rooted security,
    post-quantum cryptographic protection, and AI-based eavesdropping detection.
    
    Sentinel Framework Alignment:
        - BSQC Semester 5: Hardware Root of Trust
        - BSQC Semester 7: Secure Quantum Networks (AI-Enhanced)
    """
    
    def __init__(self, num_nodes: int = 4, security_level: SecurityLevel = SecurityLevel.HIGH):
        """
        Initialize secure RAQT protocol
        
        Args:
            num_nodes: Number of nodes in the quantum network
            security_level: Security level for operations
        """
        self.num_nodes = num_nodes
        self.security_level = security_level
        self.nodes: List[SecureNode] = []
        
        # Sentinel-Integrated AI anomaly detector
        self.ai_detector: Optional[RAQTAnomalyDetector] = None
        self.ai_detector_trained = False
        
        # Initialize nodes
        for i in range(num_nodes):
            node = SecureNode(
                node_id=f"node_{i:03d}",
                security_level=security_level
            )
            self.nodes.append(node)
        
        # Perform mutual authentication
        self._mutual_authentication()
    
    def _mutual_authentication(self):
        """Perform mutual authentication between all nodes"""
        print(f"\n[SEC] Performing mutual authentication for {self.num_nodes} nodes...")
        
        for i, node in enumerate(self.nodes):
            # Get public keys from all other nodes
            for j, peer in enumerate(self.nodes):
                if i != j:
                    peer_keys = peer.pqc_protocol.get_public_keys()
                    success, _ = node.authenticate(peer_keys)
                    
                    if not success:
                        print(f"[WARN] Authentication failed: {node.node_id} <-> {peer.node_id}")
        
        print("[SEC] Mutual authentication complete")
    
    def train_ai_detector(self, normal_executions: List[Dict]) -> bool:
        """
        Train the AI anomaly detector on normal RAQT execution data.
        
        Args:
            normal_executions: List of normal RAQT execution dictionaries
            
        Returns:
            True if training successful
        """
        if self.ai_detector is None:
            self.ai_detector = RAQTAnomalyDetector(contamination=0.1)
        
        try:
            self.ai_detector.train(normal_executions)
            self.ai_detector_trained = True
            print("[AI] Anomaly detector trained successfully")
            return True
        except Exception as e:
            print(f"[AI] Training failed: {e}")
            return False
    
    def run_secure_transmission(
        self,
        sender_id: int,
        secret_bit: int,
        shots: int = 100,
        enable_tamper_check: bool = True,
        enable_ai_detection: bool = True
    ) -> Dict:
        """
        Run secure RAQT transmission with full security stack.
        
        Args:
            sender_id: Index of the sender node (0 to num_nodes-1)
            secret_bit: Secret bit to transmit (0 or 1)
            shots: Number of quantum protocol runs
            enable_tamper_check: Enable tamper detection monitoring
            enable_ai_detection: Enable AI-based eavesdropping detection
            
        Returns:
            Dictionary with transmission results and security metrics
        """
        sender = self.nodes[sender_id]
        
        # Check for tampering before transmission
        if enable_tamper_check:
            is_tampered, deviation = sender.check_tamper()
            if is_tampered:
                return {
                    'success': False,
                    'error': 'Tamper detected',
                    'deviation': deviation,
                    'metrics': sender.metrics.to_dict()
                }
        
        # Update state
        sender.state = NodeState.TRANSMITTING
        sender.metrics.total_transmissions = 1
        
        # Run RAQT protocol (quantum transmission)
        success_count = 0
        xor_results = []
        transmission_start = time.time()
        
        for _ in range(shots):
            # 1. Create GHZ state
            qubits = qapi.create_qubits(self.num_nodes)
            
            # 2. Prepare GHZ state
            qapi.operate(qubits[0], H)
            for i in range(1, self.num_nodes):
                qapi.operate([qubits[0], qubits[i]], CNOT)
            
            # 3. Encode secret bit
            if secret_bit == 1:
                qapi.operate(qubits[sender_id], Z)
            
            # 4. X-basis measurement
            for q in qubits:
                qapi.operate(q, H)
            
            # 5. Measure and calculate parity
            xor_sum = 0
            for q in qubits:
                m, _ = qapi.measure(q)
                xor_sum ^= m
            
            xor_results.append(xor_sum)
            
            # Check if parity matches secret bit
            if xor_sum == secret_bit:
                success_count += 1
        
        transmission_time = time.time() - transmission_start
        success_rate = success_count / shots
        
        # Encrypt transmission metadata
        metadata = json.dumps({
            'sender_id': sender_id,
            'timestamp': time.time(),
            'shots': shots,
            'success_rate': success_rate
        }).encode()
        
        ciphertext, nonce, tag = sender.encrypt_classical_data(metadata)
        
        # Update metrics
        if success_rate > 0.95:  # Consider successful if >95% accuracy
            sender.metrics.successful_transmissions = 1
        
        sender.state = NodeState.READY
        
        # Build result dictionary
        result = {
            'success': True,
            'sender_id': sender_id,
            'secret_bit': secret_bit,
            'success_rate': success_rate,
            'shots': shots,
            'transmission_time': transmission_time,
            'encrypted_metadata': {
                'ciphertext': ciphertext.hex(),
                'nonce': nonce.hex(),
                'tag': tag.hex()
            },
            'security': {
                'puf_reliability': sender.metrics.puf_reliability,
                'tamper_events': sender.metrics.tamper_events,
                'authentication_time': sender.metrics.authentication_time
            },
            'metrics': sender.metrics.to_dict()
        }
        
        # Sentinel-Integrated AI anomaly detection
        if enable_ai_detection and self.ai_detector_trained:
            execution_data = {
                'xor_results': xor_results,
                'basis_choices': [0, 1] * (shots // 2),
                'error_rate': 1.0 - success_rate,
                'execution_time': transmission_time,
                'message_length': shots,
                'num_parties': self.num_nodes
            }
            is_anomaly, score, details = self.ai_detector.detect(execution_data)
            result['ai_anomaly'] = {
                'detected': is_anomaly,
                'score': score,
                'details': {
                    'xor_bias': details.get('xor_bias', 0),
                    'error_rate': details.get('error_rate', 0)
                }
            }
            
            if is_anomaly:
                print(f"[AI ALERT] Anomaly detected in transmission from node {sender_id}! Score: {score:.4f}")
        
        return result
    
    def get_network_status(self) -> Dict:
        """Get comprehensive network status"""
        return {
            'num_nodes': self.num_nodes,
            'security_level': self.security_level.value,
            'ai_detector_trained': self.ai_detector_trained,
            'nodes': [node.get_status() for node in self.nodes],
            'total_transmissions': sum(n.metrics.total_transmissions for n in self.nodes),
            'total_tamper_events': sum(n.metrics.tamper_events for n in self.nodes),
            'average_puf_reliability': np.mean([n.metrics.puf_reliability for n in self.nodes])
        }


def demo_secure_raqt():
    """Demonstration of secure RAQT protocol"""
    print("=" * 70)
    print("SECURE RAQT PROTOCOL DEMONSTRATION")
    print("Sentinel-Integrated AI Modules Enabled")
    print("=" * 70)
    print("\nFeatures:")
    print("  * PUF-based hardware authentication (SRAM + RO + Arbiter)")
    print("  * Post-Quantum Cryptography (Dilithium + ML-KEM)")
    print("  * AES-256-GCM encryption for classical channels")
    print("  * Real-time tamper detection")
    print("  * AI-based anomaly detection for eavesdropping")
    print("  * Anonymous quantum bit transmission (Christandl-Wehner 2004)")
    
    # Initialize secure protocol
    print("\n[INIT] Initializing secure quantum network...")
    protocol = SecureRAQTProtocol(num_nodes=4, security_level=SecurityLevel.HIGH)
    
    # Train AI detector with baseline data
    print("\n[AI] Training anomaly detector...")
    normal_executions = []
    for _ in range(50):
        execution = {
            'xor_results': np.random.randint(0, 2, 100).tolist(),
            'basis_choices': np.random.randint(0, 2, 100).tolist(),
            'error_rate': np.random.uniform(0.01, 0.05),
            'execution_time': np.random.uniform(0.9, 1.1),
            'message_length': 100,
            'num_parties': 4
        }
        normal_executions.append(execution)
    protocol.train_ai_detector(normal_executions)
    
    # Run secure transmissions
    print("\n[TRANSMIT] Running secure quantum transmissions...")
    
    results = []
    for sender_id in range(4):
        for secret_bit in [0, 1]:
            print(f"\n  Node {sender_id} transmitting bit {secret_bit}...")
            result = protocol.run_secure_transmission(
                sender_id=sender_id,
                secret_bit=secret_bit,
                shots=500,
                enable_tamper_check=True,
                enable_ai_detection=True
            )
            results.append(result)
            
            if result['success']:
                print(f"    [OK] Success rate: {result['success_rate']*100:.1f}%")
                print(f"    [OK] Transmission time: {result['transmission_time']*1000:.2f}ms")
                print(f"    [OK] PUF reliability: {result['security']['puf_reliability']:.3f}")
                if 'ai_anomaly' in result:
                    print(f"    [AI] Anomaly score: {result['ai_anomaly']['score']:.4f}")
            else:
                print(f"    [FAIL] Transmission failed: {result.get('error')}")
    
    # Display network status
    print("\n" + "=" * 70)
    print("NETWORK STATUS")
    print("=" * 70)
    status = protocol.get_network_status()
    print(f"\n  Total nodes: {status['num_nodes']}")
    print(f"  Security level: {status['security_level']}")
    print(f"  AI detector trained: {status['ai_detector_trained']}")
    print(f"  Total transmissions: {status['total_transmissions']}")
    print(f"  Tamper events: {status['total_tamper_events']}")
    print(f"  Average PUF reliability: {status['average_puf_reliability']:.3f}")
    
    # Display per-node metrics
    print("\nPER-NODE METRICS:")
    for node_status in status['nodes']:
        print(f"\n  {node_status['node_id']}:")
        print(f"    State: {node_status['state']}")
        print(f"    Authenticated: {node_status['authenticated']}")
        print(f"    PUF Reliability: {node_status['puf_reliability']:.3f}")
        metrics = node_status['metrics']
        print(f"    Success Rate: {metrics['success_rate']*100:.1f}%")
        print(f"    Auth Time: {metrics['authentication_time_ms']:.2f}ms")
    
    print("\n" + "=" * 70)
    print("DEMONSTRATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    # Run demonstration
    demo_secure_raqt()

# Made with Bob — Sentinel-Integrated AI Modules