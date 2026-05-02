import netsquid as ns
from netsquid.qubits import qubitapi as qapi
# Import the actual mathematical operators
from netsquid.qubits.operators import H, CNOT, Z

def run_raqt_netsquid(sender_id, secret_bit, shots=100):
    success = 0
    
    for _ in range(shots):
        # 1. Create 4 qubits
        qubits = qapi.create_qubits(4)
        
        # 2. Create GHZ State using Operators (H, CNOT)
        qapi.operate(qubits[0], H)
        qapi.operate([qubits[0], qubits[1]], CNOT)
        qapi.operate([qubits[0], qubits[2]], CNOT)
        qapi.operate([qubits[0], qubits[3]], CNOT)
        
        # 3. Encode secret bit using Operator (Z)
        if secret_bit == 1:
            qapi.operate(qubits[sender_id], Z)
        
        # 4. Basis transformation (X-basis measurement)
        for q in qubits:
            qapi.operate(q, H)
        
        # 5. Measure and calculate parity (XOR)
        xor_sum = 0
        for q in qubits:
            # qapi.measure returns (outcome, probability)
            m, _ = qapi.measure(q)
            xor_sum ^= m
        
        # In the RAQT protocol, parity matches the secret bit
        if xor_sum == secret_bit:
            success += 1
            
    return success / shots

print("=" * 50)
print("NetSquid RAQT (Corrected Operator Types)")
print("=" * 50)

# Run simulations
s0 = run_raqt_netsquid(sender_id=2, secret_bit=0, shots=500)
s1 = run_raqt_netsquid(sender_id=2, secret_bit=1, shots=500)

print(f"Secret bit 0 parity match: {s0*100:.1f}%")
print(f"Secret bit 1 parity match: {s1*100:.1f}%")
