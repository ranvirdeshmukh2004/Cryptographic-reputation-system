import hashlib
import time
import json
import typing
import os
from enum import Enum
from dataclasses import dataclass, asdict

# cryptography import might fail if not installed, but it is standard requirement logic
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Error: 'cryptography' library is required.")
    print("Please install it using: pip install cryptography")
    exit(1)

# ==============================================================================
# 1. Identity Module
# ==============================================================================

class IdentityModule:
    """Handles generation of RSA key pairs for developer identity."""
    
    @staticmethod
    def generate_key_pair() -> typing.Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generates a 2048-bit RSA private and public key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def public_key_to_pem(public_key: rsa.RSAPublicKey) -> str:
        """Converts a public key object to a PEM string format (Developer ID)."""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

# ==============================================================================
# 2. Developer Class
# ==============================================================================

class Developer:
    """Represents a developer with a cryptographic identity."""
    
    def __init__(self, name: str):
        self.name = name
        self.private_key, self.public_key_obj = IdentityModule.generate_key_pair()
        self.id = IdentityModule.public_key_to_pem(self.public_key_obj)
    
    def sign_hash(self, data_hash: str) -> str:
        """Digitally signs the hash of the contribution using Private Key."""
        # The hash string must be bytes for signing
        signature = self.private_key.sign(
            data_hash.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Return hex string of signature
        return signature.hex()

# ==============================================================================
# 3. Contribution & Hashing Module
# ==============================================================================

class Contribution:
    """Represents a code contribution."""
    
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.timestamp = time.time()
        
    def calculate_hash(self) -> str:
        """Generates SHA-256 hash of the source code."""
        return hashlib.sha256(self.source_code.encode('utf-8')).hexdigest()

# ==============================================================================
# 4. Digital Signature Verification Module
# ==============================================================================

class SignatureVerifier:
    """Verifies digital signatures."""
    
    @staticmethod
    def verify(public_key_pem: str, data_hash: str, signature_hex: str) -> bool:
        """
        Verifies that the signature was created by the owner of the public key
        for the given data hash.
        """
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            signature = bytes.fromhex(signature_hex)
            
            public_key.verify(
                signature,
                data_hash.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            # verification failed
            return False

# ==============================================================================
# 5. Reputation Engine
# ==============================================================================

@dataclass
class ReputationFactors:
    W: float = 1.0  # Weight coefficient (can be dynamic, simple 1.0 for now)
    Q: float = 0.0  # Quality score (0-10)
    V: int = 0      # Verification boolean (0 or 1)
    I: float = 0.0  # Impact score (0-10)
    T: float = 1.0  # Time/Trust factor (0-10)

class ReputationEngine:
    """
    Computes reputation based on the formula:
    R = Sum(Wi * Qi * Vi * Ii * Ti)
    """
    
    @staticmethod
    def compute_score(factors: ReputationFactors) -> float:
        """Calculates the reputation score for a single contribution."""
        # R = W * Q * V * I * T
        score = factors.W * factors.Q * float(factors.V) * factors.I * factors.T
        return round(score, 4)

# ==============================================================================
# 6. Blockchain Ledger Integration
# ==============================================================================

@dataclass
class Block:
    index: int
    timestamp: float
    developer_id: str
    contribution_hash: str
    reputation_score: float
    signature: str
    previous_hash: str
    hash: str = ""

    def calculate_block_hash(self) -> str:
        """Calculates hash of the block content."""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "developer_id": self.developer_id,
            "contribution_hash": self.contribution_hash,
            "reputation_score": self.reputation_score,
            "signature": self.signature,
            "previous_hash": self.previous_hash
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain: typing.List[Block] = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Creates the first block in the chain."""
        genesis_block = Block(
            index=0,
            timestamp=time.time(),
            developer_id="SYSTEM_GENESIS",
            contribution_hash="0",
            reputation_score=0.0,
            signature="0",
            previous_hash="0"
        )
        genesis_block.hash = genesis_block.calculate_block_hash()
        self.chain.append(genesis_block)
    
    def get_latest_block(self) -> Block:
        return self.chain[-1]
    
    def add_block(self, developer_id, contribution_hash, reputation_score, signature):
        previous_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            developer_id=developer_id,
            contribution_hash=contribution_hash,
            reputation_score=reputation_score,
            signature=signature,
            previous_hash=previous_block.hash
        )
        new_block.hash = new_block.calculate_block_hash()
        self.chain.append(new_block)
        return new_block

    def to_json(self):
        """Returns the entire chain as a JSON string."""
        chain_data = [asdict(block) for block in self.chain]
        return json.dumps(chain_data, indent=4)

    def validate_chain(self) -> bool:
        """
        Iterates through the chain to ensure:
        1. Current block's hash is valid.
        2. Current block's previous_hash matches the actual hash of the previous block.
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # 1. Recalculate hash of current block
            if current_block.hash != current_block.calculate_block_hash():
                print(f"{Colors.FAIL}TAMPERING DETECTED at Block {current_block.index}: Hash Mismatch!{Colors.ENDC}")
                return False

            # 2. Check link to previous block
            if current_block.previous_hash != previous_block.hash:
                print(f"{Colors.FAIL}TAMPERING DETECTED at Block {current_block.index}: Broken Chain Link!{Colors.ENDC}")
                return False
        
        print(f"{Colors.GREEN}Blockchain Integrity Verified: Valid.{Colors.ENDC}")
        return True

# ==============================================================================
# 7. Utilities & CLI Formatting
# ==============================================================================

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_section(title):
    print(f"\n{Colors.HEADER}{'='*60}")
    print(f" {title}")
    print(f"{'='*60}{Colors.ENDC}")

def print_step(step, msg):
    print(f"{Colors.BOLD}[Step {step}]{Colors.ENDC} {msg}")

# ==============================================================================
# 8. Main Simulation Workflow
# ==============================================================================

def main():
    print_section("Decentralized Reputation System Prototype - Initialization")
    
    # Initialize Blockchain
    reputation_chain = Blockchain()
    print(f"{Colors.GREEN}Blockchain initialized with Genesis Block.{Colors.ENDC}")

    # --- Step 1: Register Developer ---
    print_section("1. Identity Registration")
    print_step(1, "Creating Developer Identity (RSA Key Pair generation)...")
    
    # Allow user to input name or default to Alice
    name_input = input(f"   > Enter developer name (default 'Alice'): ").strip()
    dev_name = name_input if name_input else "Alice"
    
    dev_alice = Developer(dev_name)
    
    # Truncate for display
    display_id = dev_alice.id.replace('\n', '')[27:80] + "..."
    print(f"   > Developer Name: {Colors.CYAN}{dev_alice.name}{Colors.ENDC}")
    print(f"   > Public Key (ID): {display_id}")

    # --- Step 2: Create Contribution ---
    print_section("2. Contribution Submission")
    code_snippet = "def hello_world():\n    print('Hello, Decentralized World!')"
    print_step(2, f"Developer {dev_alice.name} submits code:")
    print(f"{Colors.BLUE}{code_snippet}{Colors.ENDC}")
    
    contribution = Contribution(code_snippet)
    
    # --- Step 3: Hashing ---
    print_section("3. Contribution Hashing")
    contrib_hash = contribution.calculate_hash()
    print_step(3, "Generated SHA-256 Hash of source code:")
    print(f"   > Hash: {Colors.WARNING}{contrib_hash}{Colors.ENDC}")

    # --- Step 4: Digital Signature ---
    print_section("4. Digital Signing")
    signature = dev_alice.sign_hash(contrib_hash)
    print_step(4, f"{dev_alice.name} signs the hash with Private Key.")
    print(f"   > Signature (Hex): {signature[:60]}...")

    # --- Step 5: Verification ---
    print_section("5. Decentralized Verification")
    print_step(5, f"System verifying signature against Public Key of {dev_alice.name}...")
    
    is_valid = SignatureVerifier.verify(dev_alice.id, contrib_hash, signature)
    
    if is_valid:
        print(f"   > Result: {Colors.GREEN}VERIFIED VALID ✅{Colors.ENDC}")
        verification_val = 1
    else:
        print(f"   > Result: {Colors.FAIL}INVALID SIGNATURE ❌{Colors.ENDC}")
        verification_val = 0
        exit(1) # Stop simulation if invalid

    # --- Step 6: Reputation Computation ---
    print_section("6. Reputation Score Calculation")
    print_step(6, "Evaluating contribution metrics...")
    
    # Input parameters from Patent Prototype Design
    # quality=8, peer_validation=7, impact=6, trust=9
    # Converting to factors: Q=8, V=1, I=6, T=0.9 (normalized mostly, but let's follow the simple product)
    # The user prompt example output was 7.6, but user request says:
    # R = Sum(Wi * Qi * Vi * Ii * Ti)
    # Let's map inputs:
    # Quality (Q) = 8
    # Verification (V) = 1 (Verified)
    # Impact (I) = 6
    # Trust/Time (T) = 0.9 (Approximating 'trust=9' as 0.9 factor or just 9, let's use 9 to match magnitude or scale)
    # Wait, the user prompt Example: quality=8, peer=7, impact=6, trust=9 -> score=7.6?
    # That math doesn't multiply to 7.6. 8*1*6*9 = 432. 
    # Maybe it's a weighted sum? The formula shows Multiplication: (Wi * Qi * Vi * Ii * Ti).
    # Ah, the formula is SUM of terms. But for a single contribution, it's just one term.
    # Maybe the "7.6" in the prompt example was an arbitrary number or average?
    # I will stick to the Multiplication formula provided in valid latex: $R = \sum_{i=1}^{n} (W_i \times Q_i \times V_i \times I_i \times T_i)$
    # And I'll assume Wi (Weight) scales it down. Let's set W=0.01 to keep it manageable, or just output the raw number.
    # Actually, let's follow the formula strictly.
    
    factors = ReputationFactors(
        W=0.01, # Arbitrary weight to normalize
        Q=8.0,
        V=verification_val,
        I=6.0,
        T=9.0   # Using 9 as the 'Trust' from input
    )
    
    score = ReputationEngine.compute_score(factors)
    # 0.01 * 8 * 1 * 6 * 9 = 4.32. 
    # I'll adjust W to match the user's "7.6" example closer if I wanted, but better to be chemically pure to the formula.
    # I'll stick to the logic: R = W * Q * V * I * T
    
    print(f"   > Inputs: Quality={factors.Q}, Verified={factors.V}, Impact={factors.I}, Trust={factors.T}, Weight={factors.W}")
    print(f"   > Calculated Reputation Score: {Colors.GREEN}{score}{Colors.ENDC}")

    # --- Step 7: Blockchain Commit ---
    print_section("7. Committing to Blockchain Ledger")
    print_step(7, "Mining new block with contribution data...")
    
    new_block = reputation_chain.add_block(
        developer_id=dev_alice.id,
        contribution_hash=contrib_hash,
        reputation_score=score,
        signature=signature
    )
    
    print(f"   > Block #{new_block.index} mined!")
    print(f"   > Block Hash: {new_block.hash}")
    print(f"   > Previous Hash: {new_block.previous_hash}")

    # --- Step 8: Ledger Display ---
    print_section("8. Final Blockchain Ledger")
    print(f"{Colors.CYAN}JSON Dump of Immutable Record:{Colors.ENDC}")
    print(reputation_chain.to_json())

if __name__ == "__main__":
    main()
