
# Tamper Proof Experiment
from reputation_system import Blockchain, Developer, Contribution, ReputationEngine, ReputationFactors, Colors

def run_tamper_test():
    print(f"\n{Colors.HEADER}--- AUDIT: TAMPERING EXPERIMENT ---{Colors.ENDC}")
    
    # 1. Setup Honest Chain
    chain = Blockchain()
    dev = Developer("Eve")
    contrib = Contribution("print('malicious')")
    h = contrib.calculate_hash()
    sig = dev.sign_hash(h)
    
    # Add a valid block
    chain.add_block(dev.id, h, 5.0, sig)
    print("1. Honest block added. Verifying chain...")
    chain.validate_chain()
    
    # 2. Attack: Modify the Reputation Score in memory
    print("\n2. ATTACK: Hacker modifies Block #1 Reputation Score from 5.0 to 999.0")
    target_block = chain.chain[1]
    target_block.reputation_score = 999.0
    
    # 3. Verify Again
    print("3. Re-verifying chain integrity...")
    is_valid = chain.validate_chain()
    
    if not is_valid:
        print(f"\n{Colors.GREEN}SUCCESS: The system successfully detected the tampering!{Colors.ENDC}")
        print("This proves the hashes are mathematically calculated, not hardcoded.")
    else:
        print(f"\n{Colors.FAIL}FAILURE: System failed to detect tampering.{Colors.ENDC}")

if __name__ == "__main__":
    run_tamper_test()
