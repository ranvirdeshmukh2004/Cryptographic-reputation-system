# Cryptographic Reputation System

A decentralized reputation system prototype built in Python. This project demonstrates the usage of cryptography and a blockchain-based ledger to securely track, verify, and store developer code contributions while calculating a reputation score.

## Features
- **Identity Generation**: Uses 2048-bit RSA key pairs to create secure developer identities (Public/Private Keys).
- **Contribution Hashing**: Generates SHA-256 hashes for source code contributions to create unique digital fingerprints.
- **Digital Signatures**: Signs contributions using RSA-PSS padding to ensure authenticity and non-repudiation.
- **Reputation Engine**: Calculates and assigns reputation scores based on various factors like quality, verification boolean, impact, and trust.
- **Blockchain Ledger**: Stores contribution transactions in an immutable, serialized blockchain structure linked by previous hashes.
- **Tamper Verification**: Built-in mechanisms to validate the integrity of the entire blockchain and detect malicious alterations in historical data.

## Getting Started

### Prerequisites

You will need Python 3.7+ installed. The project relies on the `cryptography` Python package.

Install the required dependency using:
```bash
pip install cryptography
```

### Usage

**1. Main System Simulation**

Run the main file to start the interactive workflow simulation:

```bash
cd "Reputation management system"
python reputation_system.py
```

This script will guide you step-by-step through:
- Registering a new developer.
- Submitting a sample code contribution.
- Hashing the code and cryptographically signing the contribution hash.
- Verifying the signature against the developer's public key.
- Generating a calculated reputation score.
- Mining a new ledger block to securely persist the exact state.

**2. Audit / Tamper Experiment Test**

To witness the tamper-detection mechanisms in action, run the experiment script:

```bash
cd "Reputation management system"
python verify_authenticity.py
```

This file sets up an honest chain, simulates a malicious memory attack that artificially changes a block's reputation score, and then demonstrates how the blockchain validates and rejects the broken chain integrity.

## Project Structure
- `Reputation management system/reputation_system.py`: Contains the core implementation including Identity Modules, the Developer class, the Signature Verifier, and the Blockchain Ledger structure.
- `Reputation management system/verify_authenticity.py`: A separate audit script utilized to run tampering experiments.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
