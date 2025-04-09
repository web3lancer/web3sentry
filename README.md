# Web3Sentry - Security Detection System

Web3Sentry is a modular Python-based security detection system for Web3lancer. It provides custom security detectors that can be easily deployed to any server and connect to an API.

## Features

- **Multisig Protection Custom Detector**: Enhances security for multisig wallets by detecting unusual signing patterns or unauthorized attempts
- **Approvals Custom Detector**: Identifies malicious/risky/deceptive approvals that could give attackers access to user assets
- **Modular Architecture**: Easily extensible with additional detectors
- **API Integration**: Simple integration with Web3lancer platform components

## Architecture

The system consists of:

1. **Base Detector**: Abstract class defining the detector interface
2. **Specialized Detectors**: Implementation of specific security detectors
3. **Detector Service**: Manages and coordinates detector operations
4. **Integration Points**: Connectors to Web3lancer's escrow and voting systems

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/web3lancer.git

# Navigate to the project directory
cd web3lancer

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Integrating with Escrow System

```python
from web3lancer.escrow.escrow_security import EscrowSecurityService

# Initialize the service
escrow_security = EscrowSecurityService()

# Verify an escrow creation
escrow_data = {
    "client_address": "0x123...",
    "escrow_contract_address": "0xabc...",
    "payment_amount": "1000000000000000000",  # 1 ETH
    "token_address": "0xdef...",
    "client_id": "client-1234",
    "is_multisig": True,
    "authorized_signers": ["0x123...", "0x456...", "0x789..."],
    "required_signatures": 2
}

results = await escrow_security.verify_escrow_creation(escrow_data)
print(f"Security assessment: {results['overall_risk']}")
```

### Integrating with Voting System

```python
from web3lancer.voting.voting_security import VotingSecurityService

# Initialize the service
voting_security = VotingSecurityService()

# Verify a proposal creation
proposal_data = {
    "creator_address": "0x123...",
    "voting_contract_address": "0xabc...",
    "creator_id": "user-1234",
    "is_multisig_governance": True,
    "authorized_signers": ["0x123...", "0x456...", "0x789..."],
    "required_signatures": 2
}

results = await voting_security.verify_proposal_creation(proposal_data)
print(f"Security assessment: {results['overall_risk']}")
```

## Custom Detector Development

To create a new detector:

1. Create a new class that inherits from `BaseDetector`
2. Implement the required methods: `analyze()` and `get_detector_info()`
3. Register your detector with the `DetectorService`

```python
from web3sentry.detectors.base_detector import BaseDetector

class MyCustomDetector(BaseDetector):
    def __init__(self):
        super().__init__(
            name="My Custom Detector",
            description="Detects specific security issues"
        )
    
    async def analyze(self, transaction_data):
        # Implement your detection logic here
        return {
            "risk_level": "safe",
            "details": "No issues detected",
            "triggers": []
        }
        
    def get_detector_info(self):
        base_info = super().get_detector_info()
        base_info.update({
            "category": "custom",
            # Add additional metadata
        })
        return base_info
```

## Testing

Run the tests:

```bash
python -m unittest discover
```

## Venn Network Hackathon Integration

This project was designed for the Venn Network Wallet Security Hackathon, focusing on:

1. **Multisig Protection Custom Detector**
2. **Approvals Custom Detector**

Both detectors follow the guidelines provided by the Venn Network, and can plug into Venn's infrastructure as core contributors in their decentralized security network.
