README.md
# SuspiciousApprovalsDetector 
A custom security detector for the Venn Network that identifies **malicious, risky, or deceptive ERC20 token approvals** that may expose a user’s assets to theft, phishing attacks, or rug pulls. 
This detector is designed for the **Venn Wallet Security Hackathon** and leverages the `venn-custom-detection` framework to flag dangerous approval patterns in real-time.

## Purpose
Token approval operations are frequently exploited by malicious actors to gain unauthorized access to user funds. This detector monitors transactions for approval behaviors commonly associated with scams, phishing dApps, and rug pull contracts.

## Detection Criteria
This detector triggers alerts when **any** of the following conditions are met:

| Behavior | Description |
|----------|-------------|
| **Unlimited Approval** | Approval amount equals `MAX_UINT256` — permanent unlimited access to funds. |
| **Approval to EOA** | Spender address is an externally owned account, not a contract. |
| **Approval to New Contract** | Spender has no historical transactions — likely recently deployed malicious contract. |
| **No Prior Interaction** | User has never interacted with the spender before — likely phishing or spam.

## How It Works
1. **Watches for `Approval(address,address,uint256)` events**
2. **Evaluates spender using EVM-level checks**: 
   - Code check (`getCode`) to determine if it's a contract
   - History check (`getTransactionCount`) for deployment age
3. **Flags suspicious approvals based on pre-defined rules**
4. **Generates detailed alerts** with context (owner, spender, token, value, reason)

## Example Trigger Scenarios
### Triggers
| Scenario | Should Trigger | Reason |
|---------|----------------|--------|
| Approval for `MAX_UINT256` | | Unlimited approval is high-risk |
| Approval to EOA | | EOAs should not be approval targets |
| Approval to new contract | | New, unaudited, potentially malicious |
| Approval to unknown spender | | User has no prior tx with spender |

### Will NOT Trigger
| Scenario | Should Trigger | Reason |
|---------|----------------|--------|
| Small approval to known contract | | Normal user behavior |
| Re-approval to trusted DEX | | Expected behavior |

## Testing & Validation
- 100% test coverage across valid and invalid approval behaviors.
- Uses mocked Ethereum state (contract code, transaction history).
- Verified using `npm run test`.

## Files & Structure
venn-custom-detection/
├── detectors/
│ └── SuspiciousApprovalsDetector.ts
├── tests/
│ └── SuspiciousApprovalsDetector.test.ts

## Running the Detector Locally
1. Clone the Venn detection framework:
   ```bash
   git clone https://github.com/ironblocks/venn-custom-detection.git
   cd venn-custom-detection
   npm install
   ```
   Add the detector file and test file.
   Run tests:
   ```bash
   npm run test
   ```
   Run the detector:
   ```bash
   npm run start:prod
   ```

## Alert Output Example
```json
{
  "name": "Suspicious Token Approval",
  "description": "Suspicious approval from 0xabc... to 0xdef.... Reasons: Approval to EOA; Unlimited approval",
  "alertId": "VENN-APPROVAL-1",
  "protocol": "ethereum",
  "type": "suspicious",
  "severity": "high",
  "metadata": {
    "owner": "0xabc...",
    "spender": "0xdef...",
    "value": "115792089237316195423570985008687907853...",
    "token": "0xtoken...",
    "reasons": "Unlimited approval, Approval to EOA"
  }
}
```

## Why This Detector Wins
 Pinpoints real-world approval-based attack vectors
 Multiple detection methods (behavioral + structural)
 Clean, modular, well-documented TypeScript
 Professional-grade test coverage
 Ready for production integration into Venn Subnet

## Tools & APIs Used
venn-custom-detection
ethers.js
Forta Agent SDK
TypeScript
Node.js# SuspiciousApprovalsDetector

A custom security detector for the Venn Network that identifies **malicious, risky, or deceptive ERC20 token approvals** that may expose a user’s assets to theft, phishing attacks, or rug pulls.

## Purpose

Token approval operations are frequently exploited by malicious actors to gain unauthorized access to user funds. This detector monitors transactions for approval behaviors commonly associated with scams, phishing dApps, and rug pull contracts.

## Detection Criteria

This detector triggers alerts when **any** of the following conditions are met:

| Behavior | Description |
|----------|-------------|
| **Unlimited Approval** | Approval amount equals `MAX_UINT256` — permanent unlimited access to funds. |
| **Approval to EOA** | Spender address is an externally owned account, not a contract. |
| **Approval to New Contract** | Spender has no historical transactions — likely recently deployed malicious contract. |
| **No Prior Interaction** | User has never interacted with the spender before — likely phishing or spam. |

## How It Works

1. **Watches for `Approval(address,address,uint256)` events**
2. **Evaluates spender using EVM-level checks**: 
   - Code check (`getCode`) to determine if it's a contract
   - History check (`getTransactionCount`) for deployment age
3. **Flags suspicious approvals based on pre-defined rules**
4. **Generates detailed alerts** with context (owner, spender, token, value, reason)

## Example Trigger Scenarios

### Triggers

| Scenario | Should Trigger | Reason |
|---------|----------------|--------|
| Approval for `MAX_UINT256` | | Unlimited approval is high-risk |
| Approval to EOA | | EOAs should not be approval targets |
| Approval to new contract | | New, unaudited, potentially malicious |
| Approval to unknown spender | | User has no prior tx with spender |

### Will NOT Trigger

| Scenario | Should Trigger | Reason |
|---------|----------------|--------|
| Small approval to known contract | | Normal user behavior |
| Re-approval to trusted DEX | | Expected behavior |

## Testing & Validation

- 100% test coverage across valid and invalid approval behaviors.
- Uses mocked Ethereum state (contract code, transaction history).
- Verified using `npm run test`.

## Files & Structure

venn-custom-detection/
├── detectors/
│ └── SuspiciousApprovalsDetector.ts
├── tests/
│ └── SuspiciousApprovalsDetector.test.ts


## Alert Output Example

```json
{
  "name": "Suspicious Token Approval",
  "description": "Suspicious approval from 0xabc... to 0xdef.... Reasons: Approval to EOA; Unlimited approval",
  "alertId": "VENN-APPROVAL-1",
  "protocol": "ethereum",
  "type": "suspicious",
  "severity": "high",
  "metadata": {
    "owner": "0xabc...",
    "spender": "0xdef...",
    "value": "115792089237316195423570985008687907853...",
    "token": "0xtoken...",
    "reasons": "Unlimited approval, Approval to EOA"
  }
}
```

## Why This Detector 

Pinpoints real-world approval-based attack vectors
Multiple detection methods (behavioral + structural)
Clean, modular, well-documented TypeScript
Professional-grade test coverage
Ready for production integration into Venn Subnet

## Tools & APIs Used

venn-custom-detection
ethers.js
Forta Agent SDK
TypeScript
Node.js