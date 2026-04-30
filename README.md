# CLBService Exam Log

**CLBService Exam Log** - Blockchain-Based Tamper-Proof Academic Integrity Evidence System

## Project Description

CLBService Exam Log is a decentralized smart contract solution built on the Stellar blockchain using Soroban SDK. It provides a secure, immutable platform for anchoring SHA-256 hashes of RespondIT BlockedEvents entries directly on the Stellar ledger. The contract ensures that exam security evidence is stored transparently and is independently verifiable by any party — including students contesting an academic integrity ruling — without storing any student PII on-chain.

The system is the third parallel write in the RespondIT CLBService BlockedEvents pipeline: after writing to a local hidden log file and Firebase, CLBService calls `anchor_event()` to permanently anchor a cryptographic hash on-chain. Each anchored entry is uniquely indexed and linked to its Firebase counterpart via a SHA-256 hash, creating a tamper-proof bridge between the human-readable dashboard record and its immutable on-chain proof.

## Project Vision

Our vision is to close the non-repudiation gap in institutional exam security by:

- **Anchoring Evidence On-Chain**: Moving exam security audit logs from mutable, institution-controlled databases to the immutable Stellar ledger
- **Protecting Student Rights**: Empowering students to independently verify that a BlockedEvents record has not been altered after the fact — without trusting the institution's own servers
- **Guaranteeing Integrity**: Providing a permanent, cryptographically verifiable record of every blocked event that cannot be quietly edited before a disciplinary proceeding
- **Preserving Privacy**: No student PII is stored on-chain — only machine identifiers (seat_id), SHA-256 hashes, and timestamps are written to the ledger
- **Building Trustless Evidence**: Creating a system where exam security proof is guaranteed by the Stellar ledger itself, not by institutional promises

We envision a future where academic integrity evidence is as trustworthy as the blockchain it lives on — auditable by students, faculty, and regulators alike, with zero reliance on a single institution's data governance.

## Key Features

### 1. **Tamper-Proof Event Anchoring**

- Anchor BlockedEvents hashes with a single `anchor_event()` call
- SHA-256 hash ties the on-chain proof to its Firebase log row
- Sequential entry index for ordered full-session audit export
- Permanent storage on the Stellar blockchain via Soroban persistent storage

### 2. **O(1) Hash Verification**

- Verify any anchored event instantly via `verify_event()`
- Reverse hash-index enables lookup by hash alone — no index required
- Returns full AnchorEntry: seat_id, event_timestamp, ledger_sequence, entry_index
- Callable by anyone with internet access — no keypair required

### 3. **Ordered Audit Log Export**

- Retrieve any entry by sequential index via `get_entry()`
- Monotonically increasing entry counter via `get_count()`
- Enables full ordered session export during disciplinary proceedings
- Ledger sequence provides an independent, blockchain-native time reference

### 4. **Authority Management**

- Only the enrolled CLBService keypair may anchor new events
- `transfer_authority()` allows secure keypair rotation at semester rollover
- `get_authority()` lets anyone confirm which CLBService account is trusted
- Idempotency guard prevents duplicate submissions from CLBService retry storms

### 5. **Stellar Network Integration**

- Leverages the high speed and low cost of Stellar for per-event anchoring
- Built using the modern Soroban Smart Contract SDK
- Persistent and instance storage optimised for audit log access patterns
- Interoperable with RespondIT's existing Firebase and Horizon REST pipeline

## Contract Details

- Contract Address: `CBLU4IUASQ4WUMOXBFLZRSBBLILGOH33GS4LUPKFBCCCMJCDQNMF7G2M`

- Here lie the links required via the bootcamp:

  [1] https://stellar.expert/explorer/testnet/tx/f508d9bb9ffe4208ad4c52fd09fbdc33037e65e496b91c18c9aa599cd4cc5d75

  [2] https://lab.stellar.org/r/testnet/contract/CARGE4ZNRJHKMEVX6X5EIXHJAEEGZ6YRP5PABKKLS5CQBWZBIF37YDQ2

## Future Scope

TBA

### Short-Term Enhancements

1. **Session-Scoped Export**: Bundle all anchored entries for a given exam session into a signed PDF for disciplinary board submission
2. **Dashboard Integration**: Surface `verify_event()` results directly in the RespondIT real-time monitoring dashboard
3. **Retry Queue**: CLBService offline queue that batches missed anchors and submits them once connectivity is restored
4. **Event-Type Filtering**: Extend AnchorEntry to include an event_type field for filtering by violation category (Alt+F4, DevTools, Sticky Keys, etc.)

### Medium-Term Development

5. **Multi-Lab Support**: Extend authority model to support per-lab CLBService keypairs with a shared audit registry
   - Lab-scoped entry namespacing
   - Per-lab authority delegation
   - Cross-lab session correlation
6. **Horizon Webhook Bridge**: Off-chain bridge that listens for new anchor transactions and triggers real-time dashboard alerts
7. **Proctor Report Generation**: Automated structured report triggered by `get_entry()` range queries for post-exam review
8. **Inter-Contract Integration**: Allow the CLBService grade management contract to reference CLBService entries as evidence during automated integrity checks

### Long-Term Vision

9. **Cross-Institution Anchoring**: Extend the anchoring model to a shared Stellar contract usable by multiple universities
10. **Decentralized Dashboard Hosting**: Host the RespondIT monitoring frontend on IPFS for full institutional independence
11. **AI-Powered Anomaly Flagging**: Optional integration with an AI layer to surface unusual patterns across anchored session entries
12. **Zero-Knowledge Verification**: Implement ZK proofs so students can verify their own records without exposing seat or session metadata to third parties
13. **DAO Governance**: Community-driven protocol improvements allowing participating institutions to vote on anchoring policy changes
14. **Decentralized Identity Binding**: Optional integration with DID systems to bind seat_id to an institution-issued pseudonymous credential

### Enterprise Features

15. **University-Wide Deployment**: Adapt the contract for institution-wide exam integrity infrastructure across all departments
16. **Immutable Compliance Logs**: Time-locked anchor entries for regulatory audit and accreditation evidence
17. **Automated Incident Reporting**: Trigger structured incident reports on-chain when a configurable threshold of BlockedEvents is exceeded in a session
18. **Multi-Language Dashboard**: Expand accessibility of the verification interface with internationalization support

---

## Technical Requirements

- Soroban SDK `22.0.0`
- Rust programming language (`wasm32-unknown-unknown` target)
- Stellar blockchain network (testnet for development, mainnet for production)

## Getting Started

### Prerequisites

Install the Rust toolchain and add the Wasm target:

```bash
rustup target add wasm32-unknown-unknown
```

Install the Soroban CLI (version `22.x`):

```bash
cargo install --locked soroban-cli
```

### How to Build

```bash
soroban contract build
```

Output: `target/wasm32-unknown-unknown/release/clbservice.wasm`

### How to Test

```bash
cargo test
```

All five tests run against `Env::default()` with `mock_all_auths()` — no network required.

```
test tests::test_anchor_and_verify_happy_path              ... ok
test tests::test_anchor_rejected_for_unauthorized_caller   ... ok
test tests::test_duplicate_hash_anchor_is_rejected         ... ok
test tests::test_state_is_correct_after_multiple_anchors   ... ok
test tests::test_authority_transfer_and_revocation         ... ok

test result: ok. 5 passed; 0 failed
```

### How to Deploy to Testnet

```bash
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/clbservice.wasm \
  --source <YOUR_SECRET_KEY> \
  --network testnet
```

Save the returned `<CONTRACT_ID>` — it is required for all subsequent CLI calls.

### Initialize the Contract (run once after deploy)

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source <YOUR_SECRET_KEY> \
  --network testnet \
  -- init \
  --authority GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12
```

### Sample CLI Invocations

Deploy the smart contract to Stellar's Soroban network and interact with it using the four main functions:

**`anchor_event()`** — Anchor a BlockedEvents SHA-256 hash on-chain (called by CLBService)

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --source <YOUR_SECRET_KEY> \
  --network testnet \
  -- anchor_event \
  --submitter GABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF12 \
  --event_hash aabbccddeeff00112233445566778899aabbccddeeff001122334455667788 \
  --seat_id "LAB_A-3B" \
  --event_timestamp 1700000000
```

**`verify_event()`** — Verify a BlockedEvents entry exists on-chain (callable by anyone)

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --network testnet \
  -- verify_event \
  --event_hash aabbccddeeff00112233445566778899aabbccddeeff001122334455667788
```

**`get_entry()`** — Retrieve a specific entry by sequential index

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --network testnet \
  -- get_entry \
  --index 0
```

**`get_count()`** — Return the total number of anchored entries

```bash
soroban contract invoke \
  --id <CONTRACT_ID> \
  --network testnet \
  -- get_count
```

---

**CLBService Exam Log** - Securing Exam Integrity Evidence on the Blockchain

---

## License

MIT License

abc