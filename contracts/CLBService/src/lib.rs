//! AuditChain Exam Log — Soroban Smart Contract
//!
//! Anchors SHA-256 hashes of RespondIT BlockedEvents entries onto the
//! Stellar ledger, making exam security evidence tamper-proof and
//! independently verifiable by any party — including those contesting
//! an academic integrity ruling — without storing any student PII on-chain.
//!
//! Architecture note:
//! CLBService computes SHA-256(event_fields) locally, then calls
//! anchor_event() via Stellar Horizon REST API. The returned transaction
//! hash is stored alongside the original Firebase log entry, creating a
//! cryptographic link between the human-readable dashboard record and its
//! immutable on-chain proof.

#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short,
    Address, BytesN, Env, String,
};

// ---------------------------------------------------------------------------
// Storage types
// ---------------------------------------------------------------------------

/// A single anchored BlockedEvents record.
/// Stored on-chain — contains NO student PII, only machine/session identifiers.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct AnchorEntry {
    /// SHA-256 hash of the BlockedEvents record fields
    /// (seat_id + mac_address + event_type + original_timestamp).
    /// This is what ties the on-chain proof to the Firebase log row.
    pub event_hash: BytesN<32>,

    /// Human-readable seat identifier, e.g. "LAB_A-3B".
    /// Matches the CLBService seat_id field — identifies the machine, not the student.
    pub seat_id: String,

    /// Unix timestamp (seconds) of the original event as recorded by CLBService.
    /// Distinct from ledger_sequence: the event may have been queued offline
    /// and submitted later, so both timestamps are preserved for transparency.
    pub event_timestamp: u64,

    /// Stellar ledger sequence number at the moment this transaction closed.
    /// Provides an independent, blockchain-native time reference that cannot
    /// be retroactively altered by the institution.
    pub ledger_sequence: u32,

    /// Sequential index of this entry within the contract's log.
    /// Allows ordered retrieval for full-session audit export.
    pub entry_index: u32,
}

/// Storage key namespace — keeps all contract data well-organized and avoids
/// key collisions between the different data types we persist.
#[contracttype]
pub enum DataKey {
    /// The Stellar address of the CLBService account authorized to anchor events.
    /// Only this address may call anchor_event(). Rotatable via transfer_authority().
    Authority,

    /// Running count of anchored entries. Used as the next entry_index.
    EntryCount,

    /// Primary entry store: sequential index → AnchorEntry.
    /// Enables ordered full-log export during disciplinary proceedings.
    Entry(u32),

    /// Reverse lookup: event_hash → entry_index.
    /// Enables O(1) verification given only the hash — the most common audit query.
    HashIndex(BytesN<32>),
}

// ---------------------------------------------------------------------------
// Contract
// ---------------------------------------------------------------------------

#[contract]
pub struct AuditChainContract;

#[contractimpl]
impl AuditChainContract {
    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------

    /// Initialize the contract with the address of the CLBService authority.
    /// Must be called exactly once immediately after deployment.
    /// The authority is the Stellar keypair held by the RespondIT CLBService
    /// process — it is the only account that may anchor new events.
    ///
    /// # Panics
    /// - If the contract has already been initialized.
    pub fn init(env: Env, authority: Address) {
        // Guard against re-initialization — storage key presence is the flag.
        if env.storage().instance().has(&DataKey::Authority) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Authority, &authority);
        env.storage().instance().set(&DataKey::EntryCount, &0u32);

        // Extend instance TTL so the contract remains live across exam periods.
        env.storage()
            .instance()
            .extend_ttl(17_280, 17_280); // ~1 day at ~5s/ledger
    }

    // -----------------------------------------------------------------------
    // Core anchoring
    // -----------------------------------------------------------------------

    /// Anchor a BlockedEvents entry hash permanently on-chain.
    ///
    /// Called by CLBService immediately after writing to Firebase.
    /// The third parallel write in the BlockedEvents pipeline:
    ///   1. Local hidden log file   (always)
    ///   2. Firebase CLBLogs/       (real-time dashboard)
    ///   3. Soroban anchor_event()  (tamper-proof non-repudiation)  ← this function
    ///
    /// # Arguments
    /// * `submitter`        — must equal the stored authority address
    /// * `event_hash`       — SHA-256(seat_id + mac + event_type + timestamp)
    /// * `seat_id`          — machine identifier, e.g. "LAB_B-07"
    /// * `event_timestamp`  — original Unix timestamp from CLBService clock
    ///
    /// # Returns
    /// The sequential entry_index assigned to this anchor (useful for receipt logging).
    ///
    /// # Panics
    /// - If `submitter` is not the stored authority.
    /// - If `event_hash` has already been anchored (prevents duplicate submissions).
    pub fn anchor_event(
        env: Env,
        submitter: Address,
        event_hash: BytesN<32>,
        seat_id: String,
        event_timestamp: u64,
    ) -> u32 {
        // 1. Authorization check — only CLBService may write to the ledger.
        let authority: Address = env
            .storage()
            .instance()
            .get(&DataKey::Authority)
            .expect("contract not initialized");

        if submitter != authority {
            panic!("unauthorized: only the CLBService authority account may anchor events");
        }
        // Require the submitter to have signed this transaction.
        submitter.require_auth();

        // 2. Idempotency guard — each unique event hash may only be anchored once.
        //    Protects against CLBService retry storms after connectivity drops.
        if env
            .storage()
            .persistent()
            .has(&DataKey::HashIndex(event_hash.clone()))
        {
            panic!("duplicate: this event_hash is already anchored on-chain");
        }

        // 3. Assign sequential index and build the on-chain record.
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::EntryCount)
            .unwrap_or(0);
        let entry_index = count;

        let entry = AnchorEntry {
            event_hash: event_hash.clone(),
            seat_id,
            event_timestamp,
            // Stellar ledger sequence — blockchain-native timestamp, independently verifiable.
            ledger_sequence: env.ledger().sequence(),
            entry_index,
        };

        // 4. Persist with TTL extension.
        //    ~34,560 ledgers ≈ 2 days at ~5s/ledger — adjust for production retention.
        env.storage()
            .persistent()
            .set(&DataKey::Entry(entry_index), &entry);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::Entry(entry_index), 34_560, 34_560);

        // Reverse lookup allows O(1) verify_event() calls during proceedings.
        env.storage()
            .persistent()
            .set(&DataKey::HashIndex(event_hash.clone()), &entry_index);
        env.storage()
            .persistent()
            .extend_ttl(&DataKey::HashIndex(event_hash), 34_560, 34_560);

        // 5. Increment the global entry counter.
        env.storage()
            .instance()
            .set(&DataKey::EntryCount, &(count + 1));

        env.storage()
            .instance()
            .extend_ttl(17_280, 17_280);

        // Return the assigned index — CLBService logs this as the on-chain receipt.
        entry_index
    }

    // -----------------------------------------------------------------------
    // Verification (public — anyone can call, no auth required)
    // -----------------------------------------------------------------------

    /// Verify that a specific event hash exists on-chain.
    ///
    /// This is the function a proctor or disciplinary board calls during a
    /// proceeding. Given the SHA-256 hash recomputed from the Firebase log
    /// fields, it returns the full AnchorEntry, proving the record existed
    /// at the stated ledger sequence and event timestamp.
    ///
    /// Anyone with internet access can call this — no keys required.
    ///
    /// # Panics
    /// - If no entry for this hash exists (hash was never anchored or has expired).
    pub fn verify_event(env: Env, event_hash: BytesN<32>) -> AnchorEntry {
        let index: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::HashIndex(event_hash))
            .expect("not found: no on-chain record for this event hash");

        env.storage()
            .persistent()
            .get(&DataKey::Entry(index))
            .expect("storage inconsistency: hash index points to missing entry")
    }

    /// Retrieve an anchored entry by its sequential index.
    /// Useful for exporting a full ordered audit log for a given session.
    ///
    /// # Panics
    /// - If no entry exists at the given index.
    pub fn get_entry(env: Env, index: u32) -> AnchorEntry {
        env.storage()
            .persistent()
            .get(&DataKey::Entry(index))
            .expect("entry not found at this index")
    }

    /// Returns the total number of anchored entries across all sessions.
    /// A monotonically increasing counter — never decrements.
    pub fn get_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::EntryCount)
            .unwrap_or(0)
    }

    // -----------------------------------------------------------------------
    // Authority management
    // -----------------------------------------------------------------------

    /// Transfer the anchoring authority to a new Stellar address.
    /// Used when CLBService keypair is rotated (e.g. after a security audit
    /// or when a new semester's CLBSecuritySuite config is pushed).
    ///
    /// # Panics
    /// - If `current_authority` does not match the stored authority address.
    pub fn transfer_authority(
        env: Env,
        current_authority: Address,
        new_authority: Address,
    ) {
        let stored: Address = env
            .storage()
            .instance()
            .get(&DataKey::Authority)
            .expect("contract not initialized");

        if current_authority != stored {
            panic!("unauthorized: only the current authority may transfer control");
        }
        // Require signature from the current authority account.
        current_authority.require_auth();

        env.storage()
            .instance()
            .set(&DataKey::Authority, &new_authority);

        env.storage()
            .instance()
            .extend_ttl(17_280, 17_280);
    }

    /// Returns the current authority address.
    /// Public — allows anyone to confirm which CLBService account is trusted.
    pub fn get_authority(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Authority)
            .expect("contract not initialized")
    }
}

// Pull in the test module when building under test configuration.
#[cfg(test)]

mod test;