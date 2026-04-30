//! AuditChain Exam Log — Contract Tests
//!
//! Five tests covering the full MVP transaction flow, failure modes,
//! and on-chain state correctness — mirroring the RespondIT scenario
//! where CLBService anchors BlockedEvents hashes during an exam session
//! at San Beda University's 7th-floor St. Anselm labs.

#[cfg(test)]
mod tests {
    use soroban_sdk::{
        testutils::{Address as _, BytesN as _},
        Address, BytesN, Env, String,
    };

    use crate::{AuditChainContract, AuditChainContractClient};

    // -----------------------------------------------------------------------
    // Shared helpers
    // -----------------------------------------------------------------------

    /// Deploy the contract, initialize it with the given authority, and return
    /// a ready-to-use client — mirrors the ICTC admin running `soroban contract deploy`
    /// before the first exam session of the semester.
    fn setup(env: &Env, authority: &Address) -> AuditChainContractClient {
        let contract_id = env.register_contract(None, AuditChainContract);
        let client = AuditChainContractClient::new(env, &contract_id);
        client.init(authority);
        client
    }

    /// Produce a deterministic 32-byte hash from a u8 seed value — simulates
    /// SHA-256(seat_id + mac + event_type + timestamp) computed by CLBService.
    fn mock_hash(env: &Env, seed: u8) -> BytesN<32> {
        BytesN::from_array(env, &[seed; 32])
    }

    /// Seat identifier string — matches the CLBService seat_id format used in
    /// the RespondIT architecture (lab label + seat number).
    fn seat(env: &Env, label: &str) -> String {
        String::from_str(env, label)
    }

    // -----------------------------------------------------------------------
    // TEST 1 — Happy path
    // End-to-end MVP: CLBService anchors one BlockedEvents entry (Alt+F4 attempt
    // from Seat LAB_A-3B) and the entry is immediately verifiable on-chain.
    // -----------------------------------------------------------------------
    #[test]
    fn test_anchor_and_verify_happy_path() {
        let env = Env::default();
        env.mock_all_auths(); // CLBService authority signs the anchor call

        let authority = Address::generate(&env);
        let client = setup(&env, &authority);

        // Simulate: student at LAB_A-3B pressed Alt+F4; CLBService blocked it,
        // computed SHA-256, and calls anchor_event().
        let hash = mock_hash(&env, 0xAF); // 0xAF → mnemonic for "Alt+F4"
        let seat_id = seat(&env, "LAB_A-3B");
        let event_ts: u64 = 1_700_000_000; // Unix timestamp from CLBService clock

        let returned_index = client.anchor_event(&authority, &hash, &seat_id, &event_ts);

        // The contract assigns the first entry index 0.
        assert_eq!(returned_index, 0, "first anchored entry should have index 0");

        // Verify: proctor pastes the SHA-256 into the dashboard → contract confirms.
        let entry = client.verify_event(&hash);
        assert_eq!(entry.event_hash, hash, "stored hash must match submitted hash");
        assert_eq!(entry.seat_id, seat_id, "seat_id must be preserved exactly");
        assert_eq!(
            entry.event_timestamp, event_ts,
            "original event timestamp must be preserved"
        );
        assert_eq!(entry.entry_index, 0, "entry_index must equal returned_index");
        // ledger_sequence is set by the environment — just assert it is non-zero.
        assert!(
            entry.ledger_sequence > 0,
            "ledger_sequence must be set by the Stellar network"
        );
    }

    // -----------------------------------------------------------------------
    // TEST 2 — Unauthorized caller is rejected
    // An attacker (or a misconfigured second CLBService instance) without the
    // authority keypair cannot write to the on-chain log — preserving the
    // integrity of the evidence record against forged entries.
    // -----------------------------------------------------------------------
    #[test]
    #[should_panic(expected = "unauthorized")]
    fn test_anchor_rejected_for_unauthorized_caller() {
        let env = Env::default();
        env.mock_all_auths();

        let authority = Address::generate(&env);
        let attacker = Address::generate(&env); // different address — not the authority
        let client = setup(&env, &authority);

        let hash = mock_hash(&env, 0x01);
        let seat_id = seat(&env, "LAB_B-01");
        let event_ts: u64 = 1_700_000_100;

        // This call uses `attacker` as the submitter — must panic with "unauthorized".
        client.anchor_event(&attacker, &hash, &seat_id, &event_ts);
    }

    // -----------------------------------------------------------------------
    // TEST 3 — Duplicate hash is rejected
    // CLBService may retry a failed Horizon submission. The contract must
    // detect the duplicate and reject it rather than creating two entries for
    // the same BlockedEvents record — which would confuse audit counts.
    // -----------------------------------------------------------------------
    #[test]
    #[should_panic(expected = "duplicate")]
    fn test_duplicate_hash_anchor_is_rejected() {
        let env = Env::default();
        env.mock_all_auths();

        let authority = Address::generate(&env);
        let client = setup(&env, &authority);

        let hash = mock_hash(&env, 0xDD); // 0xDD → "duplicate"
        let seat_id = seat(&env, "LAB_C-05");
        let event_ts: u64 = 1_700_000_200;

        // First anchor succeeds.
        client.anchor_event(&authority, &hash, &seat_id, &event_ts);

        // Second anchor of the same hash must panic with "duplicate".
        // This simulates CLBService retrying a submission it thinks failed.
        client.anchor_event(&authority, &hash, &seat_id, &event_ts);
    }

    // -----------------------------------------------------------------------
    // TEST 4 — On-chain state is correct after multiple anchors
    // A full exam session at LAB_A generates three BlockedEvents entries:
    // an Alt+F4 attempt, a Ctrl+Shift+I (DevTools) attempt, and a Sticky
    // Keys spam pattern. All three are anchored; state is verified in full.
    // -----------------------------------------------------------------------
    #[test]
    fn test_state_is_correct_after_multiple_anchors() {
        let env = Env::default();
        env.mock_all_auths();

        let authority = Address::generate(&env);
        let client = setup(&env, &authority);

        // Three distinct blocked events from one exam session.
        let events: &[(u8, &str, u64)] = &[
            (0xAF, "LAB_A-3B", 1_700_000_000), // Alt+F4 attempt
            (0xCD, "LAB_A-3B", 1_700_000_060), // Ctrl+Shift+I (DevTools)
            (0x5C, "LAB_A-3B", 1_700_000_120), // Sticky Keys spam (5× Shift in 2s)
        ];

        for (seed, seat_label, ts) in events {
            let hash = mock_hash(&env, *seed);
            let seat_id = seat(&env, seat_label);
            client.anchor_event(&authority, &hash, &seat_id, ts);
        }

        // 1. Total count must equal the number of anchored events.
        assert_eq!(
            client.get_count(),
            3,
            "entry count must equal the number of successful anchor_event calls"
        );

        // 2. Each entry is retrievable by index and carries the correct data.
        let first = client.get_entry(&0);
        assert_eq!(first.event_hash, mock_hash(&env, 0xAF));
        assert_eq!(first.event_timestamp, 1_700_000_000);
        assert_eq!(first.entry_index, 0);

        let third = client.get_entry(&2);
        assert_eq!(third.event_hash, mock_hash(&env, 0x5C));
        assert_eq!(third.event_timestamp, 1_700_000_120);
        assert_eq!(third.entry_index, 2);

        // 3. Reverse lookup via verify_event() works for every anchored hash.
        for (seed, _, ts) in events {
            let hash = mock_hash(&env, *seed);
            let entry = client.verify_event(&hash);
            assert_eq!(entry.event_timestamp, *ts);
        }
    }

    // -----------------------------------------------------------------------
    // TEST 5 — Authority transfer works and old authority is revoked
    // At semester rollover, ICTC rotates the CLBService keypair. The old
    // authority transfers control to the new keypair. After transfer:
    //   - New authority can anchor events.
    //   - Old authority is rejected.
    // -----------------------------------------------------------------------
    #[test]
    fn test_authority_transfer_and_revocation() {
        let env = Env::default();
        env.mock_all_auths();

        let old_authority = Address::generate(&env);
        let new_authority = Address::generate(&env);
        let client = setup(&env, &old_authority);

        // Old authority anchors one entry before the key rotation.
        let pre_rotation_hash = mock_hash(&env, 0x01);
        client.anchor_event(
            &old_authority,
            &pre_rotation_hash,
            &seat(&env, "LAB_A-01"),
            &1_700_000_000_u64,
        );

        // ICTC rotates the keypair — transfers authority to the new address.
        client.transfer_authority(&old_authority, &new_authority);

        // Confirm the contract now reports the new authority.
        assert_eq!(
            client.get_authority(),
            new_authority,
            "get_authority() must return the new address after transfer"
        );

        // New authority can anchor a post-rotation entry successfully.
        let post_rotation_hash = mock_hash(&env, 0x02);
        let new_index = client.anchor_event(
            &new_authority,
            &post_rotation_hash,
            &seat(&env, "LAB_A-01"),
            &1_700_001_000_u64,
        );
        assert_eq!(
            new_index, 1,
            "new authority should anchor at index 1 after the pre-rotation entry"
        );

        // Total count reflects both entries (pre- and post-rotation).
        assert_eq!(client.get_count(), 2, "count must include pre- and post-rotation entries");

        // Old authority attempting to anchor after revocation must be rejected.
        let result = std::panic::catch_unwind(|| {
            // We call directly — the env has mock_all_auths so signature is not
            // the gating factor here; the address equality check is.
            // Re-setup env for the panic test to avoid state contamination.
            let env2 = Env::default();
            env2.mock_all_auths();
            let old2 = Address::generate(&env2);
            let new2 = Address::generate(&env2);
            let client2 = setup(&env2, &old2);
            client2.transfer_authority(&old2, &new2);
            // old2 tries to anchor — must panic
            client2.anchor_event(
                &old2,
                &mock_hash(&env2, 0xFF),
                &seat(&env2, "LAB_A-01"),
                &1_700_002_000_u64,
            );
        });
        assert!(
            result.is_err(),
            "revoked old authority must not be able to anchor new events"
        );
    }
}