#![no_main]

use quad_tree_core::QuadTreeMembershipProof;
use pico_sdk::io::{commit, read_as};

pico_sdk::entrypoint!(main);

/// This program runs inside the Pico zkVM
/// It verifies a quaternary tree membership proof WITHOUT revealing the leaf index
///
/// Inputs (private):
/// - QuadTreeMembershipProof containing leaf_index, leaf_hash, sibling_hashes
///
/// Outputs (public):
/// - root_hash: The root of the tree (public)
/// - is_valid: Whether the proof is valid (public)
pub fn main() {
    // Read the membership proof from stdin
    let proof: QuadTreeMembershipProof = read_as();

    // Verify the proof by reconstructing the root hash
    // This computation happens inside the zkVM and is cryptographically proven
    let is_valid = proof.verify();

    // Commit public outputs that are visible to verifiers
    commit(&proof.root_hash);
    commit(&is_valid);

    // If the proof is invalid, panic to ensure only valid proofs generate certificates
    if !is_valid {
        panic!("Invalid quaternary tree membership proof");
    }

    // SUCCESS: We've proven in zero-knowledge that:
    // 1. We know a valid leaf in the tree
    // 2. The leaf hashes match the claimed path
    // 3. The tree root matches the public value
    // 4. WITHOUT revealing the leaf position (path stays hidden)
}
