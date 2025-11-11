#![no_main]
#![no_std]

mod getrandom_dummy;

use pico_sdk::io::{commit, read_as};
use quad_tree_core::QuadTreeMembershipProof;

pico_sdk::entrypoint!(main);

/// This program runs inside the Pico zkVM
pub fn main() {
    let proof: QuadTreeMembershipProof = read_as();
    let is_valid = proof.verify();
    commit(&proof.root_hash);
    commit(&is_valid);

    if !is_valid {
        panic!("Invalid quaternary tree membership proof");
    }
}
