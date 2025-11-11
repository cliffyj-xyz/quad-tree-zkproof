# Quaternary Merkle Tree with Zero-Knowledge Membership Proofs

Zero-knowledge membership proof implementation using quaternary (4-way branching) Merkle trees. Proves possession of a leaf without revealing leaf position.

## Structure

Three-package workspace:

- `core`: Quaternary tree index, hashing functions, membership proof verification
- `guest`: zkVM program for proof generation (runs inside Pico RISC-V zkVM)
- `host`: Tree construction, proof generation, test harness

## What This Does

Given a tree with N leaves containing ML-KEM-768 public keys:

1. Prover constructs quaternary Merkle tree
2. Prover generates membership proof for specific leaf
3. Guest program verifies proof inside Pico zkVM
4. Verification produces public outputs: root hash, validity boolean
5. Leaf position remains private (not committed publicly)

## Cryptographic Properties

**Hash function**: SHA3-256 (Keccak)

**Leaf values**: ML-KEM-768 public keys (1184 bytes, NIST FIPS 203 post-quantum standard)

**Tree structure**: Quaternary (4 children per node)

**Proof size**: depth × 3 siblings × 32 bytes
- Depth 3 (64 leaves): 288 bytes
- Depth 5 (1024 leaves): 480 bytes

**Comparison to binary Merkle**:
- Binary for 64 leaves: 192 bytes (6 levels × 1 sibling × 32 bytes)
- Quaternary for 64 leaves: 288 bytes (3 levels × 3 siblings × 32 bytes)
- Trade-off: Quaternary has 50% larger proofs but 50% fewer hash operations during verification

## Dependencies

- `pico-sdk`: Pico zkVM framework (git main branch)
- `ml-kem`: ML-KEM-768 implementation (v0.2.1)
- `sha3`: SHA3/Keccak hashing (v0.10)
- `serde`: Serialization with alloc support (v1.0)
- `bincode`: Binary serialization for zkVM input (v1.3)

## Building

Requires Rust nightly (specified in rust-toolchain.toml).

```bash
cargo build --release
Testing
Core library tests (9 tests, fast):

cargo test -p quad-tree-core
Host tests (11 tests, generates real ML-KEM keys):

cargo test -p quad-tree-host
Depth 3 test generates 64 ML-KEM-768 keypairs, runs in ~0.5 seconds.

Running Demo
Generate membership proof and save to JSON/bincode:

cd host
cargo run --release
Output: Builds quaternary tree with 64 ML-KEM-768 keys, generates membership proof for leaf [0,1,2], verifies locally, saves to quad_proof.json and quad_proof.bin.

Generating Zero-Knowledge Proofs
Requires Pico CLI installed (see setup.sh).

Fast Proof (Development/Testing)
Generate and verify proof in memory (~5 minutes):

cd guest
RUST_LOG=info cargo pico prove --input ../host/quad_proof.bin --fast --elf elf/riscv32im-pico-zkvm-elf
Full STARK Proof (Production)
Generate complete proof with recursion (~8-10 minutes):

cd guest
mkdir -p ../proof_output
RUST_LOG=info cargo pico prove --input ../host/quad_proof.bin --elf elf/riscv32im-pico-zkvm-elf --output ../proof_output
Output files in proof_output/:

proof.json - Full STARK proof (914 KB)
constraints.json - Gnark circuit constraints (52 MB)
groth16_witness.json - Witness data (708 KB)
pv_file - Public values (66 bytes)
EVM-Compatible Groth16 Proof
Requires Docker and 32GB+ RAM. Takes significantly longer.

cd guest
# First time: generate proving/verification keys
cargo pico prove --evm --setup --input ../host/quad_proof.bin --elf elf/riscv32im-pico-zkvm-elf

# Generate Groth16 proof for on-chain verification
cargo pico prove --evm --input ../host/quad_proof.bin --elf elf/riscv32im-pico-zkvm-elf --output ../evm_proof
Output includes Groth16Verifier.sol contract and proof.data (~200 bytes).

Proof Verification
Verification reconstructs root hash from leaf to root:

Start with leaf hash
At each level: combine current hash with 3 sibling hashes (in correct positions)
Hash 4 children to produce parent hash
Repeat until reaching root
Compare computed root with expected root
Sibling hashes stored leaf-to-root order (reversed from tree traversal order).

Tree Index Format
pub struct QuadTreeIndex {
    pub depth: u8,           // 0 = root
    pub path: Vec<u8>,       // Each element 0-3 (branch choices)
}
Example: path = [0, 2, 1] means depth 3, branch 0 at level 0, branch 2 at level 1, branch 1 at level 2.

Proof Format
pub struct QuadTreeMembershipProof {
    pub leaf_index: QuadTreeIndex,
    pub leaf_hash: [u8; 32],
    pub sibling_hashes: Vec<[[u8; 32]; 3]>,  // 3 siblings per level
    pub root_hash: [u8; 32],
}
Current Status
Successfully generates end-to-end zero-knowledge proofs with Pico zkVM.

Implemented:

Full STARK proof generation with recursion
Quaternary Merkle tree membership proofs
ML-KEM-768 post-quantum key integration
Bincode/JSON proof serialization
Local and zkVM verification
Not implemented:

Sparse tree support
Batch proof generation
Proof aggregation
On-chain deployment (Groth16 conversion supported but not deployed)
Test Coverage
20 tests total:

Core (9 tests):

Index creation and navigation
Hash determinism
Proof verification at depths 1-2
Invalid proof detection
Tampered data detection
Host (11 tests):

Membership proofs at depths 1-3
All-leaves verification (16 paths at depth 2)
Proof size calculation
Tree structure validation
Tamper detection (wrong leaf, wrong root, wrong siblings, depth mismatch)
Performance Characteristics
Tree Construction (Intel MacBook 2021, 8 cores):

Depth 1 (4 leaves): ~0.01s
Depth 2 (16 leaves): ~0.05s
Depth 3 (64 leaves): ~0.47s
Time dominated by ML-KEM-768 key generation (not proof operations).

ZK Proof Generation (same hardware):

Fast proof (development): ~5 minutes
Full STARK proof (production): ~8-10 minutes
RISCV phase: ~5 minutes
Recursion layers: ~3-4 minutes
Witness generation: ~30 seconds
RISC-V cycles executed: 73,100
See PROOF_RESULTS.md for detailed metrics.

Production Considerations
Not implemented in this demo:

Key management or secure storage
Network protocols for distributed proving
Proof caching or batching
Production-grade error handling
Gas optimization for on-chain verification
References
Merkle trees: Standard cryptographic data structure
Quaternary branching: Known variant, trade-off between proof size and verification depth
ML-KEM: NIST FIPS 203 (August 2024)
Pico zkVM: https://github.com/brevis-network/pico
License
Not specified.

Author
https://cliffyj.xyz and Claude Sonnet 4.5

Experimental implementation. Not audited. Not production-ready.
