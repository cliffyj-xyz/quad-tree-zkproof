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

- `pico-sdk`: Pico zkVM framework (git dependency, tag v1.0.0)
- `ml-kem`: ML-KEM-768 implementation (v0.2.1)
- `sha3`: SHA3/Keccak hashing (v0.10)
- `serde`: Serialization (v1.0)

## Building

Requires Rust nightly (specified in rust-toolchain.toml).

```bash
cargo build --release
```

## Testing

Core library tests (9 tests, fast):
```bash
cargo test -p quad-tree-core
```

Host tests (11 tests, generates real ML-KEM keys):
```bash
cargo test -p quad-tree-host
```

Depth 3 test generates 64 ML-KEM-768 keypairs, runs in ~0.5 seconds.

## Running Demo

```bash
cd host
cargo run --release
```

Output: Builds tree, generates proof, verifies locally, saves proof to `quad_proof.json`.

## Proof Verification

Verification reconstructs root hash from leaf to root:

1. Start with leaf hash
2. At each level: combine current hash with 3 sibling hashes (in correct positions)
3. Hash 4 children to produce parent hash
4. Repeat until reaching root
5. Compare computed root with expected root

Sibling hashes stored leaf-to-root order (reversed from tree traversal order).

## Tree Index Format

```rust
pub struct QuadTreeIndex {
    pub depth: u8,           // 0 = root
    pub path: Vec<u8>,       // Each element 0-3 (branch choices)
}
```

Example: `path = [0, 2, 1]` means depth 3, branch 0 at level 0, branch 2 at level 1, branch 1 at level 2.

## Proof Format

```rust
pub struct QuadTreeMembershipProof {
    pub leaf_index: QuadTreeIndex,
    pub leaf_hash: [u8; 32],
    pub sibling_hashes: Vec<[[u8; 32]; 3]>,  // 3 siblings per level
    pub root_hash: [u8; 32],
}
```

## Limitations

- Fixed branching factor (4)
- No sparse tree support
- No batch proof generation
- No proof aggregation
- Guest zkVM program not production-ready (no actual Pico proof generation implemented in demo)

## Test Coverage

20 tests total:

**Core (9 tests)**:
- Index creation and navigation
- Hash determinism
- Proof verification at depths 1-2
- Invalid proof detection
- Tampered data detection

**Host (11 tests)**:
- Membership proofs at depths 1-3
- All-leaves verification (16 paths at depth 2)
- Proof size calculation
- Tree structure validation
- Tamper detection (wrong leaf, wrong root, wrong siblings, depth mismatch)

## Performance Characteristics

Measured on Intel MacBook:

- Depth 1 (4 leaves): ~0.01s
- Depth 2 (16 leaves): ~0.05s
- Depth 3 (64 leaves): ~0.47s

Time dominated by ML-KEM-768 key generation (not proof operations).

## Not Included

- Actual Pico zkVM proof generation (requires `pico prove` CLI)
- On-chain verification contracts
- Proof serialization formats beyond JSON
- Key management or storage
- Network protocols
- Production error handling

## References

- Merkle trees: Standard cryptographic data structure
- Quaternary branching: Known variant, trade-off between proof size and verification depth
- ML-KEM: NIST FIPS 203 (August 2024)
- Pico zkVM: https://github.com/brevis-network/pico

## License

Not specified.

## Author

Experimental implementation. Not audited. Not production-ready.
