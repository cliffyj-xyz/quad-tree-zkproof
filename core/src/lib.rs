#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;
use alloc::format;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Quaternary tree index representing position in tree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuadTreeIndex {
    /// Depth in tree (0 = root, 5 = leaf for 1024 leaves)
    pub depth: u8,
    /// Path from root, each element is 0-3 (quaternary branching)
    pub path: Vec<u8>,
}

impl QuadTreeIndex {
    pub fn new(depth: u8, path: Vec<u8>) -> Self {
        assert_eq!(depth as usize, path.len(), "Depth must match path length");
        assert!(path.iter().all(|&x| x < 4), "Path indices must be 0-3");
        Self { depth, path }
    }

    pub fn root() -> Self {
        Self {
            depth: 0,
            path: vec![],
        }
    }

    pub fn child(&self, branch: u8) -> Self {
        assert!(branch < 4, "Branch index must be 0-3");
        let mut path = self.path.clone();
        path.push(branch);
        Self {
            depth: self.depth + 1,
            path,
        }
    }

    pub fn branch_at_depth(&self, depth: usize) -> Option<u8> {
        if depth < self.path.len() {
            Some(self.path[depth])
        } else {
            None
        }
    }
}

/// Hash combining function for quaternary Merkle tree
pub fn hash_node(
    child0: &[u8; 32],
    child1: &[u8; 32],
    child2: &[u8; 32],
    child3: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(child0);
    hasher.update(child1);
    hasher.update(child2);
    hasher.update(child3);
    hasher.finalize().into()
}

/// Hash a leaf value (ML-KEM public key)
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"QUAD_LEAF:");
    hasher.update(data);
    hasher.finalize().into()
}

/// Merkle membership proof for quaternary tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuadTreeMembershipProof {
    pub leaf_index: QuadTreeIndex,
    pub leaf_hash: [u8; 32],
    /// For each level, contains the 3 sibling hashes in ascending position order
    /// (excluding the branch we take)
    /// Stored from LEAF to ROOT (reverse of path traversal)
    pub sibling_hashes: Vec<[[u8; 32]; 3]>,
    pub root_hash: [u8; 32],
}

impl QuadTreeMembershipProof {
    /// Verify the proof by reconstructing the root hash
    /// We start at the leaf and work our way UP to the root
    pub fn verify(&self) -> bool {
        if self.leaf_index.depth as usize != self.sibling_hashes.len() {
            return false;
        }

        let mut current_hash = self.leaf_hash;

        // Iterate through sibling levels from LEAF to ROOT
        for (level_from_leaf, siblings) in self.sibling_hashes.iter().enumerate() {
            let path_level = self.leaf_index.depth as usize - 1 - level_from_leaf;

            let branch_index = match self.leaf_index.branch_at_depth(path_level) {
                Some(idx) => idx as usize,
                None => return false,
            };

            if branch_index >= 4 {
                return false;
            }

            // Reconstruct the 4 children
            let mut children = [[0u8; 32]; 4];
            let mut sibling_idx = 0;

            for i in 0..4 {
                if i == branch_index {
                    children[i] = current_hash;
                } else {
                    if sibling_idx >= 3 {
                        return false;
                    }
                    children[i] = siblings[sibling_idx];
                    sibling_idx += 1;
                }
            }

            current_hash = hash_node(&children[0], &children[1], &children[2], &children[3]);
        }

        current_hash == self.root_hash
    }

    pub fn size_bytes(&self) -> usize {
        let path_size = self.leaf_index.path.len();
        let sibling_size = self.sibling_hashes.len() * 3 * 32;
        32 + 32 + 1 + path_size + sibling_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quad_index_creation() {
        let idx = QuadTreeIndex::new(3, vec![0, 1, 2]);
        assert_eq!(idx.depth, 3);
        assert_eq!(idx.path, vec![0, 1, 2]);
    }

    #[test]
    fn test_quad_index_child() {
        let root = QuadTreeIndex::root();
        let child = root.child(2);
        assert_eq!(child.depth, 1);
        assert_eq!(child.path, vec![2]);
    }

    #[test]
    fn test_hash_deterministic() {
        let data1 = b"test_data";
        let hash1 = hash_leaf(data1);
        let hash2 = hash_leaf(data1);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_node_deterministic() {
        let h0 = [1u8; 32];
        let h1 = [2u8; 32];
        let h2 = [3u8; 32];
        let h3 = [4u8; 32];

        let parent1 = hash_node(&h0, &h1, &h2, &h3);
        let parent2 = hash_node(&h0, &h1, &h2, &h3);
        assert_eq!(parent1, parent2);
    }

    #[test]
    fn test_proof_verification_simple() {
        let leaf0 = hash_leaf(b"leaf0");
        let leaf1 = hash_leaf(b"leaf1");
        let leaf2 = hash_leaf(b"leaf2");
        let leaf3 = hash_leaf(b"leaf3");

        let root = hash_node(&leaf0, &leaf1, &leaf2, &leaf3);

        let proof = QuadTreeMembershipProof {
            leaf_index: QuadTreeIndex::new(1, vec![1]),
            leaf_hash: leaf1,
            sibling_hashes: vec![[leaf0, leaf2, leaf3]],
            root_hash: root,
        };

        assert!(proof.verify());
    }

    #[test]
    fn test_proof_verification_leaf_at_different_positions() {
        let leaf0 = hash_leaf(b"leaf0");
        let leaf1 = hash_leaf(b"leaf1");
        let leaf2 = hash_leaf(b"leaf2");
        let leaf3 = hash_leaf(b"leaf3");

        let root = hash_node(&leaf0, &leaf1, &leaf2, &leaf3);

        let proof0 = QuadTreeMembershipProof {
            leaf_index: QuadTreeIndex::new(1, vec![0]),
            leaf_hash: leaf0,
            sibling_hashes: vec![[leaf1, leaf2, leaf3]],
            root_hash: root,
        };
        assert!(proof0.verify());

        let proof2 = QuadTreeMembershipProof {
            leaf_index: QuadTreeIndex::new(1, vec![2]),
            leaf_hash: leaf2,
            sibling_hashes: vec![[leaf0, leaf1, leaf3]],
            root_hash: root,
        };
        assert!(proof2.verify());

        let proof3 = QuadTreeMembershipProof {
            leaf_index: QuadTreeIndex::new(1, vec![3]),
            leaf_hash: leaf3,
            sibling_hashes: vec![[leaf0, leaf1, leaf2]],
            root_hash: root,
        };
        assert!(proof3.verify());
    }

    #[test]
    fn test_proof_verification_invalid() {
        let leaf0 = hash_leaf(b"leaf0");
        let leaf1 = hash_leaf(b"leaf1");
        let leaf2 = hash_leaf(b"leaf2");
        let leaf3 = hash_leaf(b"leaf3");

        let root = hash_node(&leaf0, &leaf1, &leaf2, &leaf3);

        let wrong_leaf = hash_leaf(b"wrong");
        let proof = QuadTreeMembershipProof {
            leaf_index: QuadTreeIndex::new(1, vec![1]),
            leaf_hash: wrong_leaf,
            sibling_hashes: vec![[leaf0, leaf2, leaf3]],
            root_hash: root,
        };

        assert!(!proof.verify());
    }

    #[test]
    fn test_proof_verification_depth_2_simple() {
        let mut leaves = Vec::new();
        for i in 0..16 {
            leaves.push(hash_leaf(format!("leaf{}", i).as_bytes()));
        }

        let mut level1 = Vec::new();
        for i in 0..4 {
            level1.push(hash_node(
                &leaves[i * 4],
                &leaves[i * 4 + 1],
                &leaves[i * 4 + 2],
                &leaves[i * 4 + 3],
            ));
        }

        let root = hash_node(&level1[0], &level1[1], &level1[2], &level1[3]);

        let proof = QuadTreeMembershipProof {
            leaf_index: QuadTreeIndex::new(2, vec![0, 0]),
            leaf_hash: leaves[0],
            sibling_hashes: vec![
                [leaves[1], leaves[2], leaves[3]],
                [level1[1], level1[2], level1[3]],
            ],
            root_hash: root,
        };

        assert!(proof.verify());
    }

    #[test]
    fn test_proof_verification_depth_2() {
        let mut leaves = Vec::new();
        for i in 0..16 {
            leaves.push(hash_leaf(format!("leaf{}", i).as_bytes()));
        }

        let mut level1 = Vec::new();
        for i in 0..4 {
            level1.push(hash_node(
                &leaves[i * 4],
                &leaves[i * 4 + 1],
                &leaves[i * 4 + 2],
                &leaves[i * 4 + 3],
            ));
        }

        let root = hash_node(&level1[0], &level1[1], &level1[2], &level1[3]);

        let proof = QuadTreeMembershipProof {
            leaf_index: QuadTreeIndex::new(2, vec![3, 3]),
            leaf_hash: leaves[15],
            sibling_hashes: vec![
                [leaves[12], leaves[13], leaves[14]],
                [level1[0], level1[1], level1[2]],
            ],
            root_hash: root,
        };

        assert!(proof.verify());
    }
}
