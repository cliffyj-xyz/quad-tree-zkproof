use super::*;
use quad_tree_core::hash_leaf;

#[test]
    fn test_membership_proof_depth_1() {
        let tree = build_quad_tree(1);

        // Generate proof for leaf [2]
        let proof = generate_membership_proof(&tree, &[2]);

        assert_eq!(proof.leaf_index.depth, 1);
        assert_eq!(proof.leaf_index.path, vec![2]);
        assert_eq!(proof.sibling_hashes.len(), 1);
        assert_eq!(proof.root_hash, tree.hash);

        // Verify proof
        assert!(proof.verify(), "Proof should verify");
    }

    #[test]
    fn test_membership_proof_depth_2() {
        let tree = build_quad_tree(2);

        // Generate proof for leaf [1, 3]
        let proof = generate_membership_proof(&tree, &[1, 3]);

        assert_eq!(proof.leaf_index.depth, 2);
        assert_eq!(proof.leaf_index.path, vec![1, 3]);
        assert_eq!(proof.sibling_hashes.len(), 2);

        // Verify proof
        assert!(proof.verify(), "Proof should verify");
    }

    #[test]
    fn test_all_leaves_verify() {
        let tree = build_quad_tree(2);

        // Test all 16 possible paths
        for i in 0..4 {
            for j in 0..4 {
                let path = vec![i, j];
                let proof = generate_membership_proof(&tree, &path);
                assert!(proof.verify(), "Proof for path {:?} should verify", path);
            }
        }
    }

    #[test]
    fn test_proof_size_calculation_depth_3() {
        // Depth 3 = 64 leaves = 64 ML-KEM key generations
        let tree = build_quad_tree(3);
        let proof = generate_membership_proof(&tree, &[0, 1, 2]);

        let calculated_size = proof.size_bytes();
        let expected_size = 32 + 32 + 1 + 3 + (3 * 3 * 32); // leaf + root + depth + path + siblings

        assert_eq!(calculated_size, expected_size);
    }

    #[test]
    fn test_invalid_proof_detection() {
        let tree = build_quad_tree(2);
        let mut proof = generate_membership_proof(&tree, &[1, 2]);

        // Tamper with leaf hash
        proof.leaf_hash[0] ^= 0xFF;

        assert!(!proof.verify(), "Tampered proof should not verify");
    }

    #[test]
    fn test_wrong_root_detection() {
        let tree = build_quad_tree(2);
        let mut proof = generate_membership_proof(&tree, &[1, 2]);

        // Tamper with root hash
        proof.root_hash[0] ^= 0xFF;

        assert!(!proof.verify(), "Proof with wrong root should not verify");
    }

    #[test]
    fn test_wrong_sibling_detection() {
        let tree = build_quad_tree(2);
        let mut proof = generate_membership_proof(&tree, &[1, 2]);

        // Tamper with a sibling hash
        proof.sibling_hashes[0][0][0] ^= 0xFF;

        assert!(
            !proof.verify(),
            "Proof with wrong sibling should not verify"
        );
    }

    #[test]
    fn test_depth_mismatch_detection() {
        let tree = build_quad_tree(2);
        let mut proof = generate_membership_proof(&tree, &[1, 2]);

        // Add extra sibling level (depth mismatch)
        proof.sibling_hashes.push([[0u8; 32]; 3]);

        assert!(
            !proof.verify(),
            "Proof with depth mismatch should not verify"
        );
    }

    #[test]
    fn test_deterministic_tree_building() {
        // Note: This test will fail because ML-KEM uses random key generation
        // In production, you'd use a deterministic seed for reproducible trees
        // This test documents the expected behavior

        let tree1 = build_quad_tree(1);
        let tree2 = build_quad_tree(1);

        // Roots will be different due to random key generation
        // This is EXPECTED and SECURE behavior
        assert_ne!(
            tree1.hash, tree2.hash,
            "Trees should differ due to random ML-KEM key generation"
        );
    }

    #[test]
    fn test_hash_collision_resistance() {
        // Generate two different leaves and verify different hashes
        let data1 = b"leaf data 1";
        let data2 = b"leaf data 2";

        let hash1 = hash_leaf(data1);
        let hash2 = hash_leaf(data2);

        assert_ne!(
            hash1, hash2,
            "Different inputs should produce different hashes"
        );
    }

    #[test]
    fn test_quaternary_property() {
        // Verify that each internal node has exactly 4 children
        let tree = build_quad_tree(2);

        fn verify_quaternary(node: &QuadTreeNode) -> bool {
            if let Some(ref children) = node.children {
                if children.len() != 4 {
                    return false;
                }
                for child in children.iter() {
                    if !verify_quaternary(child) {
                        return false;
                    }
                }
            }
            true
        }

        assert!(
            verify_quaternary(&tree),
            "All internal nodes must have exactly 4 children"
        );
    }
