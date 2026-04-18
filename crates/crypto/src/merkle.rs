use crate::hash::{blake3_hash, hash_pair, Hash, HASH_LEN};

/// Sparse Merkle tree for efficient state proofs
pub struct MerkleTree {
    leaves: Vec<Hash>,
    layers: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data
    pub fn from_leaves(data: &[&[u8]]) -> Self {
        let leaves: Vec<Hash> = data.iter().map(|d| blake3_hash(d)).collect();
        Self::from_hashes(leaves)
    }

    /// Build from pre-computed leaf hashes
    pub fn from_hashes(leaves: Vec<Hash>) -> Self {
        if leaves.is_empty() {
            return Self {
                leaves: vec![],
                layers: vec![vec![[0u8; HASH_LEN]]],
            };
        }

        let mut layers = vec![leaves.clone()];
        let mut current = leaves.clone();

        while current.len() > 1 {
            let mut next = Vec::with_capacity((current.len() + 1) / 2);
            for chunk in current.chunks(2) {
                let hash = if chunk.len() == 2 {
                    hash_pair(&chunk[0], &chunk[1])
                } else {
                    hash_pair(&chunk[0], &chunk[0])
                };
                next.push(hash);
            }
            layers.push(next.clone());
            current = next;
        }

        Self { leaves, layers }
    }

    /// Get the root hash
    pub fn root(&self) -> Hash {
        self.layers
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or([0u8; HASH_LEN])
    }

    /// Generate a Merkle proof for a leaf at the given index
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut directions = Vec::new();
        let mut idx = index;

        for layer in &self.layers[..self.layers.len().saturating_sub(1)] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = if sibling_idx < layer.len() {
                layer[sibling_idx]
            } else {
                layer[idx]
            };
            siblings.push(sibling);
            directions.push(idx % 2 == 0);
            idx /= 2;
        }

        Some(MerkleProof {
            leaf: self.leaves[index],
            siblings,
            directions,
            root: self.root(),
        })
    }

    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }
}

/// Merkle inclusion proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub leaf: Hash,
    pub siblings: Vec<Hash>,
    pub directions: Vec<bool>,
    pub root: Hash,
}

impl MerkleProof {
    /// Verify the proof against a given root
    pub fn verify(&self, expected_root: &Hash) -> bool {
        if self.siblings.len() != self.directions.len() {
            return false;
        }
        let mut current = self.leaf;

        for (sibling, is_left) in self.siblings.iter().zip(self.directions.iter()) {
            current = if *is_left {
                hash_pair(&current, sibling)
            } else {
                hash_pair(sibling, &current)
            };
        }

        current == *expected_root
    }
}

/// Compute Merkle root from a list of transaction hashes (without storing the tree)
pub fn compute_merkle_root(hashes: &[Hash]) -> Hash {
    if hashes.is_empty() {
        return [0u8; HASH_LEN];
    }
    if hashes.len() == 1 {
        return hashes[0];
    }

    let mut current: Vec<Hash> = hashes.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for chunk in current.chunks(2) {
            let hash = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                hash_pair(&chunk[0], &chunk[0])
            };
            next.push(hash);
        }
        current = next;
    }
    current[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let tree = MerkleTree::from_leaves(&[b"leaf1"]);
        let root = tree.root();
        assert_ne!(root, [0u8; HASH_LEN]);
    }

    #[test]
    fn test_proof_verification() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree = MerkleTree::from_leaves(&data);

        for i in 0..data.len() {
            let proof = tree.proof(i).unwrap();
            assert!(proof.verify(&tree.root()), "proof failed for index {i}");
        }
    }

    #[test]
    fn test_odd_leaves() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let tree = MerkleTree::from_leaves(&data);
        let proof = tree.proof(2).unwrap();
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn test_compute_merkle_root_matches_tree() {
        let leaves = vec![
            blake3_hash(b"a"),
            blake3_hash(b"b"),
            blake3_hash(b"c"),
            blake3_hash(b"d"),
        ];
        let tree = MerkleTree::from_hashes(leaves.clone());
        assert_eq!(tree.root(), compute_merkle_root(&leaves));
    }

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::from_leaves(&[]);
        assert_eq!(tree.root(), [0u8; HASH_LEN]);
    }
}
