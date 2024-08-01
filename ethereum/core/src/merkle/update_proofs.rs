// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::hash::{sha2_hash_concat, HashValue};
use crate::merkle::error::MerkleError;
use crate::merkle::utils::get_subtree_index;
use crate::merkle::Merkleized;
use crate::types::block::consensus::BeaconBlockHeader;
use crate::types::block::execution::{
    ExecutionBlockHeader, ExecutionBranch, EXECUTION_BRANCH_NBR_SIBLINGS,
    EXECUTION_PAYLOAD_GENERALIZED_INDEX,
};
use crate::types::committee::{
    SyncCommittee, SyncCommitteeBranch, CURRENT_SYNC_COMMITTEE_GENERALIZED_INDEX,
    NEXT_SYNC_COMMITTEE_GENERALIZED_INDEX, SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS,
};
use crate::types::{
    Bytes32, FinalizedRootBranch, FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS,
    FINALIZED_ROOT_GENERALIZED_INDEX,
};

/// Verifies the validity of a finality proof received in an  [`crate::types::update::Update`] message.
///
/// # Arguments
///
/// * `state_root` - The state root of the Beacon block that the proof is attesting to.
/// * `finality_header` - The header of the block that the update is attesting to be finalized.
/// * `finality_branch` - The branch of the Merkle tree that proves the finality of the block.
///
/// # Returns
///
/// A `bool` indicating whether the finality proof is valid.
pub fn is_finality_proof_valid(
    state_root: &Bytes32,
    finality_header: &mut BeaconBlockHeader,
    finality_branch: &FinalizedRootBranch,
) -> Result<bool, MerkleError> {
    is_proof_valid(
        state_root,
        finality_header,
        finality_branch,
        FINALIZED_CHECKPOINT_BRANCH_NBR_SIBLINGS,
        FINALIZED_ROOT_GENERALIZED_INDEX,
    )
}

/// Verifies the validity of a sync committee proof received in an [`crate::types::update::Update`] message.
///
/// # Arguments
///
/// * `state_root` - The state root of the Beacon block that the proof is attesting to.
/// * `sync_committee` - The next sync committee that the update is attesting to.
/// * `sync_committee_branch` - The branch of the Merkle tree that proves the sync committee of the block.
///
/// # Returns
///
/// A `bool` indicating whether the sync committee proof is valid.
pub fn is_next_committee_proof_valid(
    state_root: &Bytes32,
    next_committee: &mut SyncCommittee,
    next_committee_branch: &SyncCommitteeBranch,
) -> Result<bool, MerkleError> {
    is_proof_valid(
        state_root,
        next_committee,
        next_committee_branch,
        SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS,
        NEXT_SYNC_COMMITTEE_GENERALIZED_INDEX,
    )
}

/// Verifies the validity of a current committee proof received in a [`crate::types::bootstrap::Bootstrap`] message.
///
/// # Arguments
///
/// * `state_root` - The state root of the Beacon block that the proof is attesting to.
/// * `current_committee` - The current sync committee that the bootstrap is attesting to.
/// * `current_committee_branch` - The branch of the Merkle tree that proves the current committee of the block.
///
/// # Returns
///
/// A `bool` indicating whether the current committee proof is valid.
pub fn is_current_committee_proof_valid(
    state_root: &Bytes32,
    current_committee: &mut SyncCommittee,
    current_committee_branch: &SyncCommitteeBranch,
) -> Result<bool, MerkleError> {
    is_proof_valid(
        state_root,
        current_committee,
        current_committee_branch,
        SYNC_COMMITTEE_BRANCH_NBR_SIBLINGS,
        CURRENT_SYNC_COMMITTEE_GENERALIZED_INDEX,
    )
}

/// Verifies the validity of an execution payload proof received in an [`crate::types::update::Update`] message.
///
/// # Arguments
///
/// * `state_root` - The state root of the Beacon block that the proof is attesting to.
/// * `execution_block_header` - The header of the block that the update is attesting to be executed.
/// * `execution_payload_branch` - The branch of the Merkle tree that proves the execution payload of the block.
///
/// # Returns
///
/// A `bool` indicating whether the execution payload proof is valid.
pub fn is_execution_payload_proof_valid(
    state_root: &Bytes32,
    execution_block_header: &mut ExecutionBlockHeader,
    execution_payload_branch: &ExecutionBranch,
) -> Result<bool, MerkleError> {
    is_proof_valid(
        state_root,
        execution_block_header,
        execution_payload_branch,
        EXECUTION_BRANCH_NBR_SIBLINGS,
        EXECUTION_PAYLOAD_GENERALIZED_INDEX,
    )
}

/// Generic function to verify the validity of a Merkle proof.
///
/// # Arguments
///
/// * `state_root` - The state root of the Beacon block that the proof is attesting to.
/// * `leaf_object` - The object that the proof is attesting to.
/// * `branch` - The branch of the Merkle tree that proves the object.
/// * `depth` - The depth of the Merkle tree.
/// * `generalized_index` - The generalized index of the object in the Merkle tree.
///
/// # Returns
///
/// A `bool` indicating whether the proof is valid.
fn is_proof_valid<M: Merkleized>(
    state_root: &Bytes32,
    leaf_object: &mut M,
    branch: &[Bytes32],
    depth: usize,
    generalized_index: usize,
) -> Result<bool, MerkleError> {
    // Ensure we receive the number of siblings we expected
    if branch.len() != depth {
        return Err(MerkleError::InvalidBranchLength {
            expected: depth,
            actual: branch.len(),
        });
    }

    // Ensure that the generalized index is for the given depth
    let generalized_index_depth = 63 - (generalized_index as u64).leading_zeros();
    if generalized_index_depth != depth as u32 {
        return Err(MerkleError::InvalidGeneralizedIndex {
            depth,
            generalized_index,
            generalized_index_depth,
        });
    }

    // 1. Convert generalized index to field index.
    let subtree_index = get_subtree_index(generalized_index as u64) as usize;

    // 2. Calculate path based on the subtree index
    let path = (0..depth)
        .map(|i| (subtree_index / 2usize.pow(i as u32)) % 2 != 0)
        .collect::<Vec<_>>();

    // 3. Calculate leaf value
    let leaf_hash = leaf_object
        .hash_tree_root()
        .map_err(|err| MerkleError::Hash { source: err.into() })?;

    // 4. Instantiate expected root and siblings as `HashValue`
    let state_root = HashValue::new(*state_root);
    let branch_hashes = branch
        .iter()
        .map(|bytes| HashValue::new(*bytes))
        .collect::<Vec<_>>();

    // 5. Reconstruct the root hash
    let reconstructed_root = branch_hashes
        .iter()
        .zip(path)
        .fold(leaf_hash, accumulator_update);

    // 6. Check if the reconstructed root matches the state root
    Ok(reconstructed_root == state_root)
}

/// Updates the accumulator hash during proof verification.
///
/// # Arguments
///
/// * `acc_hash: HashValue` - The current accumulator hash.
/// * `(sibling_hash, bit): (&HashValue, bool)` - The hash of the
///   sibling node and a boolean indicating whether the sibling is on the right.
///
/// # Returns
///
/// A `HashValue` representing the updated accumulator hash.
fn accumulator_update(acc_hash: HashValue, (sibling_hash, bit): (&HashValue, bool)) -> HashValue {
    if bit {
        sha2_hash_concat(sibling_hash, &acc_hash).unwrap()
    } else {
        sha2_hash_concat(&acc_hash, sibling_hash).unwrap()
    }
}

#[cfg(all(test, feature = "ethereum"))]
mod test {
    use crate::merkle::update_proofs::{
        is_current_committee_proof_valid, is_execution_payload_proof_valid,
        is_finality_proof_valid, is_next_committee_proof_valid,
    };
    use crate::test_utils::{
        generate_committee_change_test_assets, generate_inclusion_test_assets,
    };
    use crate::types::bootstrap::Bootstrap;
    use std::env::current_dir;
    use std::fs;

    #[test]
    fn test_is_execution_payload_proof_valid() {
        let test_assets = generate_inclusion_test_assets();

        let mut execution_header = test_assets
            .finality_update()
            .finalized_header()
            .execution()
            .clone();

        let is_valid = is_execution_payload_proof_valid(
            test_assets
                .finality_update()
                .finalized_header()
                .beacon()
                .body_root(),
            &mut execution_header,
            test_assets
                .finality_update()
                .finalized_header()
                .execution_branch(),
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_is_finality_proof_valid() {
        let test_assets = generate_inclusion_test_assets();

        let mut finality_header = test_assets
            .finality_update()
            .finalized_header()
            .beacon()
            .clone();

        let is_valid = is_finality_proof_valid(
            test_assets
                .finality_update()
                .attested_header()
                .beacon()
                .state_root(),
            &mut finality_header,
            test_assets.finality_update().finality_branch(),
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_is_next_committee_proof_valid() {
        let test_assets = generate_committee_change_test_assets();

        let mut next_committee = test_assets
            .update_new_period()
            .next_sync_committee()
            .clone();

        let is_valid = is_next_committee_proof_valid(
            test_assets
                .update_new_period()
                .attested_header()
                .beacon()
                .state_root(),
            &mut next_committee,
            test_assets.update_new_period().next_sync_committee_branch(),
        )
        .unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_is_current_committee_proof_valid() {
        let test_asset_path = current_dir()
            .unwrap()
            .join("../test-assets/committee-change/LightClientBootstrapDeneb.ssz");

        let test_bytes = fs::read(test_asset_path).unwrap();

        let bootstrap = Bootstrap::from_ssz_bytes(&test_bytes).unwrap();

        let mut current_committee = bootstrap.current_sync_committee().clone();

        let is_valid = is_current_committee_proof_valid(
            bootstrap.header().beacon().state_root(),
            &mut current_committee,
            bootstrap.current_sync_committee_branch(),
        )
        .unwrap();

        assert!(is_valid);
    }
}
