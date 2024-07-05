// Copyright (c) Yatima, Inc.
// SPDX-License-Identifier: Apache-2.0

/// Calculate the sync period for a given slot number.
pub fn calc_sync_period(slot: &u64) -> u64 {
    let epoch = slot / 32; // 32 slots per epoch
    epoch / 256 // 256 epochs per sync committee
}
