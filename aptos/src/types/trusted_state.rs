// SPDX-License-Identifier: Apache-2.0, MIT
use crate::types::epoch_state::EpochState;
use crate::types::ledger_info::{LedgerInfo, LedgerInfoWithSignatures};
use crate::types::waypoint::Waypoint;
use crate::types::Version;
use anyhow::{bail, ensure, format_err};
use test_strategy::Arbitrary;

#[derive(Debug, Clone, Arbitrary)]
pub enum TrustedState {
    /// The current trusted state is an epoch waypoint, which is a commitment to
    /// an epoch change ledger info. Most light clients will start here when
    /// syncing for the first time.
    EpochWaypoint(Waypoint),
    /// The current trusted state is inside a verified epoch (which includes the
    /// validator set inside that epoch).
    EpochState {
        /// The current trusted version and a commitment to a ledger info inside
        /// the current trusted epoch.
        waypoint: Waypoint,
        /// The current epoch and validator set inside that epoch.
        epoch_state: EpochState,
    },
}

impl TrustedState {
    pub fn version(&self) -> Version {
        self.waypoint().version()
    }

    pub fn waypoint(&self) -> Waypoint {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { waypoint, .. } => *waypoint,
        }
    }

    fn epoch_change_verification_required(&self, epoch: u64) -> bool {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => {
                epoch_state.epoch_change_verification_required(epoch)
            }
        }
    }

    fn is_ledger_info_stale(&self, ledger_info: &LedgerInfo) -> bool {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => epoch_state.is_ledger_info_stale(ledger_info),
        }
    }

    fn verify(&self, ledger_info: &LedgerInfoWithSignatures) -> anyhow::Result<()> {
        match self {
            Self::EpochWaypoint(_waypoint) => {
                unimplemented!("This LC doesn't support epoch waypoints")
            }
            Self::EpochState { epoch_state, .. } => epoch_state.verify(ledger_info),
        }
    }

    /// The main LC method
    pub fn verify_and_ratchet_inner<'a>(
        &self,
        latest_li: &'a LedgerInfoWithSignatures,
        epoch_change_proof: &'a EpochChangeProof,
    ) -> anyhow::Result<TrustedStateChange<'a>> {
        // Abort early if the response is stale.
        let curr_version = self.version();
        let target_version = latest_li.ledger_info().version();
        ensure!(
            target_version >= curr_version,
            "The target latest ledger info version is stale ({}) and behind our current trusted version ({})",
            target_version, curr_version,
        );

        if self.epoch_change_verification_required(latest_li.ledger_info().next_block_epoch()) {
            // Verify the EpochChangeProof to move us into the latest epoch.
            let epoch_change_li = epoch_change_proof.verify(self)?;
            let new_epoch_state = epoch_change_li
                .ledger_info()
                .next_epoch_state()
                .cloned()
                .ok_or_else(|| {
                    format_err!(
                        "A valid EpochChangeProof will never return a non-epoch change ledger info"
                    )
                })?;

            // If the latest ledger info is in the same epoch as the new verifier, verify it and
            // use it as latest state, otherwise fallback to the epoch change ledger info.
            let new_epoch = new_epoch_state.epoch;

            let verified_ledger_info = if epoch_change_li == latest_li {
                latest_li
            } else if latest_li.ledger_info().epoch() == new_epoch {
                new_epoch_state.verify(latest_li)?;
                latest_li
            } else if latest_li.ledger_info().epoch() > new_epoch && epoch_change_proof.more {
                epoch_change_li
            } else {
                bail!("Inconsistent epoch change proof and latest ledger info");
            };
            let new_waypoint = Waypoint::new_any(verified_ledger_info.ledger_info());

            let new_state = TrustedState::EpochState {
                waypoint: new_waypoint,
                epoch_state: new_epoch_state,
            };

            Ok(TrustedStateChange::Epoch {
                new_state,
                latest_epoch_change_li: epoch_change_li,
            })
        } else {
            let (curr_waypoint, curr_epoch_state) = match self {
                Self::EpochWaypoint(_) => {
                    bail!("EpochWaypoint can only verify an epoch change ledger info")
                }
                Self::EpochState {
                    waypoint,
                    epoch_state,
                    ..
                } => (waypoint, epoch_state),
            };

            // The EpochChangeProof is empty, stale, or only gets us into our
            // current epoch. We then try to verify that the latest ledger info
            // is inside this epoch.
            let new_waypoint = Waypoint::new_any(latest_li.ledger_info());
            if new_waypoint.version() == curr_waypoint.version() {
                ensure!(
                    &new_waypoint == curr_waypoint,
                    "LedgerInfo doesn't match verified state"
                );
                Ok(TrustedStateChange::NoChange)
            } else {
                // Verify the target ledger info, which should be inside the current epoch.
                curr_epoch_state.verify(latest_li)?;

                let new_state = Self::EpochState {
                    waypoint: new_waypoint,
                    epoch_state: curr_epoch_state.clone(),
                };

                Ok(TrustedStateChange::Version { new_state })
            }
        }
    }
}

#[derive(Debug)]
pub enum TrustedStateChange<'a> {
    /// We have a newer `TrustedState` but it's still in the same epoch, so only
    /// the latest trusted version changed.
    Version { new_state: TrustedState },
    /// We have a newer `TrustedState` and there was at least one epoch change,
    /// so we have a newer trusted version and a newer trusted validator set.
    Epoch {
        new_state: TrustedState,
        latest_epoch_change_li: &'a LedgerInfoWithSignatures,
    },
    /// The latest ledger info is at the same version as the trusted state and matches the hash.
    NoChange,
}

/// A vector of LedgerInfo with contiguous increasing epoch numbers to prove a sequence of
/// epoch changes from the first LedgerInfo's epoch.
pub struct EpochChangeProof {
    pub ledger_info_with_sigs: Vec<LedgerInfoWithSignatures>,
    pub more: bool,
}

impl EpochChangeProof {
    /// Verify the proof is correctly chained with known epoch and validator
    /// verifier and return the [`LedgerInfoWithSignatures`] to start target epoch.
    ///
    /// In case a waypoint is present, it's going to be used for verifying the
    /// very first epoch change (it's the responsibility of the caller to not
    /// pass a waypoint in case it's not needed).
    ///
    /// We will also skip any stale ledger info's in the [`EpochChangeProof`].
    pub fn verify(&self, verifier: &TrustedState) -> anyhow::Result<&LedgerInfoWithSignatures> {
        ensure!(
            !self.ledger_info_with_sigs.is_empty(),
            "The EpochChangeProof is empty"
        );
        ensure!(
            !verifier
                .is_ledger_info_stale(self.ledger_info_with_sigs.last().unwrap().ledger_info()),
            "The EpochChangeProof is stale as our verifier is already ahead \
             of the entire EpochChangeProof"
        );
        let mut trusted_state: TrustedState = verifier.clone();

        for ledger_info_with_sigs in self
            .ledger_info_with_sigs
            .iter()
            // Skip any stale ledger infos in the proof prefix. Note that with
            // the assertion above, we are guaranteed there is at least one
            // non-stale ledger info in the proof.
            //
            // It's useful to skip these stale ledger infos to better allow for
            // concurrent client requests.
            //
            // For example, suppose the following:
            //
            // 1. My current trusted state is at epoch 5.
            // 2. I make two concurrent requests to two validators A and B, who
            //    live at epochs 9 and 11 respectively.
            //
            // If A's response returns first, I will ratchet my trusted state
            // to epoch 9. When B's response returns, I will still be able to
            // ratchet forward to 11 even though B's EpochChangeProof
            // includes a bunch of stale ledger infos (for epochs 5, 6, 7, 8).
            //
            // Of course, if B's response returns first, we will reject A's
            // response as it's completely stale.
            .skip_while(|&ledger_info_with_sigs| {
                verifier.is_ledger_info_stale(ledger_info_with_sigs.ledger_info())
            })
        {
            // Try to verify each (epoch -> epoch + 1) jump in the EpochChangeProof.
            trusted_state.verify(ledger_info_with_sigs)?;
            // While the original verification could've been via waypoints,
            // all the next epoch changes are verified using the (already
            // trusted) validator sets.
            let new_li = ledger_info_with_sigs.ledger_info();

            let new_epoch_state = new_li
                .next_epoch_state()
                .ok_or_else(|| format_err!("LedgerInfo doesn't carry a ValidatorSet"))?;
            let new_waypoint = Waypoint::new_any(new_li);
            let new_trusted_state = TrustedState::EpochState {
                waypoint: new_waypoint,
                epoch_state: new_epoch_state.clone(),
            };
            trusted_state = new_trusted_state;
        }

        Ok(self.ledger_info_with_sigs.last().unwrap())
    }
}
