# Edge cases

Latency-wise, the worst case scenario for the light client happens when a user wants to get both proofs at the start of a new
epoch, meaning that we want to prove both the Epoch Change Proof and the Inclusion Proof at the same time.

A naïve approach would lead us to a total proving time being equal the sum of their respecting
time \\(D_{\text{total}} = D_{\text{epoch_change_proof}} + D_{\text{inclusion_proof}}\\).

However, because the validator set is identified by a hash that can be calculated quickly outside of the proof, we can
actually generate both proofs in parallel since there are no data dependencies between each proof.

Generating both proofs in parallel, we end up with a worst case latency of
\\(D_{\text{total}} = \max(D_{\text{epoch_change_proof}}, D_{\text{inclusion_proof}}\)\\) which can be approximated by
\\(D_{\text{total}} = D_{\text{sig_verification}}\\) as the majority of the proving time is dedicated to verifying the
BLS12-381 signatures used in the block header signatures.
