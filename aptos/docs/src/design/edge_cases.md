# Edge cases

The worst edge case that can happen for our Light Client is when a user wants to get both proofs at the start of a new
epoch,
meaning that we want to prove both the Epoch Change Proof and the Inclusion Proof at the same time.

A naïve approach would lead us to a total proving time being equal the sum of their respecting
time \\(D_{\text{total}} = D_{\text{epoch_change_proof}} + D_{\text{inclusion_proof}} \\).

However, in our setting we can have an optimistic approach where we consider that the epoch transition received is
valid. Thus, starting both proof generation in parallel. As the proving time for the two proofs is equivalent we end up
with \\(D_{\text{total}} = 2 * D_{\text{epoch_change_proof}}\\) which can be reduced to \\(D_{\text{total}} = 2 * D_
{\text{sig_verification}} \\) as most
of the proving time is dedicated to the BLS12-381 used in the block header signature verification.