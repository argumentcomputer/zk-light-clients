# Edge cases

Latency-wise, Ethereum Light Client's do not have a worst case scenario. As we 
explained earlier, it is possible for a Light Client to know at any given time in a
period \\(N\\) the current valid sync committee and the one for the period \\(N+1\\).

This allows the Light Client to generate inclusion proof for both the current period and the
one after if the Sync Committee Change proof has yet to be generated.

This effectively means that the Light Client has 2 periods (~2 days) to generate the Sync
Committee Change proof, which is more than enough time to generate the proof.
It also means that the Light Client can generate the Inclusion Proof at any time, even
when the Sync Committee Change proof is being generated.