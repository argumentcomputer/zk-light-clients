# Benchmark proving time

There are two types of benchmarks that you can run to get insight on the proving time necessary for the proof server to
generate a proof. The first one is the proving benchmark, which is meant to measure the time it takes to generate a
proof for a given circuit. The second one is the end-to-end benchmark, which is meant to measure the time it takes to
generate a proof in the context of a deployed Light Client with the worst case scenario happening.

Before covering how to run each benchmark we will cover the different configurations that exist for the prover and how
they should be set.