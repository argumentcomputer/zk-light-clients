<img src="images/ethereum.png" style="border-radius: 20px">

> **Note**
>
> The following documentation has been written with the supposition that the
> reader is already knowledgeable about the synchronisation protocol for Light
> Clients implemented on Ethereum.\\(N\\) 
>
> To read about it refer
> to [the Light Client section](https://ethereum.org/en/developers/docs/nodes-and-clients/light-clients/)
> of the Ethereum documentation
> and
> the [Sync Protocol specification](https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/light-client/sync-protocol.md).

The Ethereum Light Client (LC) provides a streamlined and efficient way to verify blockchain state transitions and
proofs without needing to store or synchronize the entire blockchain.

The following documentation aims to provide a high-level overview of the Ethereum LC and its components, along with a
guide
on how to set up and run or benchmark the Ethereum LC.

### Sections

**[High-level design](./design/overview.md)**

An overview of what is the Light Client and the feature set it provides.

**[Components](./components/overview.md)**

A detailed description of the components that make up the Light Client.

**[Run the Light Client](./run/overview.md)**

A guide on how to set up and run the Light Client.

**[Benchmark the Light Client](./benchmark/overview.md)**

A guide on how to benchmark the Light Client.