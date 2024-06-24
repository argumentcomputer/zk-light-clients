# Run the Light Client

In the previous section, we covered all the architecture components of the Light Client and explained their specific
roles. In this section we will cover how to set them up and run the Light Client to start proving epoch change and
inclusion proofs.

As the computational requirements for the Proof Server are heavy, here are the machine specs for each component, based
on off-the-shelf machines from cloud providers:

|                                                                       | CPU                                                                                           | Memory (GB) | Disk Size (GB) | Example                                                                  |
|-----------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|-------------|----------------|--------------------------------------------------------------------------|
| Client                                                                | 8 cores, 16 threads                                                                           | 32          | 64             | [GCP C3](https://cloud.google.com/compute/docs/general-purpose-machines) |
| Proof Server                                                          | Intel x86_64 Sapphire Rapids, 128 vCPU, bare metal, supports `avx512_ifma` and `avx512_vbmi2` | 1024        | 150            | [AWS r7iz.metal-32xl](https://aws.amazon.com/ec2/instance-types/r7iz/)   |
| [Aptos Full Node](https://aptos.dev/nodes/full-node/pfn-requirements) | 8 cores, 16 threads (Intel Xeon Skylake or newer)                                             | 32          | A few 100's GB | [GCP C3](https://cloud.google.com/compute/docs/general-purpose-machines) |

> **Note**
> 
> Generating a proof needs a minimum of 128GB, but does not make use of more than ~200GB of memory.
