# Setup an Aptos Full Node

As we covered [in the previous section](../components/aptos_pfn.md), the current reference for the Aptos Full Node
codebase is [`lurk-lab/aptos-core`](https://github.com/lurk-lab/aptos-core). The current version can be found on the
branch [`lurk-lab/aptos-core:release/aptos-node-v1.14.0-patched`](https://github.com/lurk-lab/aptos-core/tree/release/aptos-node-v1.14.0-patched).

The setup we will go over is a setup by
building the code source.

The relevant documentation concerning a Full Node deployment can be
found [on the Aptos website](https://aptos.dev/nodes/full-node/public-fullnode/).

First, clone the repository and `cd` into it:

```bash
git clone git@github.com:lurk-lab/aptos-core.git && cd aptos-core
```

Then, we have some configuration to set up.
Following [the Aptos documentation](https://aptos.dev/nodes/full-node/deployments/deploy-a-pfn-source-code):

1. Download Aptos mainnet Genesis blob:
    ```bash
    curl -O https://raw.githubusercontent.com/aptos-labs/aptos-networks/main/mainnet/genesis.blob
    ```

2. Download Aptos mainnet waypoint file:
   ```bash
   curl -O https://raw.githubusercontent.com/aptos-labs/aptos-networks/main/mainnet/waypoint.txt
   ```

3. Setup a fullnode.yaml that serves as a configuration file for the node. Here is an example of such a configuration
   file, make sure to set the proper data directory and network address for your deployment:
   ```yaml
   base:
     # Update this value to the location you want the node to store its database
     data_dir: "/home/user/aptos/db"
     role: "full_node"
     waypoint:
       # Update this value to that which the blockchain publicly provides. Please regard the directions
       # below on how to safely manage your genesis_file_location with respect to the waypoint.
       from_file: "./waypoint.txt"
   
   execution:
     # Update this to the location to where the genesis.blob is stored, prefer fullpaths
     # Note, this must be paired with a waypoint. If you update your waypoint without a
     # corresponding genesis, the file location should be an empty path.
     genesis_file_location: "./genesis.blob"
   
   full_node_networks:
     - discovery_method: "onchain"
       # The network must have a listen address to specify protocols. This runs it locally to
       # prevent remote, incoming connections.
       listen_address: "/ip4/127.0.0.1/tcp/6180"
       network_id: "public"
   
   # API related configuration, making it available at a given address.
   api:
     enabled: true
     # Update this to fit your deployment address for the node.
     address: 127.0.0.1:8080
   
   # /!\ IMPORTANT/!\
   # This configuration is especially important for the proof server to work.
   # This configuration allows us to access the state at each new block,
   # effectively allowing us to create inclusion proof about accounts.
   storage:
     buffered_state_target_items: 1
   
   # This configuration allows for a fast synchronisation of the node.
   state_sync:
     state_sync_driver:
       bootstrapping_mode: DownloadLatestStates
       continuous_syncing_mode: ExecuteTransactionsOrApplyOutputs
   ```

Once the configuration is done, we just need to run the node:

```bash
cargo run -p aptos-node --release -- -f ./fullnode.yaml
```

> **Note**
>
>The synchronisation mode that we use as an example above should reach the latest produced block in around 1 hour.
