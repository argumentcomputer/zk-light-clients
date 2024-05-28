# Aptos Light Client Proof Server

The following outlines an example use of the codebase.

Start the secondary server:

```
$ cargo run --release --bin server_secondary -- -a 127.0.0.1:6380
```

Start the primary server:

```
$ cargo run --release --bin server_primary -- -a 127.0.0.1:6379 --snd-addr 127.0.0.1:6380
```

Run the dummy client example:
```
$ cargo run --release --bin dummy_client -- --addr 127.0.0.1:6379 inclusion
$ cargo run --release --bin dummy_client -- --addr 127.0.0.1:6379 epoch-change
```

The server should be able to handle both calls above in parallel.

For more info, please refer to the `--help` sections of the servers' CLIs.
Also, please check the dummy client code to see how one can interact with the server.
