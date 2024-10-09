# FROST Testing Suite / Playground

This is a collection of tests for FROST in various configurations.
The main purpose of this repo is to test [taproot crate PR](https://github.com/ZcashFoundation/frost/pull/730) against a regtest bitcoin node. 
I will eventually be making custom changes to the taproot crate to include additional tweaks so this testuite can be used for testing those changes, but for now it's just a bunch of tests against the main PR.

## Tests so far:

- [ ] Key Spend with Trusted Dealer Setup
- [ ] Script Spend with Trusted Dealer Setup

TODO:
- [ ] Key Spend with DKG setup
- [ ] Script Spend with DKG setup

## Setup

1. run bitcoind in regtest mode with default params for regtest
1. export the RPC credentials as env variables:

```bash
export BITCOIND_RPC_USER="bitcoin"
export BITCOIND_RPC_PASS="bitcoin"
```

## Run the tests

```bash
cargo run
```

