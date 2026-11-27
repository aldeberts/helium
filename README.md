<h1 align="center">Helium</h1>

__Helium__ is a fork of [Heli](https://github.com/ryanleh/heli), a Rust library for **private aggregation**, in which the light server's work per round no longer depends on the number of clients that drop out.

Heli was developed as part of the paper [*"Heli: Heavy-Light Private Aggregation"*](https://eprint.iacr.org/2026/059). This fork is released under the same MIT License and Apache v2 License (see [License](#license)).

**WARNING:** This is an academic proof-of-concept prototype, and has not received careful code review. It should NOT be used for production use.

## What Helium changes

In Heli, the heavy server sends the light server the list of clients that dropped out of a round, and the light server re-derives each of their keys: 3 bytes of communication and one PRF evaluation per dropout.

In Helium, the heavy server sums the dropped-out clients' keys itself, under encryption, and proves that it did so honestly:

* **Setup.** For each client, the light server gives the heavy server the client's key encrypted under Paillier, along with two group elements.
* **Each round.** The heavy server multiplies the ciphertexts of the dropped-out clients and attaches a short proof that it summed distinct clients, each exactly once. The light server checks the proof with one Paillier decryption and one group exponentiation.

Clients are unchanged. The protocol and its security argument are described in [`src/dropout.rs`](src/dropout.rs).

Limitations to keep in mind:

* The security argument for the proof is a sketch, not a proof. It rests on a secret evaluation point that the light server must keep from the heavy server.
* The Paillier modulus is 2048 bits (about 112-bit security), and the Paillier code is not constant-time throughout.
* As in Heli's prototype, the decryptor will release more than one mask for the same context, so that benchmarks can repeat a round. A malicious aggregator could compare two such masks to isolate a client's report, so a deployment must refuse a second request for a context.
* As in Heli's prototype, anyone who can reach the decryptor before registration can request a simulated setup, whose keys are public. A deployment must disable it.

The table below compares the two schemes with 10% of clients dropping out, as measured by `dropout-bench` (see [Dropout benchmark](#dropout-benchmark)) on one core of an Apple M4 laptop. Expect different absolute numbers on server hardware.

| Clients | Dropouts | Light server, Heli | Light server, Helium | Heavy → light, Heli | Heavy → light, Helium | Heavy server's proof, Helium |
|---|---|---|---|---|---|---|
| 1,000 | 100 | 0.05 ms | 3.2 ms | 300 B | 576 B | 5 ms |
| 10,000 | 1,000 | 0.05 ms | 3.2 ms | 3 KB | 576 B | 40 ms |
| 100,000 | 10,000 | 0.09 ms | 3.2 ms | 30 KB | 576 B | 333 ms |
| 1,000,000 | 100,000 | 0.51 ms | 3.2 ms | 300 KB | 576 B | 3.0 s |
| 10,000,000 | 1,000,000 | 4.8 ms | 3.5 ms | 3 MB | 576 B | 8.0 s (10 threads) |

The last row was run with all ten of the laptop's cores busy; the light-server columns are single-threaded regardless.

Helium's light server does constant work, but that constant is a Paillier decryption, which costs as much as Heli's light server spends on roughly 700,000 dropouts. Helium also makes the one-time setup more expensive: about 3 ms of light-server time and 728 bytes of heavy-server storage per client.

## Directory structure

This repository contains several modules that implement the different building blocks of Heli. The high-level structure of the repository is as follows.

* [`src/crypto`](src/crypto): Low-level cryptographic components, including Paillier encryption.

* [`src/agg_only_enc.rs`](src/agg_only_enc.rs): Aggregation-only encryption scheme.

* [`src/proofs.rs`](src/proofs.rs): Zero-knowledge proofs for protecting against malicious clients.

* [`src/dropout.rs`](src/dropout.rs): Dropout-key aggregation by the heavy server, with proofs for protecting against a malicious heavy server.

* [`src/system`](src/system): Network protocol implementation.

* [`benches`](benches): Benchmarks.

* [`experiments`](experiments): End-to-end experiments to recreate Table 2
from the Heli paper.

* [`artifact-eval`](artifact-eval): Scripts to recreate Figures 4, 5 from the Heli paper.

## Build guide

Ensure that you have a C++ compiler, Rust, and the tools needed to build GMP (`m4` and `make`) installed.

On Ubuntu, you can install these via:
```bash
sudo apt install g++ m4 make
```

You can install Rust by following the directions [here](https://www.rust-lang.org/tools/install).

Next, ensure the following environment variable is set either in your current session (e.g., via `export`) or in your config file (e.g., in your `~/.bashrc` file):
```bash
RUSTFLAGS="-C target-cpu=native"
```
On ARM machines (including Apple Silicon), use `RUSTFLAGS="-C target-cpu=native --cfg aes_armv8"` instead.

Then, clone this repository and build the project:

```bash
cargo build --release
```
To run the test suite:
```bash
cargo test
```

## Experiments

### Micro-benchmarks

To reproduce Figures 4 and 5 of the Heli paper, install `cargo-criterion` via:
```bash
cargo install cargo-criterion
```
download the necessary Python dependencies:
```bash
cd artifact-eval/
pip install -r requirements.txt
```
and run the following script:
```bash
python3 run_and_plot.py
```
Plots will appear in the `artifact-eval/plots` directory.


### Dropout benchmark

To compare how Heli and Helium handle dropped-out clients, run:
```bash
RAYON_NUM_THREADS=1 cargo run --release --bin dropout-bench -- --clients 1000 10000 100000 --dropout-percent 10
```
For each configuration this prints the light server's time per round under both schemes, the time the heavy server spends summing keys and proving under Helium, the bytes the heavy server sends the light server, and Helium's setup cost per client. Unset `RAYON_NUM_THREADS` to let the heavy server use every core.

[`BENCHMARK_PLAN.md`](BENCHMARK_PLAN.md) describes the planned comparison of Heli and Helium on cloud machines.

### End-to-end experiments

The scripts in `experiments/bin/` run the aggregator, decryptor, and client with predefined configs. For these to work, ensure that the aggregator and decryptor accept TCP traffic on ports 9000 and 9001. 

* `run_{aggregator,decryptor,client}.sh` runs aggregation over 10,000,000 million clients (with 10% offline) with bit vectors of length 1, 32, and 128. The experiments are specified in `experiments/configs/full-{1,32,128}.json`.

* `run_{aggregator,decryptor,client}_sim.sh` runs aggregation over 100,000 clients (with 10% offline) with bit vectors of length 1, 32, and 128. The experiments are specified in `experiments/configs/simplified-{1,32,128}.json`.

> **Note:** For faster benchmarking, these scripts simulate the one-time setup
> and run aggregation over a small set of duplicated client reports; this does
> not effect the servers' aggregation runtimes. To run the system without 
> the simulated steps, replace the `sim-setup` and `sim-generate` modes
> specified in the client scripts to `setup` and `generate`. (Note that this
> requires the client machine to have 250 GB of disk space for writing reports)

> **Tip:** If your aggregator machine runs out of memory during aggregation, lower 
> the `max_pending_batches` config option.

> **Note:** Setup takes longer than in Heli, since it encrypts every client's 
> key (in simulated mode, the aggregator does this). The aggregator finishes 
> setup in the background, and an aggregation that arrives early waits for it.

To run all three programs on one machine instead, in simulated mode, use `experiments/bin/run_local.sh` (like the other scripts, it needs `jq`). For example, from the repository root:
```bash
cargo build --release
experiments/bin/run_local.sh /tmp/helium-run experiments/configs/simplified-1.json
```
Logs are written to the given directory.


#### Config file reference

Experiment configs are JSON files. See the predefined configs in `experiments/configs/` as examples of the correct format. The configuration options are specified below:

| Field | Type | Description |
|-------|------|-------------|
| `num_clients` | number | Total number of clients to simulate. |
| `threshold` | number | Minimum number of clients that must participate for aggregation to succeed. |
| `dropouts` | number | Number of clients that drop out. |
| `length` | number | Number of data slots per client (vector length). |
| `prover` | object | Proof type: `{"type": "binary"}` or `{"type": "range", "bitlength": N}`. |
| `aggregator_addr` | string | Host:port the aggregator listens on (e.g. `"0.0.0.0:9000"`). |
| `decryptor_addr` | string | Host:port the decryptor listens on (e.g. `"0.0.0.0:9001"`). |
| `db_path` | string | Directory path for a local sled DB. |
| `max_pending_batches` | number (optional) | Max pending client report chunks on the aggregator. Default: `100`. |
| `reports_per_chunk` | number (optional) | Number of reports the aggregator combines into one processing chunk. Default: `10000`. |

## License

Heli is licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Helium depends on GMP through the `rug` crate; both are licensed under the LGPL.

Unless you explicitly state otherwise, any contribution submitted for inclusion in Heli by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.
