# Benchmark plan: Helium vs. Heli

This is a plan only. Nothing here has been run on cloud hardware. The only measurements so far are from one Apple M4 laptop (4 performance + 6 efficiency cores, 16 GB), quoted below as predictions to test.

The plan is built to cost a few dollars, not the $60 to $100 of the first draft. Section 3 explains why that loses almost nothing.

## 1. What the evaluation should show

1. **Light server, per round.** CPU time and bytes received as the number of dropouts grows. Helium should be flat; Heli should be linear. Where do they cross?
2. **Heavy server, per round.** How much time summing the encrypted keys and proving adds to a round, and how much less it sends to the light server.
3. **Setup, one time.** Light-server time per client, bytes sent to the heavy server per client, and heavy-server storage per client. This is where Helium is strictly worse than Heli.
4. **End to end.** Rows for Helium in the layout of Heli's Table 2 (10 million clients, 10% offline, vectors of length 1, 32, 128).

## 2. What the Heli paper did

From Section 6 of the paper (USENIX Security '26; full version at eprint 2026/059) and its artifact appendix:

* **Micro-benchmarks** (their Figures 4 to 6) ran on a single core of one AWS `c7i.4xlarge` (16 vCPUs, 32 GB). The appendix says they are single-threaded, use under 8 GB of RAM, and "can also be run on a smaller machine".
* **End to end** (their Table 2): heavy server on a `c7i.24xlarge` (96 vCPUs, 192 GB), light server on a `c7i.large` (2 vCPUs, 4 GB), in us-east-1 and us-east-2, with reports submitted from a second `c7i.24xlarge`. They price the 96-vCPU machine at $4.28 per hour.
* **A simplified configuration** that the artifact reviewers accepted in place of the full one: 100,000 clients on two `c7i.4xlarge` and one `c7i.large`, about 20 minutes, scaled to 10 million clients and 96 cores by `artifact-eval/estimate_e2e.py`. That script gets the light server's time by adding the dropout micro-benchmark (5.151 ms for 1 million dropouts) to the measured time at 100,000 clients.

Numbers to compare against. The code in this fork matches the revised numbers in the artifact appendix and the eprint version, not the ones printed in the USENIX version:

| Length | Heavy wall time (96 vCPUs) | Heavy → light | Light wall time | Light → heavy |
|---|---|---|---|---|
| 1 | 43.9 s | 3,000 KB | 7 ms | 0.048 KB |
| 32 | 873 s | 3,000 KB | 8 ms | 1 KB |
| 128 | 3,232 s | 3,000 KB | 12 ms | 4 KB |

Setup, as the paper estimates it: the light server registers 10 million clients in 2.5 hours with 1,145 MB of egress, about $0.32.

## 3. Why a few dollars is enough

* **Helium changes only three things**: the light server's dropout handling, one extra step on the heavy server (key sum and proof), and setup. The heavy server's main work, checking client reports, and the clients are untouched. Heli's published numbers for those carry over; there is no need to pay to re-measure them at 10 million clients.
* **The light server's work is single-threaded** in both systems, and Helium's does not depend on the number of clients or dropouts. One small run on a `c7i.large`, the paper's own light-server machine, gives the number that goes in the table.
* **Bytes do not depend on hardware.** The communication results from the laptop are already final.
* **The heavy server's extra step** is measured per dropout by `dropout-bench` on one 16-vCPU machine, the same machine the paper used for its micro-benchmarks.
* **End to end, mirror the paper's simplified configuration** instead of its full one: run at 100,000 clients and scale. The paper's artifact evaluation did exactly this.

What this gives up: no measured 96-core, 10-million-client run of the full system. Rows scaled from the simplified configuration have to be labeled as estimates, as in Heli's artifact. E4 below is a cheap way to get one real 10-million-client run for length 1.

## 4. Budget tiers

Prices are derived from the paper's $4.28 per hour for 96 vCPUs, which scales to about $0.71 per hour for a `c7i.4xlarge` and $0.09 per hour for a `c7i.large`. Check the console before provisioning.

| Tier | What | Machines | Cost |
|---|---|---|---|
| 0 | Laptop only: every result as a same-machine ratio, bytes exact | none | $0 |
| 1 (recommended) | E1 to E3 and E5 on the paper's hardware | one `c7i.4xlarge` + one `c7i.large`, about 3 hours | about $3 |
| 2 (optional) | Tier 1 plus E4, one real 10-million-client run at length 1 | same, about 3 more hours | about $3 more |

Ways to pay less or nothing:

* **Spot instances.** Every run here is short and restartable, so spot is safe. Discounts vary; expect roughly half off or better.
* **Credits.** New AWS and Google Cloud accounts come with trial credits that would cover all of this many times over, and student programs (GitHub Student Developer Pack, course credits from the CS 356 staff) are worth asking about. I have not verified current terms for any of these.
* **Stanford machines.** A shared campus cluster costs nothing, but its CPUs differ from the paper's and other jobs add noise. Fine for ratios; not for numbers placed next to Table 2.
* **Housekeeping.** Stop both VMs whenever you are not running something, delete the disks at the end, and set a $10 budget alert first.

If credits are on Google Cloud, use `c4-standard-16` (or `c3-standard-22`) and `c4-standard-2`, and say in the write-up that the CPUs are a newer generation than the paper's.

## 5. Predictions from the laptop

Single core, 10% dropouts, medians from `dropout-bench`:

| Clients | Dropouts | Heli light | Helium light | Heli heavy → light | Helium heavy → light | Helium key sum | Helium proof |
|---|---|---|---|---|---|---|---|
| 100,000 | 10,000 | 0.09 ms | 3.2 ms | 30 KB | 576 B | 52 ms | 282 ms |
| 1,000,000 | 100,000 | 0.51 ms | 3.2 ms | 300 KB | 576 B | 548 ms | 2.5 s |
| 10,000,000 | 1,000,000 | 4.8 ms | 3.5 ms | 3 MB | 576 B | 1.1 s (10 threads) | 6.9 s (10 threads) |

The last row is the paper's headline point. It was run with all ten cores, so its two heavy-server columns are wall-clock times on ten threads, and its light-server columns (single-threaded regardless) were taken on a busy machine.

Setup costs the light server about 3.1 to 3.9 ms per client on one core, and each client's record is 728 bytes on the wire.

What these imply, to be confirmed or refuted on server hardware:

* **CPU crossover near 700,000 dropouts.** Heli's light server spends about 4.8 ns per dropout on the laptop, so it matches Helium's 3.2 to 3.5 ms at roughly 700,000 dropouts. At the paper's headline point (1 million dropouts) the laptop measures Helium about 1.4x faster; below a few hundred thousand dropouts Helium is slower, by up to 60x at small scales. The paper's own figure for Heli is 5.24 ms per million dropouts, inside a 7 ms round at length 1. Whether the 1.4x holds on a `c7i.large` is the main unknown: it depends on how fast that CPU does a Paillier decryption relative to AES, and it costs cents to find out (E2).
* **Bytes cross at 192 dropouts.** 576 bytes against 3 bytes per dropout. At 1 million dropouts the heavy server sends 0.6 KB instead of 3,000 KB.
* **Heavy-server overhead is small.** At 1 million dropouts the key sum and proof took 8 seconds on the laptop's ten cores (at most 80 core-seconds), against 43.9 s x 96 cores of existing work at length 1.
* **Setup is the cost.** At 10 million clients: about 9 core-hours of encryption on top of Heli's 2.5 hours, 7.3 GB sent to and stored by the heavy server instead of 1.1 GB, and about 8 GB of heavy-server RAM to hold the records.

## 6. Builds

Run both systems on the same VMs with the same toolchain and flags.

* **Helium:** this repository, branch `helium`.
* **Heli baseline:** upstream `main` at `119e970`, unmodified. `git worktree add ../heli-baseline main` gives a second checkout to build.

Both: `export RUSTFLAGS="-C target-cpu=native"` and `cargo build --release`. Helium also needs `m4` and `make` for GMP. Build on the `c7i.4xlarge` and copy the `target/release` binaries to the `c7i.large`; they share a CPU family, and building on 4 GB is slow.

Clone this fork on the VMs and check out the `helium` branch.

## 7. Machines

| Name | AWS type | Role | Disk |
|---|---|---|---|
| BIG | `c7i.4xlarge` (16 vCPUs, 32 GB) | Micro-benchmarks; heavy server and client in end-to-end runs | 40 GB |
| SMALL | `c7i.large` (2 vCPUs, 4 GB) | Light server | 16 GB |

Ubuntu 22.04, as in the paper. Open TCP ports 9000 and 9001 between the two.

* **The client shares BIG with the heavy server.** In simulated mode the client submits its reports first and is idle while the heavy server aggregates, and the paper's script computes upload time from byte counts, not from a measurement. So a third machine buys nothing.
* **One region is enough.** The paper puts the two servers in different regions. That affects only the round trip in the aggregator's "Decrypt time", not any CPU time. To match the paper exactly, put SMALL in us-east-1 and BIG in us-east-2; cross-region traffic at these sizes costs cents.

## 8. Experiments

### E0. Laptop (free, partly done)

The table in Section 5. Rerun `dropout-bench` after any code change. This alone supports every claim as a ratio between the two systems on one machine.

### E1. Micro-benchmarks on BIG (about 1.5 hours)

Mirrors the data behind Heli's Figures 4 and 6 (`artifact-eval/data/dropout_10.csv` and `dropout.csv`).

```bash
# (a) Growing deployment, 10% offline, everything on one core
RAYON_NUM_THREADS=1 cargo run --release --bin dropout-bench -- -c 100 1000 10000 100000 1000000 -d 10
# (b) 10 million clients, growing dropout rate, all cores for setup
cargo run --release --bin dropout-bench -- -c 10000000 -d 1 5 10 20
```

* (b) uses every core to encrypt the dropped-out clients' records, which is most of its running time (3.6 million records). The light-server columns are single-threaded regardless. The heavy-server columns in (b) are then 16-thread wall-clock times; multiply by the thread count for an upper bound on core-seconds, or rerun the 10% point with `RAYON_NUM_THREADS=1`.
* Stopping at 20% is deliberate. Heli's line is straight and Helium's is flat, so more points cost encryption time without adding information. Above 50% Heli names the online set instead, so its cost peaks at 50%; say so in the text rather than paying to plot it.
* Optional sensitivity point: change `PAILLIER_MODULUS_BITS` in `src/dropout.rs` to 3072 (128-bit security, matching Heli's group) and rerun (a) at 100,000 clients. Expect Helium's light server to slow by roughly 3x.

### E2. Light server on SMALL (about 15 minutes)

```bash
# Helium: its cost depends on neither number, so a small point is enough
RAYON_NUM_THREADS=1 ./dropout-bench -c 10000 -d 10
# Heli baseline, from the baseline checkout
cargo criterion decode
```

This is the cheapest and most important run in the plan: it replaces the laptop's 3.2 ms with the number for the paper's light-server machine.

### E3. End to end, simplified configuration (about 45 minutes)

Both builds, `experiments/configs/simplified-{1,32,128}.json` (100,000 clients, 10,000 offline), 5 rounds each. Heavy server and client on BIG, light server on SMALL.

Then scale to 10 million clients as `artifact-eval/estimate_e2e.py` does, with three changes for Helium's rows:

* **Light server time:** use the measured time as is. Heli's script adds 5.151 ms for the dropout keys of 1 million dropouts; Helium has no such term.
* **Heavy server time:** scale as the script does, then add the key sum and proof time for 1 million dropouts from E1(b).
* **Heavy → light bytes:** 596 bytes plus the mask request, instead of the script's 3 bytes per dropout.

At 100,000 clients Helium's light server will be slower than Heli's (about 3 ms against 0.1 ms). That is expected; the crossover is at larger scales, and E1 and E2 are what show it.

### E4. One real run at 10 million clients (optional, about 3 hours)

`full-1.json` for both builds, 3 rounds each, on the same two machines. It checks the flat light-server time inside the real system and the heavy server's memory with 10 million records loaded.

* On 16 vCPUs, expect Helium's simulated setup to take 1 to 1.5 hours and each length-1 round about 5 minutes (the paper's 43.9 s on 96 vCPUs, times six).
* Memory is the risk: 32 GB has to hold the reports and about 8 GB of key records. If the aggregator runs out, lower `max_pending_batches` as Heli's README says, or resize BIG to a `c7i.8xlarge` (64 GB, about $1.43 per hour).
* Restart the servers without `--clear-db` between rounds so the setup is paid once.
* Skip lengths 32 and 128 at this scale. They would take hours on 16 vCPUs and mostly re-measure Heli, since dropout handling does not depend on the vector length.

### E5. Real setup (about 20 minutes)

Simulated setup skips registration. Run the real thing once at 100,000 clients (`--mode setup`, then `generate`, then `aggregate`) to measure the light server's registration throughput on SMALL and the setup traffic, and to check a non-dummy aggregate on cloud hardware. Scale linearly to 10 million clients and put it next to the paper's 2.5 hours and 1,145 MB.

## 9. Procedure for the end-to-end runs

On BIG, clone and build both checkouts and copy the binaries to SMALL. Rewrite the addresses in the configs to the VMs' internal IPs (the upstream scripts in `experiments/bin/` show the `jq` command). Then, for one build at a time and from that build's checkout:

```bash
# BIG
cargo run --release --bin exp_aggregator -- <config> --clear-db
# SMALL
./exp_decryptor <config> --clear-db
# BIG, second terminal
cargo run --release --bin exp_client -- <config> --mode sim-setup --clear-db
cargo run --release --bin exp_client -- <config> --mode sim-generate
cargo run --release --bin exp_client -- <config> --mode aggregate   # repeat for more rounds
```

* Setup is per client count, not per config: configs with the same `num_clients` can share one setup, as the upstream scripts do.
* For both builds, wait for "Setup complete" in the aggregator log before aggregating. Heli's aggregator fails an early aggregation. Helium's makes it wait, but then the client's own timer and the aggregator's setup byte counts include the wait.
* Never clear only one of the two servers' databases.
* Smoke-test everything on BIG alone first with `experiments/bin/run_local.sh <dir> <configs...>`.

What to record from the logs:

| Quantity | Process | Log line |
|---|---|---|
| Light-server time per round | decryptor | `Decrypt mask for context ...` then `Dropout proof:` (Helium) or `Dropout key:` (Heli), `Mask computation:`, `Total:` |
| Bytes heavy → light and back, per round | decryptor | `Sent ...B, Recv ...B` after each mask |
| Heavy-server round time | aggregator | `Wall-clock time:`, and the `Timing breakdown` lines |
| Key sum and proof time | aggregator | `Dropout proof for N dropouts:` (Helium only) |
| Setup time | aggregator, decryptor | `Setup complete: ...` (in simulated mode the aggregator does the work, so the light server's setup cost comes only from E5 and `dropout-bench`) |
| Setup traffic | aggregator, decryptor | the `Sent ...B, Recv ...B` line right after setup (meaningful only in E5) |
| Heavy-server memory | aggregator | peak RSS, from `/usr/bin/time -v` |

Report medians over the rounds, and the minimum and maximum.

## 10. Tables and figures to produce

1. **Light server vs. deployment size** at 10% offline, both systems, CPU and bytes (log-log). Same shape as Heli's Figure 4 (left), from E1(a).
2. **Light server vs. dropout rate** at 10 million clients, CPU and bytes, from E1(b) and E2. This is the figure that shows the linear term going away, and the crossover.
3. **End-to-end table** in the layout of Heli's Table 2, with the paper's rows for Heli and estimated rows for Helium, from E3 (and one measured row from E4 if run).
4. **Heavy-server overhead**: key sum and proof time against Heli's round time, from E1.
5. **Setup costs**: time per client, bytes per client, storage, for both systems, from E1 and E5.

`dropout-bench` prints tab-separated values in the same style as the files in `artifact-eval/data/`. The plotting scripts there do not know about its columns yet; extending them is remaining work.

## 11. Time and cost

| Step | Machine time | Cost at list price |
|---|---|---|
| Build, smoke test | 30 min, both | $0.40 |
| E1 | 1.5 h on BIG | $1.10 |
| E2 | 15 min on SMALL | $0.02 |
| E3 | 45 min, both | $0.60 |
| E5 | 20 min, both | $0.30 |
| **Tier 1 total** | about 3 h | **about $3** with disks and traffic |
| E4 (optional) | 3 h, both | about $3 |

Allow two or three times that for mistakes and reruns. It still stays under $20, and under $10 on spot.

## 12. Things that can go wrong

* **Different CPUs for the two builds.** Compare the two systems only on the same VM instance, back to back.
* **Estimated rows passed off as measured.** Anything scaled from 100,000 clients must be labeled, as Heli's artifact labels its own.
* **Simulated rounds return a dummy result.** That is expected (reports are duplicated), so it does not check correctness. E5 and the unit tests do.
* **Byte counters are per process.** Read the `Sent/Recv` line that follows the event of interest, since each one resets the counter.
* **Hyperthreads.** A `c7i.large` has one physical core with two threads. Keep the light-server measurements single-threaded and do not run anything else on SMALL during them.
* **Paillier at 2048 bits is about 112-bit security**, slightly below the rest of the system. Say so next to any headline number, and include the 3072-bit sensitivity point from E1 if time allows.
* **Not constant-time everywhere.** The exponentiations with secret exponents use GMP's constant-time routine; the rest of the Paillier code does not. Mention it as a limitation rather than tuning it away.
* **The security argument is a sketch.** The evaluation measures cost; it does not validate soundness.
