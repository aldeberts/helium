//! Compares how Heli and Helium handle dropped-out clients.
//!
//! For each client count it measures the light server's work per round under
//! both schemes, the heavy server's extra work under Helium, the bytes the
//! heavy server sends to the light server, and Helium's per-client setup cost.
//! Results are printed as tab-separated values.
//!
//! Times are wall-clock medians, so set `RAYON_NUM_THREADS=1` for single-core numbers.
//! The light-server times cover deriving the mask key and computing the mask,
//! not parsing the heavy server's message.

use clap::Parser;
use heli::{
    agg_only_enc::AggOnlyEnc,
    crypto::{KHPRF, Scalar},
    dropout::{DropoutProverKey, DropoutVerifierKey, KeyRecord},
};
use rand::seq::index;
use rand_core::OsRng;
use rayon::prelude::*;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};

#[derive(Parser)]
struct Config {
    /// Number of measurement iterations to run
    #[arg(short, long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..))]
    iterations: u32,

    /// Number of warmup iterations before measurement
    #[arg(short, long, default_value_t = 2)]
    warmup: usize,

    /// Numbers of clients to benchmark (space-separated list)
    #[arg(short, long, num_args = 1.., value_delimiter = ' ', default_value = "1000 10000 100000")]
    clients: Vec<usize>,

    /// Percentages of clients that drop out (space-separated list)
    #[arg(short, long, num_args = 1.., value_delimiter = ' ', default_value = "10")]
    dropout_percent: Vec<f64>,

    /// Length of input vectors
    #[arg(short, long, default_value_t = 1)]
    length: usize,
}

const CONTEXT: u32 = 42;

/// Bytes per client index in Heli's packed dropout list.
const HELI_BYTES_PER_INDEX: usize = 3;

/// Number of key records generated at a time when setting up a benchmark.
const SETUP_CHUNK_SIZE: usize = 1 << 12;

struct Measurement {
    num_clients: usize,
    num_dropouts: usize,
    heli_light: Duration,
    helium_light: Duration,
    helium_sum_keys: Duration,
    helium_quotient: Duration,
    heli_bytes: usize,
    helium_bytes: usize,
    setup_per_client: Duration,
    record_bytes: usize,
}

/// The median time of `run` over the configured number of iterations.
fn median_time<T>(config: &Config, mut run: impl FnMut() -> T) -> Duration {
    for _ in 0..config.warmup {
        black_box(run());
    }
    let mut times: Vec<Duration> = (0..config.iterations)
        .map(|_| {
            let start = Instant::now();
            black_box(run());
            start.elapsed()
        })
        .collect();
    times.sort();
    times[times.len() / 2]
}

fn measure(config: &Config, num_clients: usize, dropout_percent: f64) -> Measurement {
    let num_dropouts = (num_clients as f64 * dropout_percent / 100.0).round() as usize;
    eprintln!("Setting up {num_clients} clients with {num_dropouts} dropouts...");

    let (secret_key, eval_keys) = AggOnlyEnc::setup(num_clients, &mut OsRng);
    let dropouts = index::sample(&mut OsRng, num_clients, num_dropouts).into_vec();

    // Proving only reads the records of the dropped-out clients, so the rest
    // share a placeholder instead of each costing an encryption.
    let verifier_key = DropoutVerifierKey::generate(num_clients, &mut OsRng);
    let dropout_keys: Vec<(u32, Scalar)> = dropouts
        .iter()
        .map(|&id| (id as u32, *eval_keys[id]))
        .collect();
    let setup_keys = match dropout_keys.is_empty() {
        true => vec![(0, *eval_keys[0])],
        false => dropout_keys,
    };
    let setup_start = Instant::now();
    let setup_records: Vec<KeyRecord> = setup_keys
        .chunks(SETUP_CHUNK_SIZE)
        .flat_map(|chunk| verifier_key.key_records(chunk))
        .collect();
    let setup_per_client = setup_start.elapsed() / setup_keys.len() as u32;

    let placeholder = setup_records[0].clone();
    let record_bytes = bincode::serialized_size(&placeholder).unwrap() as usize;
    let mut records = vec![placeholder; num_clients];
    for (&id, record) in dropouts.iter().zip(setup_records) {
        records[id] = record;
    }
    let prover_key = DropoutProverKey::new(verifier_key.paillier_public_key().clone(), records);
    let dropout_ids: Vec<u32> = dropouts.iter().map(|&id| id as u32).collect();

    eprintln!("Benchmarking...");
    let proof = prover_key.prove(&dropout_ids).unwrap();
    let verified = verifier_key.verify(&proof).unwrap();
    let expected_key_sum: Scalar = dropouts.iter().map(|&id| *eval_keys[id]).sum();
    assert_eq!(verified.count, num_dropouts);
    assert_eq!(verified.key_sum, expected_key_sum);

    // Heli's heavy server names whichever of the dropped-out and online sets is smaller.
    let invert = 2 * num_dropouts > num_clients;
    let heli_list = if invert {
        let mut online = vec![true; num_clients];
        dropouts.iter().for_each(|&id| online[id] = false);
        (0..num_clients).filter(|&id| online[id]).collect()
    } else {
        dropouts.clone()
    };

    // Each scheme's light server derives the mask key, then computes the mask.
    let heli_light = median_time(config, || {
        AggOnlyEnc::decrypt_mask(&secret_key, CONTEXT, &heli_list, invert, config.length)
    });
    let helium_light = median_time(config, || {
        // As in `decrypt_mask`, with the verified key sum standing in for the mask key.
        let key_sum = verifier_key.verify(&proof).unwrap().key_sum;
        (0..config.length)
            .into_par_iter()
            .map(|i| KHPRF::evaluate_context(&key_sum, CONTEXT, i))
            .collect::<Vec<_>>()
    });
    let helium_sum_keys = median_time(config, || prover_key.sum_keys(&dropout_ids));
    let helium_quotient = median_time(config, || prover_key.commit_quotient(&dropout_ids));

    Measurement {
        num_clients,
        num_dropouts,
        heli_light,
        helium_light,
        helium_sum_keys,
        helium_quotient,
        heli_bytes: HELI_BYTES_PER_INDEX * heli_list.len(),
        helium_bytes: bincode::serialized_size(&proof).unwrap() as usize,
        setup_per_client,
        record_bytes,
    }
}

fn millis(duration: Duration) -> String {
    format!("{:.3}", duration.as_secs_f64() * 1000.0)
}

fn main() {
    let config = Config::parse();

    println!(
        "clients\tdropouts\theli_light_ms\thelium_light_ms\thelium_sum_keys_ms\t\
         helium_quotient_ms\theli_bytes\thelium_bytes\tsetup_per_client_ms\trecord_bytes"
    );
    for &num_clients in &config.clients {
        for &dropout_percent in &config.dropout_percent {
            let m = measure(&config, num_clients, dropout_percent);
            println!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                m.num_clients,
                m.num_dropouts,
                millis(m.heli_light),
                millis(m.helium_light),
                millis(m.helium_sum_keys),
                millis(m.helium_quotient),
                m.heli_bytes,
                m.helium_bytes,
                millis(m.setup_per_client),
                m.record_bytes,
            );
        }
    }
}
