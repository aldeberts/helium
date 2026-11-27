use crate::{
    BATCH_REPORT_SIZE,
    agg_only_enc::{AggOnlyEnc, Ciphertext},
    crypto::{
        G, Scalar,
        hpke::{ServerKeys, hpke_decrypt},
        paillier,
        prf::ScalarPRF,
    },
    dropout::{DropoutProof, DropoutProverKey, DropoutVerifierKey, KeyRecord},
    proofs::{Proof, VerifierKey},
    system::{ProverType, messages::*},
};

use anyhow::{Result, anyhow, ensure};
use group::Group;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rayon::prelude::*;
use sled::Db;
use std::{collections::HashSet, sync::Arc, time::Instant};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, RwLock, mpsc, watch},
};
use tracing::{debug, error, info};

const VERIFY_BATCH_SIZE: usize = 128;

/// Database key of the key commitments. They are the last thing the setup
/// writes, so their presence marks it as complete.
const KEY_COMMITMENTS_DB_KEY: &[u8] = b"kc";

const DROPOUT_PAILLIER_KEY_DB_KEY: &[u8] = b"dropout_paillier_key";
const DROPOUT_RECORDS_DB_PREFIX: &[u8] = b"dropout_records_";

/// Number of clients whose dropout key records share one database entry.
const KEY_RECORDS_PER_DB_ENTRY: usize = 4096;

/// Number of clients whose dropout key records are derived at a time in a simulated setup.
const SIMULATED_SETUP_CHUNK_SIZE: usize = 1 << 16;

pub struct Aggregator {
    addr: String,
    state: Arc<AggregatorState>,
}

/// Progress of the one-time setup with the decryptor.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SetupState {
    Pending,
    Complete,
    Failed,
}

pub struct AggregatorState {
    num_clients: usize,
    #[allow(dead_code)]
    threshold: usize,
    db: Db,
    hpke_keys: ServerKeys,
    current_ctx: RwLock<Option<u32>>,
    setup: watch::Sender<SetupState>,
    /// Loaded from the database on first use after a restart.
    dropout_key: OnceCell<Arc<DropoutProverKey>>,
    request_send: OnceCell<mpsc::Sender<Message>>,
    mask_recv: Mutex<Option<mpsc::Receiver<Message>>>,
    max_pending_batches: usize,
    reports_per_chunk: usize,
}

impl Aggregator {
    pub fn new(
        addr: &str,
        num_clients: usize,
        threshold: usize,
        _prover: ProverType,
        db: Db,
        hpke_keys: ServerKeys,
        max_pending_batches: usize,
        reports_per_chunk: usize,
    ) -> Self {
        let setup = match db.contains_key(KEY_COMMITMENTS_DB_KEY) {
            Ok(true) => SetupState::Complete,
            _ => SetupState::Pending,
        };
        let state = Arc::new(AggregatorState {
            num_clients,
            threshold,
            db,
            hpke_keys,
            current_ctx: RwLock::new(None),
            setup: watch::Sender::new(setup),
            dropout_key: OnceCell::new(),
            request_send: OnceCell::new(),
            mask_recv: Mutex::new(None),
            max_pending_batches,
            reports_per_chunk,
        });

        Self {
            addr: addr.to_string(),
            state,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Aggregator listening on {}", self.addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            debug!("Connection from {}", addr);
            tokio::spawn(Self::handle_connection(socket, self.state.clone()));
        }
    }

    async fn handle_connection(mut socket: TcpStream, state: Arc<AggregatorState>) {
        let message = match read_message(&mut socket).await {
            Ok(msg) => msg,
            Err(e) => {
                send_error_message(&mut socket, &format!("Failed to read: {e}"))
                    .await
                    .ok();
                return;
            }
        };

        match message {
            Message::DecryptorInit {} => {
                Self::handle_decryptor_init(socket, state).await;
            }
            Message::AggregateStreamStart {
                context,
                num_batches,
                binary,
                bitlength,
                simulated,
                sim_dropouts,
            } => {
                Self::handle_aggregate_stream(
                    &mut socket,
                    state,
                    context,
                    num_batches,
                    binary,
                    bitlength,
                    simulated,
                    sim_dropouts,
                )
                .await;
            }
            _ => {
                send_error_message(&mut socket, "Invalid request")
                    .await
                    .ok();
            }
        }
    }

    // --- Aggregate stream: combined submit + aggregate, fully in-memory ---

    async fn handle_aggregate_stream(
        socket: &mut TcpStream,
        state: Arc<AggregatorState>,
        context: u32,
        num_batches: usize,
        binary: bool,
        bitlength: Option<usize>,
        simulated: bool,
        sim_dropouts: Vec<u32>,
    ) {
        // Ensure no other aggregation is in progress
        {
            let mut current = state.current_ctx.write().await;
            if current.is_some() {
                send_error_message(socket, "Another aggregation is already in progress")
                    .await
                    .ok();
                return;
            }
            *current = Some(context);
        }

        info!(
            "Aggregate stream for context {context}: {num_batches} batches, simulated={simulated}"
        );

        let result = Self::run_aggregate_stream(
            socket,
            &state,
            context,
            num_batches,
            binary,
            bitlength,
            simulated,
            sim_dropouts,
        )
        .await;

        match result {
            Ok(data) => {
                write_message(socket, &Message::AggregationResponse { result: data })
                    .await
                    .ok();
            }
            Err(e) => {
                error!("Aggregate stream failed: {e}");
                send_error_message(socket, &format!("Aggregation failed: {e}"))
                    .await
                    .ok();
            }
        }

        info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
        reset_byte_counters();

        *state.current_ctx.write().await = None;
    }

    async fn run_aggregate_stream(
        socket: &mut TcpStream,
        state: &AggregatorState,
        context: u32,
        num_batches: usize,
        binary: bool,
        bitlength: Option<usize>,
        simulated: bool,
        sim_dropouts: Vec<u32>,
    ) -> Result<Vec<u64>> {
        // Setup encrypts every client's key, so it may still be running.
        if *state.setup.borrow() == SetupState::Pending {
            info!("Waiting for setup to complete");
        }
        let mut setup = state.setup.subscribe();
        let setup = *setup
            .wait_for(|&setup| setup != SetupState::Pending)
            .await?;
        ensure!(setup == SetupState::Complete, "Setup failed");

        let vk = Self::build_vk(state, binary, bitlength)?;
        let dropout_key = Self::dropout_key(state).await?;
        let hpke_sk = state.hpke_keys.sk.clone();

        // Bounded channel: once full, the reader blocks, applying backpressure to the network
        let (batch_tx, mut batch_rx) =
            mpsc::channel::<Vec<(u32, Vec<u8>)>>(state.max_pending_batches);

        // Processor thread: pulls batches from the channel, decrypts/verifies/aggregates
        let proc_context = context;
        let proc_reports_per_chunk = state.reports_per_chunk as f64;
        let processor_handle = std::thread::spawn(move || {
            let mut all_online = Vec::new();
            let mut aggregate: Option<Ciphertext> = None;
            let mut total_decrypt = std::time::Duration::ZERO;
            let mut total_verify = std::time::Duration::ZERO;
            let mut total_agg = std::time::Duration::ZERO;
            let mut chunks_processed = 0usize;
            let num_chunks =
                (((BATCH_REPORT_SIZE * num_batches) as f64) / proc_reports_per_chunk).ceil();

            while let Some(reports) = batch_rx.blocking_recv() {
                let (online, agg, dt, vt, at) = process_chunk(&hpke_sk, &vk, proc_context, reports);
                total_decrypt += dt;
                total_verify += vt;
                total_agg += at;
                all_online.extend(online);
                aggregate = match (aggregate, agg) {
                    (Some(a), Some(b)) => Some(a + b),
                    (Some(a), None) => Some(a),
                    (None, b) => b,
                };
                chunks_processed += 1;
                if chunks_processed % 10 == 0 {
                    info!("Processed chunks {chunks_processed}/{num_chunks}");
                }
            }

            info!(
                "Timing breakdown:\n\tHPKE Decrypt: {:?}\n\tVerify: {:?}\n\tAggregate: {:?}",
                total_decrypt, total_verify, total_agg
            );
            (all_online, aggregate)
        });

        // Reader loop: read batches from network, combine into larger chunks,
        // then pipe to processor via bounded channel (backpressure when full).
        let recv_start = Instant::now();
        let mut total_reports = 0usize;
        let mut chunk = Vec::with_capacity(state.reports_per_chunk);
        for _ in 0..num_batches {
            let message = read_message(socket).await?;
            if let Message::BatchEncryptedClientReports { reports, .. } = message {
                total_reports += reports.len();
                if simulated {
                    chunk.extend(
                        reports
                            .into_iter()
                            .map(|(id, data)| (id % BATCH_REPORT_SIZE as u32, data)),
                    );
                } else {
                    chunk.extend(reports);
                }
                if chunk.len() >= state.reports_per_chunk {
                    batch_tx
                        .send(std::mem::replace(
                            &mut chunk,
                            Vec::with_capacity(state.reports_per_chunk),
                        ))
                        .await
                        .map_err(|_| anyhow!("Processor thread died"))?;
                }
            } else {
                return Err(anyhow!("Expected BatchEncryptedClientReports"));
            }
        }
        if !chunk.is_empty() {
            batch_tx
                .send(chunk)
                .await
                .map_err(|_| anyhow!("Processor thread died"))?;
        }
        drop(batch_tx);
        info!(
            "Received {} reports in {} batches ({:?})",
            total_reports,
            num_batches,
            recv_start.elapsed()
        );

        // Wait for processor to finish
        let (online_clients, aggregate) = processor_handle
            .join()
            .map_err(|_| anyhow!("Processor thread panicked"))?;
        let aggregate = aggregate.ok_or_else(|| anyhow!("No valid reports"))?;

        let online_count = online_clients.len();
        info!("Aggregation: {online_count} online clients (simulated: {simulated})");

        let decrypt_start = Instant::now();
        let dropouts: Vec<u32> = if simulated {
            sim_dropouts
        } else {
            let online_set: HashSet<_> = online_clients.iter().copied().collect();
            (0..state.num_clients as u32)
                .filter(|i| !online_set.contains(i))
                .collect()
        };

        // Sum the dropped-out clients' encrypted keys and prove the sum
        let dropout_count = dropouts.len();
        let proof_start = Instant::now();
        let dropout_proof =
            tokio::task::spawn_blocking(move || dropout_key.prove(&dropouts)).await??;
        info!(
            "Dropout proof for {dropout_count} dropouts: {:?}",
            proof_start.elapsed()
        );

        // Request decryption mask
        let mask =
            Self::request_decryption_mask(state, context, dropout_proof, aggregate.len()).await?;
        let mask = match mask {
            Message::DecryptMaskResponse { mask } => mask,
            Message::Error(e) => return Err(anyhow!("Decryptor error: {e}")),
            _ => return Err(anyhow!("Unexpected decryptor response")),
        };

        // Decrypt aggregate
        let max_dlog = if binary {
            online_count
        } else {
            online_count * (1 << bitlength.unwrap_or(8))
        } as u64;

        let result = AggOnlyEnc::decrypt(&aggregate, &mask, max_dlog);
        info!(
            "\n\tDecrypt time: {:?}\n\tWall-clock time: {:?}",
            decrypt_start.elapsed(),
            recv_start.elapsed()
        );

        match result {
            Ok(r) => Ok(r),
            Err(_) if simulated => {
                info!("Simulated round - returning dummy result");
                let length = (context & 0xFFFF) as usize;
                Ok(vec![0u64; length.min(128)])
            }
            Err(e) => Err(e.into()),
        }
    }

    // --- Verifier key ---

    fn build_vk(
        state: &AggregatorState,
        binary: bool,
        bitlength: Option<usize>,
    ) -> Result<VerifierKey> {
        let g_comm = Proof::get_g_comm();
        let data = state
            .db
            .get(KEY_COMMITMENTS_DB_KEY)?
            .ok_or_else(|| anyhow!("No key commitments in DB"))?;
        let key_commitments = Self::deserialize_key_commitments(&data)?;

        Ok(if binary {
            VerifierKey::Binary {
                g_comm,
                key_commitments,
            }
        } else {
            VerifierKey::Range {
                g_comm,
                key_commitments,
                bitlength: bitlength
                    .ok_or_else(|| anyhow!("bitlength required for range proof"))?,
            }
        })
    }

    fn deserialize_key_commitments(data: &[u8]) -> Result<Vec<G>> {
        // Format: num_clients (u64) + [chunk_len (u64) + chunk_data]*
        let num_clients = u64::from_le_bytes(data[0..8].try_into()?) as usize;
        let mut offset = 8;
        let mut chunks_data = Vec::new();

        while offset < data.len() {
            let chunk_len = u64::from_le_bytes(data[offset..offset + 8].try_into()?) as usize;
            offset += 8;
            chunks_data.push(&data[offset..offset + chunk_len]);
            offset += chunk_len;
        }

        let chunks: Vec<Vec<G>> = chunks_data
            .into_par_iter()
            .map(|chunk_data| bincode::deserialize(chunk_data).unwrap())
            .collect();

        let mut result = Vec::with_capacity(num_clients);
        for chunk in chunks {
            result.extend(chunk);
        }

        Ok(result)
    }

    // --- Decryptor connection ---

    async fn handle_decryptor_init(socket: TcpStream, state: Arc<AggregatorState>) {
        let (request_send, request_recv) = mpsc::channel(10);
        let (mask_send, mask_recv) = mpsc::channel(10);
        state.request_send.set(request_send).ok();
        *state.mask_recv.lock().await = Some(mask_recv);

        tokio::spawn(async move {
            if let Err(e) =
                Self::handle_decryptor_connection(socket, state, request_recv, mask_send).await
            {
                error!("Decryptor connection error: {e:?}");
            }
        });
    }

    async fn handle_decryptor_connection(
        mut socket: TcpStream,
        state: Arc<AggregatorState>,
        mut request_recv: mpsc::Receiver<Message>,
        mask_send: mpsc::Sender<Message>,
    ) -> Result<()> {
        if *state.setup.borrow() == SetupState::Complete {
            info!("Key commitments already exist, skipping setup");
            write_message(&mut socket, &Message::SetupAlreadyComplete {}).await?;
        } else {
            let result = Self::run_setup(&mut socket, &state).await;
            let setup = match result {
                Ok(()) => SetupState::Complete,
                Err(_) => SetupState::Failed,
            };
            state.setup.send_replace(setup);
            result?;
        }

        while let Some(request) = request_recv.recv().await {
            write_message(&mut socket, &request).await?;
            let response = read_message(&mut socket).await?;
            mask_send.send(response).await.ok();
        }
        Ok(())
    }

    /// Runs the one-time setup: receives (or, if simulated, derives) each
    /// client's key commitment and dropout key record, and persists them.
    async fn run_setup(socket: &mut TcpStream, state: &AggregatorState) -> Result<()> {
        write_message(socket, &Message::Success {}).await?;

        let setup_start = Instant::now();
        let num_clients = state.num_clients;

        let (key_commitments, dropout_key) = match read_message(socket).await? {
            Message::SimulateSetup {} => {
                let keys =
                    tokio::task::spawn_blocking(move || simulated_client_keys(num_clients)).await?;
                info!(
                    "Simulated setup: computed keys for {num_clients} clients in {:?}",
                    setup_start.elapsed()
                );
                write_message(socket, &Message::Success {}).await?;
                keys
            }
            Message::DropoutSetup { paillier_key } => {
                write_message(socket, &Message::Success {}).await?;

                let mut key_commitments = vec![G::generator(); num_clients];
                let mut key_records = vec![None; num_clients];
                let mut received = 0;
                while received < num_clients {
                    let Message::ClientKeysBatch { keys } = read_message(socket).await? else {
                        return Err(anyhow!("Expected ClientKeysBatch"));
                    };
                    received += keys.len();
                    for (idx, key_comm, key_record) in keys {
                        let idx = idx as usize;
                        ensure!(idx < num_clients, "Client index out of range");
                        key_commitments[idx] = key_comm;
                        key_records[idx] = Some(key_record);
                    }
                    write_message(socket, &Message::Success {}).await?;
                }
                let key_records = key_records
                    .into_iter()
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| anyhow!("Missing client keys"))?;
                (
                    key_commitments,
                    DropoutProverKey::new(paillier_key, key_records),
                )
            }
            _ => return Err(anyhow!("Expected SimulateSetup or DropoutSetup")),
        };

        let dropout_key = Arc::new(dropout_key);
        let db = state.db.clone();
        let dropout_key_clone = dropout_key.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_start = Instant::now();
            store_dropout_key(&db, &dropout_key_clone)?;
            db.insert(
                KEY_COMMITMENTS_DB_KEY,
                serialize_key_commitments(&key_commitments),
            )?;
            db.flush()?;
            info!("Wrote client keys to DB in {:?}", write_start.elapsed());
            Ok(())
        })
        .await??;
        state.dropout_key.set(dropout_key).ok();

        info!(
            "Setup complete: keys for {} clients in {:?}",
            state.num_clients,
            setup_start.elapsed()
        );
        info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
        reset_byte_counters();
        Ok(())
    }

    /// The key for proving dropout-key sums, read from the database if this
    /// process did not run the setup itself.
    async fn dropout_key(state: &AggregatorState) -> Result<Arc<DropoutProverKey>> {
        let load = || async {
            let db = state.db.clone();
            let num_clients = state.num_clients;
            let load_start = Instant::now();
            let key = tokio::task::spawn_blocking(move || load_dropout_key(&db, num_clients));
            let key = Arc::new(key.await??);
            info!("Loaded dropout key from DB in {:?}", load_start.elapsed());
            Ok::<_, anyhow::Error>(key)
        };
        Ok(state.dropout_key.get_or_try_init(load).await?.clone())
    }

    // --- Decryption mask request ---

    async fn request_decryption_mask(
        state: &AggregatorState,
        context: u32,
        dropout_proof: DropoutProof,
        length: usize,
    ) -> Result<Message> {
        let sender = state
            .request_send
            .get()
            .ok_or_else(|| anyhow!("Decryptor not connected"))?;
        sender
            .send(Message::DecryptMaskRequest {
                context,
                dropout_proof,
                length,
            })
            .await
            .map_err(|_| anyhow!("Failed to send decrypt request"))?;

        let mut guard = state.mask_recv.lock().await;
        let recv = guard
            .as_mut()
            .ok_or_else(|| anyhow!("Decryptor not connected"))?;
        recv.recv()
            .await
            .ok_or_else(|| anyhow!("Decryptor disconnected"))
    }
}

// --- Client keys (setup material) ---

/// Derives every client's key commitment and dropout key record from the
/// fixed keys of a simulated setup.
fn simulated_client_keys(num_clients: usize) -> (Vec<G>, DropoutProverKey) {
    let prf = ScalarPRF::new(&SIMULATE_PRF_KEY);
    let g_comm = Proof::get_g_comm();
    let eval_keys: Vec<(u32, Scalar)> = (0..num_clients as u32)
        .into_par_iter()
        .map(|i| (i, prf.evaluate(i as u64)))
        .collect();
    let key_commitments = eval_keys.par_iter().map(|(_, ek)| g_comm * ek).collect();

    let verifier_key = DropoutVerifierKey::simulated(num_clients);
    let mut key_records = Vec::with_capacity(num_clients);
    for chunk in eval_keys.chunks(SIMULATED_SETUP_CHUNK_SIZE) {
        key_records.extend(verifier_key.key_records(chunk));
    }
    let dropout_key =
        DropoutProverKey::new(verifier_key.paillier_public_key().clone(), key_records);
    (key_commitments, dropout_key)
}

/// Format: num_clients (u64) + [chunk_len (u64) + chunk_data]*
fn serialize_key_commitments(key_commitments: &[G]) -> Vec<u8> {
    const CHUNK_SIZE: usize = 100_000;
    let serialized_chunks: Vec<Vec<u8>> = key_commitments
        .par_chunks(CHUNK_SIZE)
        .map(|chunk| bincode::serialize(chunk).unwrap())
        .collect();

    let total_len: usize = serialized_chunks.iter().map(|c| c.len()).sum();
    let mut serialized = Vec::with_capacity(total_len + 8 + serialized_chunks.len() * 8);
    serialized.extend_from_slice(&(key_commitments.len() as u64).to_le_bytes());
    for chunk in serialized_chunks {
        serialized.extend_from_slice(&(chunk.len() as u64).to_le_bytes());
        serialized.extend(chunk);
    }
    serialized
}

/// Stores the key records in fixed-size groups, keyed so that they sort by client index.
fn store_dropout_key(db: &Db, key: &DropoutProverKey) -> Result<()> {
    let paillier_key = bincode::serialize(key.paillier_public_key())?;
    db.insert(DROPOUT_PAILLIER_KEY_DB_KEY, paillier_key)?;

    let groups = key.records().chunks(KEY_RECORDS_PER_DB_ENTRY);
    for (i, records) in groups.enumerate() {
        let mut db_key = DROPOUT_RECORDS_DB_PREFIX.to_vec();
        db_key.extend_from_slice(&(i as u64).to_be_bytes());
        db.insert(db_key, bincode::serialize(records)?)?;
    }
    Ok(())
}

fn load_dropout_key(db: &Db, num_clients: usize) -> Result<DropoutProverKey> {
    let paillier_key = db
        .get(DROPOUT_PAILLIER_KEY_DB_KEY)?
        .ok_or_else(|| anyhow!("No dropout key in DB"))?;
    let paillier_key: paillier::PublicKey = bincode::deserialize(&paillier_key)?;

    let mut records: Vec<KeyRecord> = Vec::with_capacity(num_clients);
    for entry in db.scan_prefix(DROPOUT_RECORDS_DB_PREFIX).values() {
        records.extend(bincode::deserialize::<Vec<KeyRecord>>(&entry?)?);
    }
    ensure!(
        records.len() == num_clients,
        "Expected dropout key records for {num_clients} clients, found {}",
        records.len()
    );
    Ok(DropoutProverKey::new(paillier_key, records))
}

// --- Chunk processing (decrypt, verify, aggregate) ---

fn process_chunk(
    hpke_sk: &<hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey,
    vk: &VerifierKey,
    context: u32,
    reports: Vec<(u32, Vec<u8>)>,
) -> (
    Vec<u32>,
    Option<Ciphertext>,
    std::time::Duration,
    std::time::Duration,
    std::time::Duration,
) {
    let decrypt_start = Instant::now();
    let decrypted: Vec<_> = reports
        .into_par_iter()
        .filter_map(|(id, data)| {
            let envelope: crate::crypto::hpke::HpkeEnvelope = bincode::deserialize(&data).ok()?;
            let (report_bytes, _) = hpke_decrypt(hpke_sk, &envelope, b"", b"").ok()?;
            let Message::ClientReport { proof, ciphertext } =
                bincode::deserialize(&report_bytes).ok()?
            else {
                return None;
            };
            Some((id, proof, ciphertext))
        })
        .collect();
    let decrypt_time = decrypt_start.elapsed();

    let verify_start = Instant::now();
    let verify_chunks: Vec<_> = decrypted.chunks(VERIFY_BATCH_SIZE).collect();
    let verified: Vec<_> = verify_chunks
        .into_par_iter()
        .filter_map(|chunk| {
            let ids: Vec<u32> = chunk.iter().map(|(id, _, _)| *id).collect();
            let proofs: Vec<_> = chunk.iter().map(|(_, p, _)| p.clone()).collect();
            let cts: Vec<_> = chunk.iter().map(|(_, _, c)| c.clone()).collect();

            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            Proof::batch_verify(
                vk,
                &cts,
                context,
                &proofs,
                &ids,
                &mut ChaCha20Rng::from_seed(seed),
            )
            .ok()
            .map(|_| (ids, cts))
        })
        .collect();
    let verify_time = verify_start.elapsed();

    let agg_start = Instant::now();
    let mut online = Vec::new();
    let mut agg: Option<Ciphertext> = None;
    for (ids, cts) in verified {
        online.extend(ids);
        let chunk_agg = cts.into_iter().reduce(|a, b| a + b);
        agg = match (agg, chunk_agg) {
            (Some(a), Some(b)) => Some(a + b),
            (Some(a), None) => Some(a),
            (None, b) => b,
        };
    }
    let agg_time = agg_start.elapsed();

    (online, agg, decrypt_time, verify_time, agg_time)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dropout key must survive the database, in order, when its records
    /// span several entries.
    #[test]
    fn dropout_key_roundtrips_through_db() -> Result<()> {
        let num_clients = 2 * KEY_RECORDS_PER_DB_ENTRY + 3;
        let verifier_key = DropoutVerifierKey::generate(num_clients, &mut OsRng);
        // Encrypting is slow, so the records cycle through a few distinct ones.
        let distinct = verifier_key.key_records(&[
            (0, Scalar::from(1u64)),
            (1, Scalar::from(2u64)),
            (2, Scalar::from(3u64)),
        ]);
        let records: Vec<KeyRecord> = distinct.iter().cycle().take(num_clients).cloned().collect();
        let key = DropoutProverKey::new(verifier_key.paillier_public_key().clone(), records);

        let db = sled::Config::default().temporary(true).open()?;
        assert!(load_dropout_key(&db, num_clients).is_err());
        store_dropout_key(&db, &key)?;
        assert_eq!(db.scan_prefix(DROPOUT_RECORDS_DB_PREFIX).count(), 3);

        let loaded = load_dropout_key(&db, num_clients)?;
        assert_eq!(loaded.paillier_public_key(), key.paillier_public_key());
        assert_eq!(loaded.records(), key.records());
        assert!(load_dropout_key(&db, num_clients - 1).is_err());
        Ok(())
    }
}
