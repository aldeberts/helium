use crate::{
    agg_only_enc::{EvalKey, SecretKey},
    crypto::{
        G, Scalar,
        app_attest::{verify_app_attest, verify_sig},
        hpke::*,
        prf::{KHPRF, ScalarPRF},
    },
    dropout::{DropoutVerifierKey, KeyRecord},
    proofs::Proof,
    system::messages::{Message, *},
};
use rayon::prelude::*;

use anyhow::{Result, anyhow};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sled::Db;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Mutex, OnceCell, RwLock, mpsc, oneshot},
};
use tracing::{error, info};

pub struct Decryptor {
    addr: String,
    pub(crate) state: Arc<DecryptorState>,
}

const CLIENT_KEYS_BATCH_SIZE: usize = 1024;

/// The decryptor's long-term secrets, fixed once setup completes.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct DecryptorKeys {
    pub(crate) secret_key: SecretKey,
    dropout_key: DropoutVerifierKey,
}

pub(crate) struct DecryptorState {
    num_clients: usize,
    threshold: usize,
    hpke_keypair: ServerKeys,
    pub(crate) keys: OnceCell<DecryptorKeys>,
    current_ctx: RwLock<Option<u32>>,
    db: Db,
    keygen_prf: RwLock<ScalarPRF>,
    /// Key under which registering clients' keys are encrypted for the
    /// aggregator. A simulated setup replaces it with a fixed key.
    setup_dropout_key: Arc<DropoutVerifierKey>,
    next_client_index: AtomicUsize,
    ek_send: mpsc::UnboundedSender<ClientKey>,
    setup_send: mpsc::UnboundedSender<SetupToAggregator>,
    sk_recv: Mutex<Option<oneshot::Receiver<Scalar>>>,
    setup_start: OnceCell<Instant>,
}

enum ClientKey {
    Simulate,
    Key(u32, Scalar),
}

pub(crate) enum SetupToAggregator {
    ClientKeysBatch(Vec<(u32, G, KeyRecord)>),
    Simulate,
}

impl Decryptor {
    pub fn new(
        addr: &str,
        aggregator_addr: &str,
        num_clients: usize,
        threshold: usize,
        hpke_keypair: ServerKeys,
        db: Db,
    ) -> Self {
        let saved_keys: Option<DecryptorKeys> = db
            .get(b"keys")
            .ok()
            .flatten()
            .and_then(|bytes| bincode::deserialize(&bytes).ok());

        let (ek_send, mut ek_recv) = mpsc::unbounded_channel();
        let (sk_send, sk_recv) = oneshot::channel();
        let (setup_send, setup_recv) = mpsc::unbounded_channel();

        let setup_complete = saved_keys.is_some();
        let keys_cell = OnceCell::new();
        let (keygen_prf, setup_dropout_key) = if let Some(keys) = saved_keys {
            info!("Loaded keys from database");
            let registration_keys = (keys.secret_key.keygen_prf.clone(), keys.dropout_key.clone());
            keys_cell.set(keys).ok();
            registration_keys
        } else {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            (
                ScalarPRF::new(&key),
                DropoutVerifierKey::generate(num_clients, &mut OsRng),
            )
        };

        let state = Arc::new(DecryptorState {
            num_clients,
            threshold,
            hpke_keypair,
            keys: keys_cell,
            current_ctx: RwLock::new(None),
            db,
            keygen_prf: RwLock::new(keygen_prf),
            setup_dropout_key: Arc::new(setup_dropout_key),
            next_client_index: AtomicUsize::new(0),
            ek_send,
            setup_send,
            sk_recv: Mutex::new(Some(sk_recv)),
            setup_start: OnceCell::new(),
        });

        // If no saved keys, spawn task to aggregate evaluation keys
        if !setup_complete {
            let n = num_clients;
            let state_clone = state.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    Self::key_aggregation_task(state_clone, &mut ek_recv, sk_send, n).await
                {
                    error!("Key aggregation failed: {e:?}");
                }
            });
        }

        // Spawn task to communicate with aggregator
        let agg_addr = aggregator_addr.to_string();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) =
                Self::aggregator_task(agg_addr, state_clone, setup_recv, setup_complete).await
            {
                error!("Aggregator connection error: {e:?}");
            }
        });

        Self {
            addr: addr.to_string(),
            state,
        }
    }

    async fn key_aggregation_task(
        state: Arc<DecryptorState>,
        ek_recv: &mut mpsc::UnboundedReceiver<ClientKey>,
        sk_send: oneshot::Sender<Scalar>,
        num_clients: usize,
    ) -> Result<()> {
        let Some(first) = ek_recv.recv().await else {
            return Err(anyhow!("Channel closed before receiving any key"));
        };

        let prf_key = match first {
            ClientKey::Simulate => {
                let keys = Self::compute_simulated_keys(num_clients).await?;
                let prf_key = keys.secret_key.prf_key;
                Self::finish_setup(&state, keys)?;
                state.setup_send.send(SetupToAggregator::Simulate).ok();
                prf_key
            }
            ClientKey::Key(idx, ek) => {
                Self::aggregate_real_keys(&state, ek_recv, idx, ek, num_clients).await?
            }
        };

        sk_send
            .send(prf_key)
            .map_err(|_| anyhow!("Failed to send secret key"))?;
        Ok(())
    }

    async fn compute_simulated_keys(num_clients: usize) -> Result<DecryptorKeys> {
        tokio::task::spawn_blocking(move || {
            let keygen_prf = ScalarPRF::new(&SIMULATE_PRF_KEY);
            let prf_key =
                (0..num_clients).fold(Scalar::ZERO, |acc, i| acc + keygen_prf.evaluate(i as u64));
            DecryptorKeys {
                secret_key: SecretKey {
                    prf_key,
                    keygen_prf,
                },
                dropout_key: DropoutVerifierKey::simulated(num_clients),
            }
        })
        .await
        .map_err(|e| anyhow!("{e}"))
    }

    /// Persists the keys and closes registration.
    fn finish_setup(state: &DecryptorState, keys: DecryptorKeys) -> Result<()> {
        state.db.insert(b"keys", bincode::serialize(&keys)?)?;
        state.db.flush()?;
        info!("Saved keys to database");
        state
            .keys
            .set(keys)
            .map_err(|_| anyhow!("Setup already complete"))
    }

    async fn aggregate_real_keys(
        state: &DecryptorState,
        ek_recv: &mut mpsc::UnboundedReceiver<ClientKey>,
        first_idx: u32,
        first_ek: Scalar,
        num_clients: usize,
    ) -> Result<Scalar> {
        let mut prf_key = first_ek;
        let mut batch = vec![(first_idx, first_ek)];
        let mut received = 1;

        loop {
            if batch.len() >= CLIENT_KEYS_BATCH_SIZE || received == num_clients {
                let keys = Self::client_keys_batch(state, std::mem::take(&mut batch)).await?;
                state
                    .setup_send
                    .send(SetupToAggregator::ClientKeysBatch(keys))
                    .ok();
            }
            if received == num_clients {
                return Ok(prf_key);
            }

            let ClientKey::Key(idx, ek) = ek_recv
                .recv()
                .await
                .ok_or_else(|| anyhow!("Channel closed"))?
            else {
                return Err(anyhow!("Unexpected simulate message during registration"));
            };

            prf_key += ek;
            batch.push((idx, ek));
            received += 1;
        }
    }

    /// Computes what the aggregator stores for each client in `clients`: a
    /// commitment to its key and its dropout key record.
    async fn client_keys_batch(
        state: &DecryptorState,
        clients: Vec<(u32, Scalar)>,
    ) -> Result<Vec<(u32, G, KeyRecord)>> {
        let dropout_key = state.setup_dropout_key.clone();
        let batch = tokio::task::spawn_blocking(move || {
            let g_comm = Proof::get_g_comm();
            let records = dropout_key.key_records(&clients);
            clients
                .into_iter()
                .zip(records)
                .map(|((idx, ek), record)| (idx, g_comm * ek, record))
                .collect()
        })
        .await?;
        Ok(batch)
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!("Decryptor listening on {}", self.addr);

        loop {
            let (mut socket, _) = listener.accept().await?;
            let state = self.state.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(&mut socket, state).await {
                    send_error_message(&mut socket, &e.to_string()).await.ok();
                }
            });
        }
    }

    async fn handle_client(socket: &mut TcpStream, state: Arc<DecryptorState>) -> Result<()> {
        let msg = read_message(socket).await?;
        match msg {
            Message::SimulateSetup {} => {
                state.ek_send.send(ClientKey::Simulate)?;
                Self::handle_simulate_setup(socket, state).await
            }
            _ => Self::handle_register_request(socket, state, msg).await,
        }
    }

    async fn handle_simulate_setup(
        socket: &mut TcpStream,
        state: Arc<DecryptorState>,
    ) -> Result<()> {
        if state.keys.initialized() {
            return Err(anyhow!("Setup already complete"));
        }
        state.setup_start.set(Instant::now()).ok();
        write_message(socket, &Message::Success {}).await
    }

    async fn handle_register_request(
        socket: &mut TcpStream,
        state: Arc<DecryptorState>,
        initial_msg: Message,
    ) -> Result<()> {
        if state.keys.initialized() {
            return Err(anyhow!("Registration closed"));
        }
        state.setup_start.set(Instant::now()).ok();

        // Decrypt and verify the initial HPKE request
        let hpke_sk = state.hpke_keypair.sk.clone();
        let (mut ctx, request) = tokio::task::spawn_blocking(move || {
            let Message::HpkeRequest { envelope } = initial_msg else {
                return Err(anyhow!("Expected HpkeRequest"));
            };
            let (msg, ctx) = hpke_decrypt(&hpke_sk, &envelope, b"", b"")?;
            Ok::<_, anyhow::Error>((ctx, bincode::deserialize::<Message>(&msg)?))
        })
        .await??;

        // Verify attestation
        tokio::task::spawn_blocking(move || {
            let Message::RegisterRequest { attestation } = request else {
                return Err(anyhow!("Expected RegisterRequest"));
            };
            verify_app_attest(&attestation)
        })
        .await??;

        // Challenge-response
        let mut challenge = [0u8; 32];
        OsRng.fill_bytes(&mut challenge);
        write_message(socket, &Message::RegisterChallenge { challenge }).await?;

        let response = read_message(socket).await?;
        let Message::HpkeMessage { message } = response else {
            return Err(anyhow!("Expected HpkeMessage"));
        };
        let decrypted = hpke_decrypt_with_context(&mut ctx, &message, b"")?;
        let response: Message = bincode::deserialize(&decrypted)?;

        tokio::task::spawn_blocking(move || {
            let Message::RegisterResponse { signature } = response else {
                return Err(anyhow!("Expected RegisterResponse"));
            };
            verify_sig(&challenge, &signature)
        })
        .await??;

        // Assign client ID
        let client_id = state.next_client_index.fetch_add(1, Ordering::SeqCst);
        if client_id >= state.num_clients {
            return Err(anyhow!("Registration closed"));
        }

        // Compute and send evaluation key
        let ek = state.keygen_prf.read().await.evaluate(client_id as u64);
        state.ek_send.send(ClientKey::Key(client_id as u32, ek))?;
        write_message(
            socket,
            &Message::RegisterSuccess {
                id: client_id as u32,
                eval_key: EvalKey(ek),
            },
        )
        .await?;

        // Finalize setup after last client
        if client_id == state.num_clients - 1 {
            let prf_key = state.sk_recv.lock().await.take().unwrap().await?;
            let keygen_prf = state.keygen_prf.read().await.clone();
            let keys = DecryptorKeys {
                secret_key: SecretKey {
                    prf_key,
                    keygen_prf,
                },
                dropout_key: DropoutVerifierKey::clone(&state.setup_dropout_key),
            };
            Self::finish_setup(&state, keys)?;
        }
        Ok(())
    }

    async fn aggregator_task(
        aggregator_addr: String,
        state: Arc<DecryptorState>,
        mut setup_recv: mpsc::UnboundedReceiver<SetupToAggregator>,
        setup_complete: bool,
    ) -> Result<()> {
        let mut socket = TcpStream::connect(&aggregator_addr).await?;
        write_message(&mut socket, &Message::DecryptorInit {}).await?;

        match read_message(&mut socket).await? {
            Message::SetupAlreadyComplete {} => {
                info!("Setup already complete, skipping setup");
                setup_recv.close();
                while setup_recv.recv().await.is_some() {}
            }
            // Hanging up fails the aggregator's setup rather than leaving it waiting.
            Message::Success {} if setup_complete => {
                return Err(anyhow!(
                    "Aggregator expects a setup, but this decryptor already completed one"
                ));
            }
            Message::Success {} => {
                Self::send_client_keys(&mut socket, &state, &mut setup_recv).await?;
            }
            Message::Error(e) => return Err(anyhow!("Aggregator error: {e}")),
            _ => return Err(anyhow!("Unexpected aggregator response")),
        }

        // Process decryption mask requests
        Self::handle_mask_requests(&mut socket, &state).await
    }

    async fn send_client_keys(
        socket: &mut TcpStream,
        state: &DecryptorState,
        recv: &mut mpsc::UnboundedReceiver<SetupToAggregator>,
    ) -> Result<()> {
        let mut received = 0;
        while received < state.num_clients {
            match recv.recv().await {
                Some(SetupToAggregator::ClientKeysBatch(keys)) => {
                    if received == 0 {
                        let paillier_key = state.setup_dropout_key.paillier_public_key().clone();
                        make_request(socket, &Message::DropoutSetup { paillier_key }).await?;
                    }
                    received += keys.len();
                    make_request(socket, &Message::ClientKeysBatch { keys }).await?;
                }
                Some(SetupToAggregator::Simulate) => {
                    make_request(socket, &Message::SimulateSetup {}).await?;
                    info!("Simulated setup: aggregator notified");
                    break;
                }
                None => break,
            }
        }

        if let Some(start) = state.setup_start.get() {
            info!(
                "Setup complete: {} clients in {:?}",
                state.num_clients,
                start.elapsed()
            );
        }
        info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
        reset_byte_counters();
        Ok(())
    }

    async fn handle_mask_requests(socket: &mut TcpStream, state: &DecryptorState) -> Result<()> {
        loop {
            let Message::DecryptMaskRequest {
                context,
                dropout_proof,
                length,
            } = read_message(socket).await?
            else {
                error!("Unexpected message type");
                continue;
            };

            let wall_start = Instant::now();

            // Validate context
            {
                let mut ctx = state.current_ctx.write().await;
                match *ctx {
                    None => *ctx = Some(context),
                    Some(c) if c != context => {
                        return Err(anyhow!("Context mismatch: expected {c}, got {context}"));
                    }
                    _ => {}
                }
            }

            let keys = state
                .keys
                .get()
                .ok_or_else(|| anyhow!("Setup incomplete"))?
                .clone();

            // As a precaution, an invalid proof ends the aggregator's session.
            let DecryptorKeys {
                secret_key,
                dropout_key,
            } = keys;
            let (dropped, dropout_proof_time) = tokio::task::spawn_blocking(move || {
                let dropout_proof_start = Instant::now();
                let dropped = dropout_key.verify(&dropout_proof);
                (dropped, dropout_proof_start.elapsed())
            })
            .await?;
            let dropped = dropped?;

            // Check threshold
            let online = state.num_clients.saturating_sub(dropped.count);
            if online < state.threshold {
                let error = format!("Threshold not met: {online} < {}", state.threshold);
                error!("{error}");
                send_error_message(socket, &error).await?;
            } else {
                let key = secret_key.prf_key - dropped.key_sum;
                let (mask, mask_compute_time) = tokio::task::spawn_blocking(move || {
                    let mask_start = Instant::now();
                    let mask: Vec<G> = (0..length)
                        .into_par_iter()
                        .map(|i| KHPRF::evaluate_context(&key, context, i))
                        .collect();
                    (mask, mask_start.elapsed())
                })
                .await?;

                write_message(socket, &Message::DecryptMaskResponse { mask }).await?;

                info!(
                    "Decrypt mask for context {context}: {online} online clients\n\t\
                     Dropout proof: {:?}\n\t\
                     Mask computation: {:?}\n\t\
                     Total: {:?}",
                    dropout_proof_time,
                    mask_compute_time,
                    wall_start.elapsed()
                );
            }

            // Reset for next round
            *state.current_ctx.write().await = None;
            info!("Sent {}B, Recv {}B", bytes_sent(), bytes_recv());
            reset_byte_counters();
        }
    }
}
