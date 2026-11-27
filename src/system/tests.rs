use crate::{
    crypto::{G, KHPRF, Scalar, hpke::ServerKeys},
    dropout::{DropoutProof, DropoutProverKey},
    system::{
        ProverType,
        aggregator::Aggregator,
        client::Client,
        decryptor::{Decryptor, DecryptorState},
        messages::{Message, read_message, write_message},
    },
};

use anyhow::{Result, anyhow, bail};
use rand::{Rng, rngs::OsRng};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::sleep,
};
use tracing_subscriber::EnvFilter;

const TEST_BATCH_SIZE: usize = 64;

/// A local address on a port that was free a moment ago, and that no other
/// test in this process has been given.
fn free_addr() -> String {
    static TAKEN: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());
    loop {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        if TAKEN.lock().unwrap().insert(addr.port()) {
            return addr.to_string();
        }
    }
}

/// Polls until `condition` holds, for up to ten seconds.
async fn wait_until(condition: impl Fn() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("Timed out waiting for a condition");
}

struct TestConfig {
    num_clients: usize,
    threshold: usize,
    length: usize,
    decryptor_addr: String,
    aggregator_addr: String,
    prover: ProverType,
}

impl TestConfig {
    fn new(num_clients: usize, length: usize, prover: ProverType) -> Self {
        Self {
            num_clients,
            threshold: num_clients,
            length,
            decryptor_addr: free_addr(),
            aggregator_addr: free_addr(),
            prover,
        }
    }

    fn binary(num_clients: usize, length: usize) -> Self {
        Self::new(num_clients, length, ProverType::Binary)
    }

    fn range(num_clients: usize, length: usize, bitlength: usize) -> Self {
        Self::new(num_clients, length, ProverType::Range(bitlength))
    }

    /// The same deployment on fresh ports, as after a restart of both servers.
    fn restarted(&self) -> Self {
        Self {
            threshold: self.threshold,
            ..Self::new(self.num_clients, self.length, self.prover)
        }
    }

    /// The `(binary, bitlength)` encoding of the prover type used on the wire.
    fn proof_params(&self) -> (bool, Option<usize>) {
        match self.prover {
            ProverType::Binary => (true, None),
            ProverType::Range(bitlength) => (false, Some(bitlength)),
        }
    }

    /// Exclusive upper bound on a client's input in each slot.
    fn max_input(&self) -> u64 {
        match self.prover {
            ProverType::Binary => 2,
            ProverType::Range(bitlength) => 1u64 << bitlength,
        }
    }
}

/// A running aggregator and decryptor.
struct Servers {
    aggregator_keys: ServerKeys,
    decryptor_keys: ServerKeys,
    decryptor_state: Arc<DecryptorState>,
    aggregator_handle: JoinHandle<()>,
    decryptor_handle: JoinHandle<()>,
}

impl Servers {
    async fn start(config: &TestConfig) -> Result<Self> {
        let temporary_db = || sled::Config::default().temporary(true).open();
        Self::start_with_dbs(config, temporary_db()?, temporary_db()?).await
    }

    async fn start_with_dbs(
        config: &TestConfig,
        aggregator_db: sled::Db,
        decryptor_db: sled::Db,
    ) -> Result<Self> {
        let aggregator_keys = ServerKeys::generate();
        let aggregator_handle = spawn_aggregator(config, aggregator_db, &aggregator_keys);
        sleep(Duration::from_millis(100)).await;

        let decryptor_keys = ServerKeys::generate();
        let (decryptor_state, decryptor_handle) =
            spawn_decryptor(config, decryptor_db, &decryptor_keys);
        sleep(Duration::from_millis(100)).await;

        Ok(Self {
            aggregator_keys,
            decryptor_keys,
            decryptor_state,
            aggregator_handle,
            decryptor_handle,
        })
    }

    async fn register_clients(&self, config: &TestConfig) -> Result<Vec<Client>> {
        let mut clients = Vec::new();
        for _ in 0..config.num_clients {
            clients.push(self.register_client(config).await?);
        }
        Ok(clients)
    }

    async fn register_client(&self, config: &TestConfig) -> Result<Client> {
        Client::register(
            &config.decryptor_addr,
            &config.aggregator_addr,
            config.prover,
            &self.decryptor_keys,
            &self.aggregator_keys,
        )
        .await
    }

    fn stop(self) {
        self.decryptor_handle.abort();
        self.aggregator_handle.abort();
    }
}

fn spawn_aggregator(config: &TestConfig, db: sled::Db, keys: &ServerKeys) -> JoinHandle<()> {
    let aggregator = Aggregator::new(
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        config.prover,
        db,
        keys.clone(),
        4,
        64,
    );
    tokio::spawn(async move {
        if let Err(e) = aggregator.run().await {
            panic!("Aggregator error: {}", e);
        }
    })
}

fn spawn_decryptor(
    config: &TestConfig,
    db: sled::Db,
    keys: &ServerKeys,
) -> (Arc<DecryptorState>, JoinHandle<()>) {
    let decryptor = Decryptor::new(
        &config.decryptor_addr,
        &config.aggregator_addr,
        config.num_clients,
        config.threshold,
        keys.clone(),
        db,
    );
    let state = decryptor.state.clone();
    let handle = tokio::spawn(async move {
        if let Err(e) = decryptor.run().await {
            panic!("Decryptor error: {}", e);
        }
    });
    (state, handle)
}

fn init_tracing() {
    let filter = EnvFilter::from_default_env().add_directive("sled=off".parse().unwrap());

    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(filter)
        .with_test_writer()
        .try_init();
}

/// Stream reports to the aggregator using AggregateStreamStart and return the result.
/// With `sim_dropouts`, the round is flagged as simulated and the aggregator
/// takes the dropped-out clients from that list, as in the experiments.
async fn stream_aggregate(
    aggregator_addr: &str,
    context: u32,
    reports: Vec<(u32, Vec<u8>)>,
    binary: bool,
    bitlength: Option<usize>,
    sim_dropouts: Option<Vec<u32>>,
) -> Result<Vec<u64>> {
    let batches: Vec<Vec<(u32, Vec<u8>)>> = reports
        .chunks(TEST_BATCH_SIZE)
        .map(|c| c.to_vec())
        .collect();
    let num_batches = batches.len();

    let mut socket = TcpStream::connect(aggregator_addr).await?;
    write_message(
        &mut socket,
        &Message::AggregateStreamStart {
            context,
            num_batches,
            binary,
            bitlength,
            simulated: sim_dropouts.is_some(),
            sim_dropouts: sim_dropouts.unwrap_or_default(),
        },
    )
    .await?;

    for batch in batches {
        write_message(
            &mut socket,
            &Message::BatchEncryptedClientReports {
                context,
                reports: batch,
            },
        )
        .await?;
    }

    match read_message(&mut socket).await? {
        Message::AggregationResponse { result } => Ok(result),
        Message::Error(e) => Err(anyhow!("Aggregation failed: {e}")),
        _ => Err(anyhow!("Unexpected response")),
    }
}

/// Runs one round in which exactly the clients in `online` submit random
/// inputs, and checks that the aggregate is the sum of those inputs.
async fn run_round(
    config: &TestConfig,
    clients: &[Client],
    context: u32,
    online: impl IntoIterator<Item = usize>,
) -> Result<()> {
    run_round_with(config, clients, context, online, None).await
}

async fn run_round_with(
    config: &TestConfig,
    clients: &[Client],
    context: u32,
    online: impl IntoIterator<Item = usize>,
    sim_dropouts: Option<Vec<u32>>,
) -> Result<()> {
    let mut rng = OsRng;
    let mut expected_sums = vec![0u64; config.length];
    let mut reports: Vec<(u32, Vec<u8>)> = Vec::new();

    // Generate reports and serialize envelopes into batched format
    for i in online {
        let inputs: Vec<u64> = (0..config.length)
            .map(|_| rng.gen_range(0..config.max_input()))
            .collect();
        for (sum, &val) in expected_sums.iter_mut().zip(&inputs) {
            *sum += val;
        }
        let report = clients[i].generate_report(context, &inputs)?;
        if let Message::EncryptedClientReport { id, envelope, .. } = report {
            reports.push((id, bincode::serialize(&envelope)?));
        }
    }

    let (binary, bitlength) = config.proof_params();
    let result = stream_aggregate(
        &config.aggregator_addr,
        context,
        reports,
        binary,
        bitlength,
        sim_dropouts,
    )
    .await?;

    assert_eq!(
        result, expected_sums,
        "Round {} results don't match expected sums",
        context
    );
    Ok(())
}

#[tokio::test]
async fn test_decryptor_setup() -> Result<()> {
    init_tracing();

    let config = TestConfig::binary(5, 1);
    let servers = Servers::start(&config).await?;

    let mut expected_key = Scalar::ZERO;
    for client in servers.register_clients(&config).await? {
        expected_key += *client.eval_key;
    }

    wait_until(|| servers.decryptor_state.keys.initialized()).await;

    let result = servers.register_client(&config).await;
    assert!(
        result.is_err(),
        "Should not be able to register after max clients"
    );

    let secret_key = &servers.decryptor_state.keys.get().unwrap().secret_key;
    assert_eq!(secret_key.prf_key, expected_key);

    servers.stop();
    Ok(())
}

async fn test_end_to_end_impl(
    config: TestConfig,
    num_rounds: u32,
    num_dropouts: usize,
) -> Result<()> {
    let servers = Servers::start(&config).await?;
    let clients = servers.register_clients(&config).await?;

    let num_submitting = config.num_clients - num_dropouts;
    for round in 0..num_rounds {
        run_round(&config, &clients, round, 0..num_submitting).await?;
    }

    servers.stop();
    Ok(())
}

#[tokio::test]
async fn test_end_to_end_binary() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::binary(10, 4), 1, 0).await
}

#[tokio::test]
async fn test_end_to_end_range() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::range(8, 4, 8), 1, 0).await
}

#[tokio::test]
async fn test_multiple_rounds() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::binary(6, 2), 3, 0).await
}

#[tokio::test]
async fn test_multi_chunk_verification() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::binary(200, 1), 1, 0).await
}

#[tokio::test]
async fn test_with_dropouts() -> Result<()> {
    init_tracing();
    let num_clients = 200;
    let num_dropouts = 50;
    let mut config = TestConfig::binary(num_clients, 1);
    config.threshold = num_clients - num_dropouts;
    test_end_to_end_impl(config, 1, num_dropouts).await
}

#[tokio::test]
async fn test_single_client() -> Result<()> {
    init_tracing();
    test_end_to_end_impl(TestConfig::binary(1, 2), 1, 0).await
}

/// A different, scattered set of clients drops out of each round.
#[tokio::test]
async fn test_dropouts_vary_across_rounds() -> Result<()> {
    init_tracing();
    let num_clients = 30;
    let mut config = TestConfig::range(num_clients, 2, 4);
    config.threshold = 10;
    let servers = Servers::start(&config).await?;
    let clients = servers.register_clients(&config).await?;

    let everyone = 0..num_clients;
    run_round(
        &config,
        &clients,
        0,
        everyone.clone().filter(|i| i % 3 != 0),
    )
    .await?;
    run_round(&config, &clients, 1, everyone.clone()).await?;
    run_round(
        &config,
        &clients,
        2,
        everyone.clone().filter(|i| i % 2 == 0),
    )
    .await?;
    run_round(&config, &clients, 3, everyone.filter(|i| *i >= 20)).await?;

    servers.stop();
    Ok(())
}

/// With fewer online clients than the threshold, the decryptor must not release a mask.
#[tokio::test]
async fn test_threshold_not_met() -> Result<()> {
    init_tracing();
    let mut config = TestConfig::binary(10, 1);
    config.threshold = 8;
    let servers = Servers::start(&config).await?;
    let clients = servers.register_clients(&config).await?;

    let error = run_round(&config, &clients, 0, 0..7).await.unwrap_err();
    assert!(error.to_string().contains("Threshold not met"), "{error}");

    // The servers keep serving rounds that meet the threshold.
    run_round(&config, &clients, 1, 0..8).await?;

    servers.stop();
    Ok(())
}

/// Both servers must be able to resume from their databases after a restart.
#[tokio::test]
async fn test_restart_reuses_setup() -> Result<()> {
    init_tracing();
    let mut config = TestConfig::binary(12, 2);
    config.threshold = 6;
    let aggregator_db = sled::Config::default().temporary(true).open()?;
    let decryptor_db = sled::Config::default().temporary(true).open()?;

    let servers =
        Servers::start_with_dbs(&config, aggregator_db.clone(), decryptor_db.clone()).await?;
    let clients = servers.register_clients(&config).await?;
    run_round(&config, &clients, 0, 0..9).await?;
    servers.stop();

    let config = config.restarted();
    let restarted = Servers::start_with_dbs(&config, aggregator_db, decryptor_db).await?;
    let clients: Vec<Client> = clients
        .into_iter()
        .map(|client| Client {
            aggregator_pk: restarted.aggregator_keys.pk.clone(),
            ..client
        })
        .collect();
    run_round(&config, &clients, 1, 2..12).await?;
    run_round(&config, &clients, 2, 0..12).await?;

    restarted.stop();
    Ok(())
}

/// An aggregation that is waiting for the setup must fail if the setup does.
#[tokio::test]
async fn test_aggregation_fails_if_setup_fails() -> Result<()> {
    init_tracing();
    let config = TestConfig::binary(4, 1);
    let db = sled::Config::default().temporary(true).open()?;
    let aggregator_handle = spawn_aggregator(&config, db, &ServerKeys::generate());
    sleep(Duration::from_millis(100)).await;

    let aggregator_addr = config.aggregator_addr.clone();
    let aggregation = tokio::spawn(async move {
        stream_aggregate(&aggregator_addr, 0, vec![], true, None, None).await
    });
    sleep(Duration::from_millis(100)).await;
    assert!(!aggregation.is_finished(), "Aggregation did not wait");

    // A decryptor that breaks the setup protocol.
    let mut decryptor = TcpStream::connect(&config.aggregator_addr).await?;
    write_message(&mut decryptor, &Message::DecryptorInit {}).await?;
    let Message::Success {} = read_message(&mut decryptor).await? else {
        bail!("Expected Success");
    };
    write_message(&mut decryptor, &Message::Success {}).await?;

    let result = tokio::time::timeout(Duration::from_secs(10), aggregation).await??;
    let error = result.expect_err("Aggregation succeeded without a setup");
    assert!(error.to_string().contains("Setup failed"), "{error}");

    aggregator_handle.abort();
    Ok(())
}

/// A decryptor that completed setup cannot redo it for an aggregator that lost
/// its own: aggregations must fail rather than wait forever.
#[tokio::test]
async fn test_aggregation_fails_if_aggregator_lost_setup() -> Result<()> {
    init_tracing();
    let config = TestConfig::binary(4, 1);
    let decryptor_db = sled::Config::default().temporary(true).open()?;
    let aggregator_db = sled::Config::default().temporary(true).open()?;

    let servers = Servers::start_with_dbs(&config, aggregator_db, decryptor_db.clone()).await?;
    let clients = servers.register_clients(&config).await?;
    run_round(&config, &clients, 0, 0..4).await?;
    servers.stop();

    let config = config.restarted();
    let fresh_db = sled::Config::default().temporary(true).open()?;
    let restarted = Servers::start_with_dbs(&config, fresh_db, decryptor_db).await?;
    // No reports are sent: the aggregator fails the round without reading them.
    let round = stream_aggregate(&config.aggregator_addr, 1, vec![], true, None, None);
    let error = tokio::time::timeout(Duration::from_secs(10), round)
        .await?
        .unwrap_err();
    assert!(error.to_string().contains("Setup failed"), "{error}");

    restarted.stop();
    Ok(())
}

async fn test_simulated_setup_impl(num_clients: usize, num_dropouts: usize) -> Result<()> {
    let mut config = TestConfig::binary(num_clients, 4);
    config.threshold = num_clients - num_dropouts;
    let servers = Servers::start(&config).await?;

    Client::trigger_sim_setup(&config.decryptor_addr).await?;

    let clients: Vec<Client> = (0..config.num_clients)
        .map(|id| {
            Client::new_simulated(
                id as u32,
                &config.aggregator_addr,
                &servers.aggregator_keys,
                config.prover,
            )
        })
        .collect();

    // As the experiments do, name the dropped-out clients in the request.
    let sim_dropouts = Some((0..num_dropouts as u32).collect());
    let online = num_dropouts..num_clients;
    run_round_with(&config, &clients, 0, online, sim_dropouts).await?;
    run_round(&config, &clients, 1, num_dropouts..num_clients).await?;

    servers.stop();
    Ok(())
}

#[tokio::test]
async fn test_end_to_end_simulated_setup() -> Result<()> {
    init_tracing();
    test_simulated_setup_impl(20, 0).await
}

#[tokio::test]
async fn test_simulated_setup_with_dropouts() -> Result<()> {
    init_tracing();
    test_simulated_setup_impl(20, 7).await
}

// --- The decryptor against a malicious aggregator ---

/// Length of the masks requested from the decryptor in these tests.
const MASK_LENGTH: usize = 3;

/// A decryptor that has completed setup with this test playing the aggregator.
struct MaskSession {
    socket: TcpStream,
    prover_key: DropoutProverKey,
    eval_keys: Vec<Scalar>,
    decryptor_handle: JoinHandle<()>,
}

impl MaskSession {
    async fn start(num_clients: usize, threshold: usize) -> Result<Self> {
        let mut config = TestConfig::binary(num_clients, 1);
        config.threshold = threshold;

        let listener = TcpListener::bind(&config.aggregator_addr).await?;
        let setup = tokio::spawn(receive_setup(listener, num_clients));

        let decryptor_keys = ServerKeys::generate();
        let decryptor_db = sled::Config::default().temporary(true).open()?;
        let (_, decryptor_handle) = spawn_decryptor(&config, decryptor_db, &decryptor_keys);
        sleep(Duration::from_millis(100)).await;

        let mut eval_keys = vec![Scalar::ZERO; num_clients];
        for _ in 0..num_clients {
            let client = Client::register(
                &config.decryptor_addr,
                &config.aggregator_addr,
                config.prover,
                &decryptor_keys,
                &ServerKeys::generate(),
            )
            .await?;
            eval_keys[client.id as usize] = *client.eval_key;
        }

        let (socket, prover_key) = setup.await??;
        Ok(Self {
            socket,
            prover_key,
            eval_keys,
            decryptor_handle,
        })
    }

    /// Requests a mask; `Err` means the decryptor refused or hung up.
    async fn request_mask(&mut self, context: u32, dropout_proof: DropoutProof) -> Result<Vec<G>> {
        let request = Message::DecryptMaskRequest {
            context,
            dropout_proof,
            length: MASK_LENGTH,
        };
        write_message(&mut self.socket, &request).await?;
        match read_message(&mut self.socket).await? {
            Message::DecryptMaskResponse { mask } => Ok(mask),
            Message::Error(e) => bail!("Decryptor error: {e}"),
            _ => bail!("Unexpected response"),
        }
    }

    /// The mask the decryptor should release when `dropouts` are offline.
    fn expected_mask(&self, context: u32, dropouts: &[u32]) -> Vec<G> {
        let key: Scalar = (0u32..)
            .zip(&self.eval_keys)
            .filter(|(id, _)| !dropouts.contains(id))
            .map(|(_, key)| key)
            .sum();
        (0..MASK_LENGTH)
            .map(|i| KHPRF::evaluate_context(&key, context, i))
            .collect()
    }
}

/// Plays the aggregator's side of the setup protocol.
async fn receive_setup(
    listener: TcpListener,
    num_clients: usize,
) -> Result<(TcpStream, DropoutProverKey)> {
    let (mut socket, _) = listener.accept().await?;
    let Message::DecryptorInit {} = read_message(&mut socket).await? else {
        bail!("Expected DecryptorInit");
    };
    write_message(&mut socket, &Message::Success {}).await?;
    let Message::DropoutSetup { paillier_key } = read_message(&mut socket).await? else {
        bail!("Expected DropoutSetup");
    };
    write_message(&mut socket, &Message::Success {}).await?;

    let mut records = vec![None; num_clients];
    while records.contains(&None) {
        let Message::ClientKeysBatch { keys } = read_message(&mut socket).await? else {
            bail!("Expected ClientKeysBatch");
        };
        for (idx, _, record) in keys {
            records[idx as usize] = Some(record);
        }
        write_message(&mut socket, &Message::Success {}).await?;
    }
    let records = records.into_iter().flatten().collect();
    Ok((socket, DropoutProverKey::new(paillier_key, records)))
}

#[tokio::test]
async fn test_decryptor_serves_valid_dropout_proofs() -> Result<()> {
    init_tracing();
    let mut session = MaskSession::start(8, 5).await?;

    for (context, dropouts) in [(0, vec![]), (1, vec![1, 6]), (2, vec![0, 3, 7])] {
        let proof = session.prover_key.prove(&dropouts)?;
        let mask = session.request_mask(context, proof).await?;
        assert_eq!(mask, session.expected_mask(context, &dropouts));
    }

    session.decryptor_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_decryptor_rejects_forged_dropout_proof() -> Result<()> {
    init_tracing();
    let mut session = MaskSession::start(8, 5).await?;

    let proof = session.prover_key.prove(&[1, 6])?;
    let other = session.prover_key.prove(&[1, 5])?;
    let forgery = proof.with_quotient_of(&other);
    assert!(session.request_mask(0, forgery).await.is_err());

    // The session is over: even an honest request goes unanswered.
    assert!(session.request_mask(1, proof).await.is_err());

    session.decryptor_handle.abort();
    Ok(())
}

#[tokio::test]
async fn test_decryptor_enforces_threshold() -> Result<()> {
    init_tracing();
    let mut session = MaskSession::start(8, 5).await?;

    // Three dropouts leave exactly the threshold online; four do not.
    let proof = session.prover_key.prove(&[0, 1, 2])?;
    assert!(session.request_mask(0, proof).await.is_ok());
    let proof = session.prover_key.prove(&[0, 1, 2, 3])?;
    let error = session.request_mask(1, proof).await.unwrap_err();
    assert!(error.to_string().contains("Threshold not met"), "{error}");

    // Unlike an invalid proof, this does not end the session.
    let proof = session.prover_key.prove(&[4])?;
    assert!(session.request_mask(2, proof).await.is_ok());

    session.decryptor_handle.abort();
    Ok(())
}
