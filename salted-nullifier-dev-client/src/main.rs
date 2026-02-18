use std::{collections::HashMap, str::FromStr as _, sync::Arc, time::Duration};

use alloy::{
    network::EthereumWallet,
    primitives::{Address, U160},
    providers::{Provider as _, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use ark_ff::UniformRand as _;
use clap::Parser;
use eyre::Context as _;
use rand::SeedableRng as _;
use rustls::{ClientConfig, RootCertStore};
use secrecy::{ExposeSecret as _, SecretString};
use taceo_oprf::{
    client::Connector,
    core::oprf::{BlindedOprfRequest, BlindingFactor},
    dev_client::{Command, StressTestOprfCommand, oprf_test_utils::health_checks},
    types::{OprfKeyId, ShareEpoch, api::OprfRequest, crypto::OprfPublicKey},
};
use uuid::Uuid;

/// The configuration for the OPRF client.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct OprfDevClientConfig {
    /// The URLs to all OPRF nodes
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_NODES",
        value_delimiter = ',',
        default_value = "http://127.0.0.1:10000,http://127.0.0.1:10001,http://127.0.0.1:10002"
    )]
    pub nodes: Vec<String>,

    /// The threshold of services that need to respond
    #[clap(long, env = "OPRF_DEV_CLIENT_THRESHOLD", default_value = "2")]
    pub threshold: usize,

    /// The Address of the OprfKeyRegistry contract.
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_REGISTRY_CONTRACT")]
    pub oprf_key_registry_contract: Address,

    /// The RPC for chain communication
    #[clap(
        long,
        env = "OPRF_DEV_CLIENT_CHAIN_RPC_URL",
        default_value = "http://localhost:8545"
    )]
    pub chain_rpc_url: SecretString,

    /// The PRIVATE_KEY of the TACEO admin wallet - used to register the OPRF nodes
    ///
    /// Default is anvil wallet 0
    #[clap(
        long,
        env = "TACEO_ADMIN_PRIVATE_KEY",
        default_value = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    )]
    pub taceo_private_key: SecretString,

    /// rp id of already registered rp
    #[clap(long, env = "OPRF_DEV_CLIENT_OPRF_KEY_ID")]
    pub oprf_key_id: Option<U160>,

    /// The share epoch. Will be ignored if `oprf_key_id` is `None`.
    #[clap(long, env = "OPRF_DEV_CLIENT_SHARE_EPOCH", default_value = "0")]
    pub share_epoch: u32,

    /// max wait time for init key-gen/reshare to succeed.
    #[clap(long, env = "OPRF_DEV_CLIENT_WAIT_TIME", default_value="2min", value_parser=humantime::parse_duration)]
    pub max_wait_time: Duration,

    /// Command
    #[command(subcommand)]
    pub command: Command,
}

async fn run_oprf(nodes: &[String], threshold: usize, connector: Connector) -> eyre::Result<()> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    // TODO compute a client-side proof and receive the encrypted unsalted nullifier
    let _action = ark_babyjubjub::Fq::rand(&mut rng);

    // the client example internally checks the DLog equality
    salted_nullifier_client::salted_nullifier(nodes, threshold, connector, &mut rng).await;

    Ok(())
}

fn prepare_oprf_stress_test_oprf_request()
-> eyre::Result<(Uuid, BlindedOprfRequest, OprfRequest<()>)> {
    let mut rng = rand_chacha::ChaCha12Rng::from_entropy();

    let request_id = Uuid::new_v4();
    let action = ark_babyjubjub::Fq::rand(&mut rng);
    let blinding_factor = BlindingFactor::rand(&mut rng);
    let query = action;
    let blinded_request = taceo_oprf::core::oprf::client::blind_query(query, blinding_factor);
    let oprf_req = OprfRequest {
        request_id,
        blinded_query: blinded_request.blinded_query(),
        auth: (),
    };

    Ok((request_id, blinded_request, oprf_req))
}

async fn stress_test(
    cmd: StressTestOprfCommand,
    nodes: &[String],
    threshold: usize,
    oprf_public_key: OprfPublicKey,
    connector: Connector,
) -> eyre::Result<()> {
    let mut blinded_requests = HashMap::with_capacity(cmd.runs);
    let mut init_requests = HashMap::with_capacity(cmd.runs);

    tracing::info!("preparing requests..");
    for _ in 0..cmd.runs {
        let (request_id, blinded_req, req) = prepare_oprf_stress_test_oprf_request()?;
        blinded_requests.insert(request_id, blinded_req);
        init_requests.insert(request_id, req);
    }

    tracing::info!("sending init requests..");
    let (sessions, finish_requests) = taceo_oprf::dev_client::send_init_requests(
        nodes,
        "face",
        threshold,
        connector,
        cmd.sequential,
        init_requests,
    )
    .await?;

    tracing::info!("sending finish requests..");
    let responses = taceo_oprf::dev_client::send_finish_requests(
        sessions,
        cmd.sequential,
        finish_requests.clone(),
    )
    .await?;

    if !cmd.skip_checks {
        tracing::info!("checking OPRF + proofs");
        for (id, res) in responses {
            let blinded_req = blinded_requests.get(&id).expect("is there").to_owned();
            let finish_req = finish_requests.get(&id).expect("is there").to_owned();
            let _dlog_proof = taceo_oprf::client::verify_dlog_equality(
                id,
                oprf_public_key,
                &blinded_req,
                res,
                finish_req,
            )?;
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    taceo_nodes_observability::install_tracing(
        "taceo_oprf=trace,taceo-salted-nullifier-dev-client=trace,warn",
    );
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let config = OprfDevClientConfig::parse();
    tracing::info!("starting oprf-dev-client with config: {config:#?}");

    tracing::info!("health check for all nodes...");
    health_checks::services_health_check(&config.nodes, Duration::from_secs(5))
        .await
        .context("while doing health checks")?;
    tracing::info!("everyone online..");

    let private_key = PrivateKeySigner::from_str(config.taceo_private_key.expose_secret())?;
    let wallet = EthereumWallet::from(private_key.clone());

    tracing::info!("init rpc provider..");
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect(config.chain_rpc_url.expose_secret())
        .await
        .context("while connecting to RPC")?
        .erased();

    let (_oprf_key_id, _share_epoch, oprf_public_key) =
        if let Some(oprf_key_id) = config.oprf_key_id {
            let oprf_key_id = OprfKeyId::new(oprf_key_id);
            let share_epoch = ShareEpoch::from(config.share_epoch);
            let oprf_public_key = health_checks::oprf_public_key_from_services(
                oprf_key_id,
                share_epoch,
                &config.nodes,
                config.max_wait_time,
            )
            .await?;
            (oprf_key_id, share_epoch, oprf_public_key)
        } else {
            let (oprf_key_id, oprf_public_key) = taceo_oprf::dev_client::init_key_gen(
                &config.nodes,
                config.oprf_key_registry_contract,
                provider.clone(),
                config.max_wait_time,
            )
            .await?;
            (oprf_key_id, ShareEpoch::default(), oprf_public_key)
        };

    // setup TLS config - even if we are http
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let rustls_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = Connector::Rustls(Arc::new(rustls_config));

    match config.command.clone() {
        Command::Test => {
            tracing::info!("running oprf-test");
            run_oprf(&config.nodes, config.threshold, connector).await?;
            tracing::info!("oprf-test successful");
        }
        Command::StressTestOprf(cmd) => {
            tracing::info!("running stress-test");
            stress_test(
                cmd,
                &config.nodes,
                config.threshold,
                oprf_public_key,
                connector,
            )
            .await?;
            tracing::info!("stress-test successful");
        }
        Command::DeleteTest => todo!(),
        Command::StressTestKeyGen(_) => todo!(),
        Command::ReshareTest(_) => todo!(),
    }

    Ok(())
}
