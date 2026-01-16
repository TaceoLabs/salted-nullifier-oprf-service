//! Configuration types and CLI/environment parsing for the OPRF node.

use std::{net::SocketAddr, time::Duration};

use clap::Parser;
use oprf_service::config::OprfNodeConfig;
use reqwest::Url;

/// The configuration for the OPRF node.
///
/// It can be configured via environment variables or command line arguments using `clap`.
#[derive(Parser, Debug)]
pub struct SaltedNullifierOprfNodeConfig {
    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_NODE_BIND_ADDR", default_value = "0.0.0.0:4321")]
    pub bind_addr: SocketAddr,

    /// The bind addr of the AXUM server
    #[clap(long, env = "OPRF_NODE_ORACLE")]
    pub oracle_url: Url,

    /// Max wait time the service waits for its workers during shutdown.
    #[clap(
        long,
        env = "OPRF_NODE_MAX_WAIT_TIME_SHUTDOWN",
        default_value = "10s",
        value_parser = humantime::parse_duration

    )]
    pub max_wait_time_shutdown: Duration,

    /// The OPRF node config
    #[clap(flatten)]
    pub node_config: OprfNodeConfig,
}
