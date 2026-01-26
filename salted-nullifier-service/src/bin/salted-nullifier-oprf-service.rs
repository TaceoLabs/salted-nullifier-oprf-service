use std::{process::ExitCode, sync::Arc};

use clap::Parser as _;
use taceo_oprf::service::{config::Environment, secret_manager::aws::AwsSecretManager};
use taceo_salted_nullifier_service::config::SaltedNullifierOprfNodeConfig;

#[tokio::main]
async fn main() -> eyre::Result<ExitCode> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("can install");
    let tracing_config = nodes_observability::TracingConfig::try_from_env()?;
    let _tracing_handle = nodes_observability::initialize_tracing(&tracing_config)?;
    taceo_salted_nullifier_service::metrics::describe_metrics();

    tracing::info!("{}", nodes_common::version_info!());

    let config = SaltedNullifierOprfNodeConfig::parse();

    let aws_config = match config.service_config.environment {
        Environment::Prod => aws_config::load_from_env().await,
        Environment::Dev => nodes_common::localstack_aws_config().await,
    };

    // Load the AWS secret manager.
    let secret_manager = Arc::new(
        AwsSecretManager::init(aws_config, &config.service_config.rp_secret_id_prefix).await,
    );
    let result = taceo_salted_nullifier_service::start_service(
        config,
        secret_manager,
        nodes_common::default_shutdown_signal(),
    )
    .await;
    match result {
        Ok(()) => {
            tracing::info!("good night!");
            Ok(ExitCode::SUCCESS)
        }
        Err(err) => {
            tracing::error!("{err:?}");
            Ok(ExitCode::FAILURE)
        }
    }
}
