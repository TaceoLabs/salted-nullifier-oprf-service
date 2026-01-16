use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use eyre::Context;
use oprf_service::OprfRequestAuthenticator;
use oprf_types::api::v1::OprfRequest;
use reqwest::{ClientBuilder, Url};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct SaltedNullifierRequestAuth;

#[derive(Debug, thiserror::Error)]
#[allow(unused)]
pub(crate) enum SaltedNullifierAuthError {
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for SaltedNullifierAuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            SaltedNullifierAuthError::InternalServerError(err) => {
                let error_id = Uuid::new_v4();
                tracing::error!("{error_id} - {err:?}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("An internal server error has occurred. Error ID={error_id}"),
                )
                    .into_response()
            }
        }
    }
}

pub(crate) struct SaltedNullifierOprfRequestAuthenticator {
    #[expect(unused)]
    client: reqwest::Client,
}

impl SaltedNullifierOprfRequestAuthenticator {
    pub(crate) async fn init(oracle_url: Url) -> eyre::Result<Self> {
        // we use the client-builder to avoid panic if we cannot install tls backend
        let client = ClientBuilder::new()
            .build()
            .context("while building reqwest client")?;
        let health_url = oracle_url
            .join("/health")
            .context("while building health url")?;
        tracing::info!("pinging oracle at: {health_url}");
        let response = client
            .get(health_url)
            .send()
            .await
            .context("while trying to reach oracle")?;
        let status_code = response.status();
        if status_code == StatusCode::OK {
            tracing::info!("oracle is healthy!");
        } else {
            tracing::warn!("cannot reach oracle: {response:?}");
            eyre::bail!("cannot reach oracle");
        }
        Ok(Self { client })
    }
}

#[async_trait]
impl OprfRequestAuthenticator for SaltedNullifierOprfRequestAuthenticator {
    type RequestAuth = SaltedNullifierRequestAuth;
    type RequestAuthError = SaltedNullifierAuthError;

    async fn verify(
        &self,
        _request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<(), Self::RequestAuthError> {
        // TODO use client to request proof
        Ok(())
    }
}
