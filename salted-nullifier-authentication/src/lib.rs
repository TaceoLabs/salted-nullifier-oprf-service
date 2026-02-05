use async_trait::async_trait;
use axum::{http::StatusCode, response::IntoResponse};
use eyre::Context;
use reqwest::{ClientBuilder, Url};
use serde::{Deserialize, Serialize};
use taceo_oprf::types::{
    OprfKeyId,
    api::{OprfRequest, OprfRequestAuthenticator},
};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct SaltedNullifierRequestAuth {
    pub oprf_key_id: OprfKeyId,
}

#[derive(Debug, thiserror::Error)]
pub enum SaltedNullifierAuthError {
    /// Cannot reach oracle
    #[error(transparent)]
    OracleNotRachable(#[from] reqwest::Error),
    /// Internal server error
    #[error(transparent)]
    InternalServerError(#[from] eyre::Report),
}

impl IntoResponse for SaltedNullifierAuthError {
    fn into_response(self) -> axum::response::Response {
        tracing::debug!("{self:?}");
        match self {
            SaltedNullifierAuthError::OracleNotRachable(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "cannot reach oracle".to_owned(),
            )
                .into_response(),
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

pub struct SaltedNullifierOprfRequestAuthenticator {
    client: reqwest::Client,
    oracle_url: Url,
}

impl SaltedNullifierOprfRequestAuthenticator {
    pub async fn init(oracle_url: Url) -> eyre::Result<Self> {
        // we use the client-builder to avoid panic if we cannot install tls backend
        let client = ClientBuilder::new()
            .build()
            .context("while building reqwest client")?;
        tracing::info!("pinging oracle at: {oracle_url}");
        let response = client
            .get(oracle_url.clone())
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
        Ok(Self { client, oracle_url })
    }
}

#[async_trait]
impl OprfRequestAuthenticator for SaltedNullifierOprfRequestAuthenticator {
    type RequestAuth = SaltedNullifierRequestAuth;
    type RequestAuthError = SaltedNullifierAuthError;

    async fn authenticate(
        &self,
        request: &OprfRequest<Self::RequestAuth>,
    ) -> Result<OprfKeyId, Self::RequestAuthError> {
        tracing::debug!("sending request to oracle");
        let response = self
            .client
            .get(self.oracle_url.clone())
            .send()
            .await
            .context("while trying to reach oracle")?;
        let _response = response.error_for_status()?;
        // TODO check if validation was ok or not

        Ok(request.auth.oprf_key_id)
    }
}
