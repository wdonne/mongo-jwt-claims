use config::ConfigError;
use log::{debug, error};
use salvo::http::StatusError;
use salvo::{Depot, Request, Response, Writer, async_trait};
use std::{io, time};
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum ServerError {
    #[error("unknown algorithm")]
    Alg,
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("convert from BSON error: {0}")]
    FromBson(#[from] immutable_json::error::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("issuer state error")]
    IssuerState,
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("jwks state error")]
    JwksState,
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("key state error")]
    KeyState,
    #[error("mongodb error: {0}")]
    MongoDB(#[from] mongodb::error::Error),
    #[error("no handler aggregation")]
    NoAggregation,
    #[error("no handler collection")]
    NoCollection,
    #[error("no config")]
    NoConfig,
    #[error("no handler for path {0}")]
    NoHandler(String),
    #[error("no handlers")]
    NoHandlers,
    #[error("no jwks_uri")]
    NoJwksUri,
    #[error("no handler path")]
    NoPath,
    #[error("no signer error")]
    NoSigner,
    #[error("the aggregation result is not an object")]
    NotObject,
    #[error("the query did not yield a result")]
    NotFound,
    #[error("not implemented")]
    NotImplemented,
    #[error("otel error: {0}")]
    Otel(#[from] otel_config::error::Error),
    #[error("salvo: {0}")]
    Salvo(#[from] salvo::Error),
    #[error("system time: {0}")]
    SystemTime(#[from] time::SystemTimeError),
    #[error("unauthorized")]
    Unauthorized,
}

#[async_trait]
impl Writer for ServerError {
    async fn write(mut self, _req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        error!("ServerError: {0}", self);
        match self {
            ServerError::Jwt(e) => {
                debug!("{0}", e);
                res.render(StatusError::unauthorized())
            }
            ServerError::NoHandler(_) => res.render(StatusError::not_found()),
            ServerError::NotFound => res.render(StatusError::not_found()),
            ServerError::NotImplemented => res.render(StatusError::not_implemented()),
            ServerError::Unauthorized => res.render(StatusError::unauthorized()),
            _ => res.render(StatusError::internal_server_error().brief("unknown error")),
        }
    }
}
