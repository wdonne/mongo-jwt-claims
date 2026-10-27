use crate::error::ServerError::{self, NoJwksUri};
use bson::Bson;
use bson::document::Document;
use clap::Parser;
use config::{Config, ValueKind};
use config_util::config;
use immutable_json::array::Array;
use immutable_json::bson::from_bson;
use immutable_json::object::Object;
use iter_util::fold_result::FoldResultExt;
use jsonwebtoken::dangerous::insecure_decode;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use log::{debug, info};
use mongodb::{Client, Collection, Cursor, Database};
use multimap::MultiMap;
use salvo::affix_state::AffixList;
use salvo::http::uri::Scheme;
use salvo::{Depot, Request, Response, Router};
use salvo::{affix_state, handler};
use salvo_from_config::Server;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use smol::lock::Mutex;
use smol::stream::StreamExt;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::ops::DerefMut;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

mod error;

const JWKS_FILE: &str = "jwks-file";
const KEY_FILE: &str = "key-file";
const MONGO_DATABASE: &str = "mongo.database";
const MONGO_URI: &str = "mongo.uri";
const THIS_ISSUER: &str = "this-issuer";
const VERSION: &str = "1.1.1";

#[derive(Parser)]
struct Cli {
    #[arg(
        short,
        long,
        default_value = "8080",
        long_help = "The port the service will bind to"
    )]
    port: Option<u16>,
}

#[derive(Clone)]
struct Handler {
    aggregation: Vec<Document>,
    collection: Collection<Document>,
    path: String,
}

struct Issuer {
    audiences: Vec<String>,
    loaded: SystemTime,
    jwks: JwkSet,
}

struct IssuerState {
    issuers: Mutex<HashMap<String, Issuer>>,
}

struct JwksLoaded {
    jwks_file: String,
    loaded: Option<SystemTime>,
    response: String,
}

struct JwksState {
    loaded: Mutex<JwksLoaded>,
}

#[derive(Serialize, Deserialize)]
struct Key {
    #[serde(default = "Key::default_alg")]
    alg: String,
    kid: String,
    pem: String,
}

struct KeyLoaded {
    key_file: String,
    loaded: Option<SystemTime>,
    signer: Option<Signer>,
}

struct KeyState {
    loaded: Mutex<KeyLoaded>,
}

#[derive(Clone)]
struct Signer {
    alg: String,
    key: EncodingKey,
    kid: String,
}

#[derive(Debug)]
struct TokenMetadata {
    alg: Algorithm,
    iss: String,
    kid: String,
}

impl Issuer {
    fn get_decoding_key(&self, kid: &str) -> Result<DecodingKey, ServerError> {
        self.jwks
            .find(kid)
            .and_then(|j| DecodingKey::try_from(j).ok())
            .ok_or_else(|| {
                debug!("KID {0} not found in reloaded JWKS", kid);
                ServerError::Unauthorized
            })
    }
}

impl JwksLoaded {
    fn changed(&self) -> Result<bool, ServerError> {
        self.loaded
            .map(|l| changed(&self.jwks_file, &l))
            .unwrap_or(Ok(true))
    }

    fn reload(&mut self) -> Result<(), ServerError> {
        info!("Reload jwks");
        self.response = "".to_string();
        File::open(&self.jwks_file)?.read_to_string(&mut self.response)?;
        self.loaded = Some(SystemTime::now());
        Ok(())
    }
}

impl Key {
    fn default_alg() -> String {
        "RS512".to_string()
    }
}

impl KeyLoaded {
    fn changed(&self) -> Result<bool, ServerError> {
        self.loaded
            .map(|l| changed(&self.key_file, &l))
            .unwrap_or(Ok(true))
    }

    fn reload(&mut self) -> Result<(), ServerError> {
        info!("Reload key");

        let key: Key = serde_json::from_reader(BufReader::new(File::open(&self.key_file)?))?;

        info!("Using key {0}", key.kid);
        self.signer = Some(signer(&key)?);
        self.loaded = Some(SystemTime::now());
        Ok(())
    }
}

fn aggregation(config: &config::Map<String, config::Value>) -> Result<Vec<Document>, ServerError> {
    match config
        .get("aggregation")
        .and_then(|a| a.clone().into_string().ok())
    {
        Some(s) => Ok(json_to_aggregation(&s)?),
        _ => match config
            .get("aggregation")
            .and_then(|a| a.clone().into_array().ok())
        {
            Some(a) => Ok(config_array_to_array(&a)
                .iter()
                .filter_map(|v| v.as_document())
                .cloned()
                .collect()),
            _ => Err(ServerError::NoAggregation),
        },
    }
}

async fn alg_from_depot(depot: &Depot) -> Result<String, ServerError> {
    let mut guard = key_state_from_depot(depot)?.loaded.lock().await;
    let loaded: &mut KeyLoaded = guard.deref_mut();

    if loaded.changed()? {
        loaded.reload()?;
    }

    Ok(loaded
        .signer
        .as_ref()
        .map(|s| s.alg.clone())
        .unwrap_or("RS256".to_string()))
}

fn changed(path: &str, loaded: &SystemTime) -> Result<bool, ServerError> {
    Ok(Path::new(path).metadata()?.modified()?.elapsed()? < loaded.elapsed()?)
}

fn collection(collection: &str, database: &Database) -> Collection<Document> {
    let collection = database.collection::<Document>(collection);

    info!("Connected to collection {0}", collection.name());
    collection
}

fn config_array_to_array(array: &[config::Value]) -> bson::Array {
    array.iter().map(config_to_bson).collect()
}

fn config_from_depot(depot: &Depot) -> Result<&Config, ServerError> {
    depot
        .get_typed::<Config>()
        .map_err(|_| ServerError::NoConfig)
}

fn config_to_bson(value: &config::Value) -> Bson {
    match &value.kind {
        ValueKind::Nil => Bson::Null,
        ValueKind::Boolean(v) => Bson::Boolean(*v),
        ValueKind::I64(v) => Bson::Int64(*v),
        ValueKind::I128(_) => Bson::Undefined,
        ValueKind::U64(_) => Bson::Undefined,
        ValueKind::U128(_) => Bson::Undefined,
        ValueKind::Float(v) => Bson::Double(*v),
        ValueKind::String(v) => Bson::String(v.clone()),
        ValueKind::Table(v) => Bson::Document(config_table_to_document(v)),
        ValueKind::Array(v) => Bson::Array(config_array_to_array(v)),
    }
}

fn config_table_to_document(table: &config::Map<String, config::Value>) -> Document {
    let mut document = Document::new();

    table.iter().for_each(|(k, v)| {
        document.insert(k, config_to_bson(v));
    });

    document
}

fn convert_to_bson(value: &str) -> Bson {
    f64::from_str(value)
        .ok()
        .map(Bson::Double)
        .or_else(|| i64::from_str(value).ok().map(Bson::Int64))
        .or_else(|| bool::from_str(value).ok().map(Bson::Boolean))
        .unwrap_or_else(|| Bson::String(value.to_string()))
}

async fn database(config: &Config) -> Result<Database, ServerError> {
    info!("Connecting to MongoDB");
    Ok(Client::with_uri_str(config.get_string(MONGO_URI)?)
        .await?
        .database(&config.get_string(MONGO_DATABASE)?))
}

async fn decode_token(req: &Request, depot: &mut Depot) -> Result<Object, ServerError> {
    let token = get_bearer_token(req).ok_or_else(|| {
        debug!("No bearer token");
        ServerError::Unauthorized
    })?;
    let metadata = get_token_metadata(&token)?;

    debug!("Token metadata: {0:?}", metadata);

    let mut guard = issuer_state_from_depot(depot)?.issuers.lock().await;
    let issuers: &mut HashMap<String, Issuer> = guard.deref_mut();

    if issuers.is_empty() {
        load_issuers(issuers, depot).await?;
    }

    let result = verified_token(&token, issuers, &metadata)
        .await?
        .as_object()
        .and_then(|o| {
            immutable_json::api::Value::try_from(Value::Object(o.clone()))
                .ok()
                .and_then(|v| v.as_object())
        })
        .ok_or(ServerError::Unauthorized)?;

    debug!(
        "Decoded token: {0}",
        immutable_json::api::Value::Object(result.clone())
    );
    Ok(result)
}

fn field_from_query(s: &str, query: &MultiMap<String, String>) -> Bson {
    s.strip_prefix("$$")
        .and_then(|field| query.get(field))
        .map(|value| convert_to_bson(value))
        .unwrap_or_else(|| Bson::String(s.to_string()))
}

fn field_from_token(s: &str, token: &Object) -> Bson {
    token
        .get_p(&("/".to_string() + &s.replace(".", "/")))
        .and_then(|v| Bson::try_from(v).ok())
        .unwrap_or_else(|| Bson::String(s.to_string()))
}

fn get_audiences(issuer: &HashMap<String, config::Value>) -> Vec<String> {
    issuer
        .get("aud")
        .and_then(|a| a.clone().into_array().ok())
        .map(|a| {
            a.iter()
                .flat_map(|aud| aud.clone().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn get_bearer_token(req: &Request) -> Option<String> {
    req.header("Authorization")
        .map(|s: &str| {
            let v: Vec<&str> = s.split_ascii_whitespace().collect();

            v
        })
        .filter(|v| v.len() == 2 && v[0].to_lowercase() == "bearer")
        .map(|v| v[1].to_string())
}

async fn get_jwk_set(issuer: &str) -> Result<JwkSet, ServerError> {
    let body: Value = reqwest::get(issuer.to_string() + "/.well-known/openid-configuration")
        .await?
        .json()
        .await?;
    let jwks_uri = body
        .as_object()
        .and_then(|o| o.get("jwks_uri"))
        .and_then(|v| v.as_str())
        .ok_or(NoJwksUri)?;
    let jwks: Value = reqwest::get(jwks_uri).await?.json().await?;

    Ok(JwkSet::deserialize(jwks)?)
}

async fn get_jwks_response(depot: &Depot) -> Result<String, ServerError> {
    let mut guard = jwks_state_from_depot(depot)?.loaded.lock().await;
    let loaded: &mut JwksLoaded = guard.deref_mut();

    if loaded.changed()? {
        loaded.reload()?;
    }

    Ok(loaded.response.clone())
}

async fn get_result(cursor: &mut Cursor<Document>) -> Result<Object, ServerError> {
    let result: Vec<Document> = cursor.try_collect().await?;

    debug!("Aggregation result: {0:?}", result);

    if result.is_empty() {
        Err(ServerError::NotFound)
    } else {
        match immutable_json::api::Value::try_from(Bson::Document(result[0].to_owned()))?
            .as_object()
        {
            Some(o) => Ok(o),
            None => Err(ServerError::NotObject),
        }
    }
}

async fn get_signer(depot: &mut Depot) -> Result<Signer, ServerError> {
    let mut guard = key_state_from_depot(depot)?.loaded.lock().await;
    let loaded: &mut KeyLoaded = guard.deref_mut();

    if loaded.changed()? {
        loaded.reload()?;
    }

    loaded.signer.clone().ok_or_else(|| ServerError::NoSigner)
}

fn get_string_from_value(value: &Value, field: &str) -> String {
    value
        .as_object()
        .and_then(|o| o.get(field))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn get_token_metadata(token: &str) -> Result<TokenMetadata, ServerError> {
    let data = insecure_decode::<Value>(token)?;

    Ok(TokenMetadata {
        alg: data.header.alg,
        kid: data.header.kid.unwrap_or("".to_string()),
        iss: get_string_from_value(&data.claims, "iss"),
    })
}

fn get_validation(issuers: &HashMap<String, Issuer>, metadata: &TokenMetadata) -> Validation {
    let mut validation = Validation::new(metadata.alg);

    if let Some(audience) = issuers
        .get(&metadata.iss)
        .map(|i| i.audiences.as_slice())
        .filter(|aud| !aud.is_empty())
    {
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_audience(audience);
    } else {
        validation.validate_aud = false;
    }

    validation
}

async fn get_verifier(
    issuers: &mut HashMap<String, Issuer>,
    issuer: &str,
    kid: &str,
) -> Result<DecodingKey, ServerError> {
    let loaded_issuer = issuers.get(issuer).ok_or_else(|| {
        debug!("Issuer {0} not found", issuer);
        ServerError::Unauthorized
    })?;

    debug!(
        "Using issuer {0} with audiences {1:?}",
        issuer, loaded_issuer.audiences
    );
    match loaded_issuer.get_decoding_key(kid) {
        Ok(k) => Ok(k),
        Err(_) => {
            if loaded_issuer.loaded.elapsed()?.as_secs() > 60 {
                let new_issuer = load_issuer(issuer, &loaded_issuer.audiences).await?;
                let result = new_issuer.get_decoding_key(kid);

                issuers.insert(issuer.to_string(), new_issuer);
                result
            } else {
                debug!("KID {0} not found", kid);
                Err(ServerError::Unauthorized)
            }
        }
    }
}

fn handler(
    config: &config::Map<String, config::Value>,
    database: &Database,
) -> Result<Handler, ServerError> {
    info!("Connecting to database {0}", database.name());

    Ok(Handler {
        aggregation: aggregation(config)?,
        collection: collection(
            &config
                .get("collection")
                .and_then(|v| v.clone().into_string().ok())
                .ok_or(ServerError::NoCollection)?,
            database,
        ),
        path: config
            .get("path")
            .and_then(|v| v.clone().into_string().ok())
            .ok_or(ServerError::NoPath)?,
    })
}

fn handlers(config: &Config, database: &Database) -> Result<HashMap<String, Handler>, ServerError> {
    let mut result: HashMap<String, Handler> = HashMap::new();

    config
        .get_array("mongo.handlers")?
        .iter()
        .filter_map(|h| h.clone().into_table().ok())
        .map(|c| handler(&c, database))
        .fold_result(&mut result, |m, h| {
            m.insert(h.path.clone(), h);
            m
        })?;

    Ok(result)
}

fn handlers_from_depot(depot: &Depot) -> Result<&HashMap<String, Handler>, ServerError> {
    depot
        .get_typed::<HashMap<String, Handler>>()
        .map_err(|_| ServerError::NoHandlers)
}

fn handler_for_request<'a>(req: &'a Request, depot: &'a Depot) -> Result<&'a Handler, ServerError> {
    let path = req.uri().path();

    handlers_from_depot(depot)?
        .get(path)
        .ok_or_else(|| ServerError::NoHandler(path.to_string()))
}

#[handler]
async fn handle_jwks(resp: &mut Response, depot: &mut Depot) -> Result<(), ServerError> {
    resp.add_header("Content-Type", "application/json", true)?;
    resp.write_body(get_jwks_response(depot).await?)?;
    Ok(())
}

#[handler]
async fn handle_jwt(
    req: &mut Request,
    resp: &mut Response,
    depot: &mut Depot,
) -> Result<(), ServerError> {
    let decoded = decode_token(req, depot).await?;
    let signer = get_signer(depot).await?;
    let issuer = config_from_depot(depot)?.get_string("this-issuer")?;
    let handler = handler_for_request(req, depot)?;
    let mut cursor = handler
        .collection
        .aggregate(resolve_aggregation(
            &handler.aggregation,
            &decoded,
            req.queries(),
        ))
        .await?;
    let found = get_result(&mut cursor).await?;
    let result = Value::try_from(immutable_json::api::Value::Object(
        decoded
            .merge(&found)
            .add_string("iss", &issuer)
            .add_string("kid", &signer.kid),
    ))?;
    let mut header = Header::new(Algorithm::from_str(&signer.alg)?);

    header.kid = Some(signer.kid);
    resp.add_header("Content-Type", "application/jose", true)?;
    resp.write_body(encode(&header, &result, &signer.key)?)?;
    Ok(())
}

#[handler]
async fn handle_well_known(
    req: &Request,
    resp: &mut Response,
    depot: &mut Depot,
) -> Result<(), ServerError> {
    resp.add_header("Content-Type", "application/json", true)?;
    resp.write_body(well_known(
        config_from_depot(depot)?,
        &alg_from_depot(depot).await?,
        req.scheme(),
    )?)?;
    Ok(())
}

async fn issuer_state() -> Result<AffixList, ServerError> {
    debug!("Setting issuer state");
    Ok(affix_state::inject(Arc::new(IssuerState {
        issuers: Mutex::new(HashMap::new()),
    })))
}

fn issuer_state_from_depot(depot: &Depot) -> Result<&Arc<IssuerState>, ServerError> {
    debug!("Getting issuer state");
    depot
        .get_typed::<Arc<IssuerState>>()
        .map_err(|_| ServerError::IssuerState)
}

fn json_array_to_aggregation(array: &[Value]) -> Vec<Document> {
    array
        .iter()
        .filter_map(|v| v.as_object())
        .cloned()
        .flat_map(|o| Document::try_from(o).ok())
        .collect()
}

fn json_to_aggregation(json: &str) -> Result<Vec<Document>, ServerError> {
    let value = serde_json::from_str::<Value>(json)?;

    match value {
        Value::Array(v) => Ok(json_array_to_aggregation(&v)),
        _ => Err(ServerError::NoAggregation),
    }
}

fn jwks_state(config: &Config) -> Result<AffixList, ServerError> {
    debug!("Setting JWKS state");
    Ok(affix_state::inject(Arc::new(JwksState {
        loaded: Mutex::new(JwksLoaded {
            jwks_file: config.get_string(JWKS_FILE)?,
            loaded: None,
            response: "{}".to_string(),
        }),
    })))
}

fn jwks_state_from_depot(depot: &Depot) -> Result<&Arc<JwksState>, ServerError> {
    depot
        .get_typed::<Arc<JwksState>>()
        .map_err(|_| ServerError::JwksState)
}

fn key_state(config: &Config) -> Result<AffixList, ServerError> {
    debug!("Setting key state");
    Ok(affix_state::inject(Arc::new(KeyState {
        loaded: Mutex::new(KeyLoaded {
            key_file: config.get_string(KEY_FILE)?,
            loaded: None,
            signer: None,
        }),
    })))
}

fn key_state_from_depot(depot: &Depot) -> Result<&Arc<KeyState>, ServerError> {
    debug!("Getting key state");
    depot
        .get_typed::<Arc<KeyState>>()
        .map_err(|_| ServerError::KeyState)
}

async fn load_issuer(issuer: &str, audiences: &[String]) -> Result<Issuer, ServerError> {
    info!("Loading issuer {0}", issuer);
    Ok(Issuer {
        audiences: audiences.to_vec(),
        loaded: SystemTime::now(),
        jwks: get_jwk_set(issuer).await?,
    })
}

async fn load_issuers(
    issuers: &mut HashMap<String, Issuer>,
    depot: &Depot,
) -> Result<(), ServerError> {
    let config = config_from_depot(depot)?;
    let configured: Vec<(String, Vec<String>)> = config
        .get_array("issuers")?
        .iter()
        .filter_map(|v| v.clone().into_table().ok())
        .filter_map(|table| {
            table
                .get("iss")
                .and_then(|i| i.clone().into_string().ok())
                .map(|issuer| (issuer, get_audiences(&table)))
        })
        .collect();

    for (issuer, audience) in configured {
        issuers.insert(issuer.clone(), load_issuer(&issuer, &audience).await?);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let config = config()?;
    let server = Server::new(&config, "", Cli::parse().port.unwrap_or_default())?;

    info!("Version: {VERSION}");
    server
        .run(router(&database(&config).await?, &config).await?)
        .await?;
    Ok(())
}

#[handler]
fn not_implemented() -> Result<(), ServerError> {
    Err(ServerError::NotImplemented)
}

fn replace_array_fields(
    array: &bson::Array,
    token: &Object,
    query: &MultiMap<String, String>,
) -> bson::Array {
    let mut new_array = bson::Array::new();

    array
        .iter()
        .map(|v| replace_field_bson(v, token, query))
        .for_each(|v| new_array.push(v));

    new_array
}

fn replace_field(s: &str, token: &Object, query: &MultiMap<String, String>) -> Bson {
    if s.starts_with("$$") {
        field_from_query(s, query)
    } else if s.starts_with("${") && s.ends_with("}") {
        field_from_token(&s[2..s.len() - 1], token)
    } else {
        Bson::String(s.to_string())
    }
}

fn replace_field_bson(v: &Bson, token: &Object, query: &MultiMap<String, String>) -> Bson {
    match v {
        Bson::String(s) => replace_field(s, token, query),
        Bson::Array(a) => Bson::Array(replace_array_fields(a, token, query)),
        Bson::Document(d) => Bson::Document(replace_document_fields(d, token, query)),
        _ => v.clone(),
    }
}

fn replace_document_fields(
    document: &Document,
    token: &Object,
    query: &MultiMap<String, String>,
) -> Document {
    let mut new_document = Document::new();

    document
        .iter()
        .map(|(k, v)| (k, replace_field_bson(v, token, query)))
        .for_each(|(k, v)| {
            new_document.insert(k, v);
        });

    new_document
}

fn resolve_aggregation(
    aggregation: &[Document],
    token: &Object,
    query: &MultiMap<String, String>,
) -> Vec<Document> {
    debug!("URL query: {0:?}", query);
    let result: Vec<Document> = aggregation
        .iter()
        .map(|d| replace_document_fields(d, token, query))
        .collect();

    debug!(
        "Aggregation: {0}",
        from_bson(&Bson::Array(to_bson(&result)))
            .map(|json| json.to_string())
            .unwrap_or_default()
    );
    result
}

async fn router(database: &Database, config: &Config) -> Result<Router, ServerError> {
    Ok(Router::new()
        .hoop(affix_state::inject(config.clone()))
        .push(Router::with_path("/auth").get(not_implemented))
        .push(Router::with_path("/token").get(not_implemented))
        .hoop(jwks_state(config)?)
        .push(Router::with_path("/jwks").get(handle_jwks))
        .push(
            Router::with_hoop(key_state(config)?)
                .push(Router::with_path("/.well-known/openid-configuration").get(handle_well_known))
                .push(
                    Router::with_hoop(affix_state::inject(handlers(config, database)?))
                        .hoop(issuer_state().await?)
                        .push(Router::with_path("/{**}").get(handle_jwt)),
                ),
        ))
}

fn signer(key: &Key) -> Result<Signer, ServerError> {
    let encoding_key = if key.alg.starts_with("ES") {
        Some(EncodingKey::from_ec_pem(key.pem.as_bytes())?)
    } else if key.alg.starts_with("Ed") {
        Some(EncodingKey::from_ed_pem(key.pem.as_bytes())?)
    } else if key.alg.starts_with("RS") {
        Some(EncodingKey::from_rsa_pem(key.pem.as_bytes())?)
    } else {
        None
    };

    match encoding_key {
        Some(k) => Ok(Signer {
            alg: key.alg.clone(),
            key: k,
            kid: key.kid.clone(),
        }),
        None => Err(ServerError::Alg),
    }
}

fn to_bson(documents: &[Document]) -> Vec<Bson> {
    documents
        .iter()
        .map(|d| Bson::Document(d.clone()))
        .collect()
}

async fn verified_token(
    token: &str,
    issuers: &mut HashMap<String, Issuer>,
    metadata: &TokenMetadata,
) -> Result<Value, ServerError> {
    Ok(decode::<Value>(
        &token,
        &get_verifier(issuers, &metadata.iss, &metadata.kid).await?,
        &get_validation(issuers, metadata),
    )
    .map_err(|e| {
        debug!("Invalid signature: {0}", e);
        ServerError::Unauthorized
    })?
    .claims)
}

fn well_known(config: &Config, alg: &str, scheme: &Scheme) -> Result<String, ServerError> {
    let issuer = &config
        .get_string(THIS_ISSUER)?
        .replace("http", scheme.as_str());

    Ok(Object::new()
        .add_string("issuer", issuer)
        .add_string("authorization_endpoint", &(issuer.to_string() + "/auth"))
        .add_string("token_endpoint", &(issuer.to_string() + "/token"))
        .add_string("jwks_uri", &(issuer.to_string() + "/jwks"))
        .add_array(
            "subject_types_supported",
            &Array::new().add_string("public"),
        )
        .add_array(
            "id_token_signing_alg_values_supported",
            &Array::new().add_string(alg),
        )
        .to_string())
}
