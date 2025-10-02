use std::{collections::BTreeMap, env, net::SocketAddr, sync::Arc};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Json, Router,
};
use tokio::net::TcpListener;
use dotenvy::dotenv;
use md5::{Digest, Md5};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};
use tokio::sync::RwLock;

struct AppState {
    http: Client,
    api_key: String,
    shared_secret: String,
    session_key: RwLock<Option<String>>,
    username: RwLock<Option<String>>,
}

#[derive(Debug, Error)]
enum AppError {
    #[error("missing configuration: {0}")]
    MissingConfig(&'static str),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        error!(err = ?self, "request failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error").into_response()
    }
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    dotenv().ok();
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    fmt().with_env_filter(filter).init();

    let api_key = env::var("LAST_FM_API_KEY").map_err(|_| AppError::MissingConfig("LAST_FM_API_KEY"))?;
    let shared_secret = env::var("LAST_FM_SHARED_SECRET").map_err(|_| AppError::MissingConfig("LAST_FM_SHARED_SECRET"))?;

    let state = Arc::new(AppState {
        http: Client::new(),
        api_key,
        shared_secret,
        session_key: RwLock::new(None),
        username: RwLock::new(None),
    });

    let app = Router::new()
        .route("/auth/start", get(auth_start))
        .route("/auth/callback", get(auth_callback))
        .route("/recent", get(recent_tracks))
        .route("/recent_public", get(recent_tracks_public))
        .with_state(state);

    let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let listener = TcpListener::bind(&addr).await.unwrap();
    info!(%addr, "listening");
    axum::serve(listener, app).await.unwrap();
    Ok(())
}

#[derive(Deserialize)]
struct StartParams {
    cb: Option<String>,
}

async fn auth_start(State(state): State<Arc<AppState>>, Query(params): Query<StartParams>) -> Result<impl IntoResponse, AppError> {
    let mut url = format!("https://www.last.fm/api/auth/?api_key={}", state.api_key);
    if let Some(cb) = params.cb {
        // Last.fm expects raw cb param; to be safe, encode it
        let cb_enc = urlencoding::encode(&cb);
        url.push_str("&cb=");
        url.push_str(&cb_enc);
    }
    Ok(Redirect::to(&url))
}

#[derive(Deserialize)]
struct CallbackParams {
    token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GetSessionResponse {
    session: Session,
}

#[derive(Debug, Serialize, Deserialize)]
struct Session {
    key: String,
    name: String,
    subscriber: u8,
}

async fn auth_callback(State(state): State<Arc<AppState>>, Query(params): Query<CallbackParams>) -> Result<impl IntoResponse, AppError> {
    // Build params for auth.getSession
    let mut params_map: BTreeMap<&str, String> = BTreeMap::new();
    params_map.insert("api_key", state.api_key.clone());
    params_map.insert("method", "auth.getSession".to_string());
    params_map.insert("token", params.token.clone());

    let api_sig = sign(&params_map, &state.shared_secret);
    let mut form = params_map.clone();
    form.insert("api_sig", api_sig);
    form.insert("format", "json".to_string());

    let resp = state
        .http
        .post("https://ws.audioscrobbler.com/2.0/")
        .form(&form)
        .send()
        .await?
        .error_for_status()?;

    let payload: GetSessionResponse = resp.json().await?;
    {
        let mut sk = state.session_key.write().await;
        *sk = Some(payload.session.key.clone());
    }
    {
        let mut uname = state.username.write().await;
        *uname = Some(payload.session.name.clone());
    }
    Ok(Json(payload))
}

fn sign(params: &BTreeMap<&str, String>, shared_secret: &str) -> String {
    // Concatenate sorted key-value pairs without separators, then append shared secret and md5
    let mut concatenated = String::new();
    for (k, v) in params.iter() {
        concatenated.push_str(k);
        concatenated.push_str(v);
    }
    concatenated.push_str(shared_secret);
    let mut hasher = Md5::new();
    hasher.update(concatenated.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[derive(Deserialize)]
struct RecentParams {
    limit: Option<u32>,
    page: Option<u32>,
}

async fn recent_tracks(State(state): State<Arc<AppState>>, Query(q): Query<RecentParams>) -> Result<impl IntoResponse, AppError> {
    let sk = state.session_key.read().await.clone();
    let username = state.username.read().await.clone();
    let (sk, username) = match (sk, username) {
        (Some(sk), Some(u)) => (sk, u),
        _ => return Ok((StatusCode::UNAUTHORIZED, "No session. Authenticate via /auth/start").into_response()),
    };

    let mut params_map: BTreeMap<&str, String> = BTreeMap::new();
    params_map.insert("api_key", state.api_key.clone());
    params_map.insert("method", "user.getRecentTracks".to_string());
    params_map.insert("sk", sk);
    params_map.insert("user", username);
    if let Some(limit) = q.limit { params_map.insert("limit", limit.to_string()); }
    if let Some(page) = q.page { params_map.insert("page", page.to_string()); }

    let api_sig = sign(&params_map, &state.shared_secret);
    let mut form = params_map.clone();
    form.insert("api_sig", api_sig);
    form.insert("format", "json".to_string());

    let resp = state
        .http
        .post("https://ws.audioscrobbler.com/2.0/")
        .form(&form)
        .send()
        .await?
        .error_for_status()?;

    let json = resp.text().await?; // Keep as text to pass through unmodified
    Ok((StatusCode::OK, json).into_response())
}

#[derive(Deserialize)]
struct RecentPublicParams {
    user: String,
    limit: Option<u32>,
    page: Option<u32>,
    from: Option<u64>,
    to: Option<u64>,
    extended: Option<u8>, // 0|1
}

async fn recent_tracks_public(State(state): State<Arc<AppState>>, Query(q): Query<RecentPublicParams>) -> Result<impl IntoResponse, AppError> {
    // No auth required; call with only api_key + method + user (+ optional params)
    let mut params_map: BTreeMap<&str, String> = BTreeMap::new();
    params_map.insert("api_key", state.api_key.clone());
    params_map.insert("method", "user.getRecentTracks".to_string());
    params_map.insert("user", q.user.clone());
    if let Some(limit) = q.limit { params_map.insert("limit", limit.to_string()); }
    if let Some(page) = q.page { params_map.insert("page", page.to_string()); }
    if let Some(from) = q.from { params_map.insert("from", from.to_string()); }
    if let Some(to) = q.to { params_map.insert("to", to.to_string()); }
    if let Some(extended) = q.extended { params_map.insert("extended", extended.to_string()); }

    // No signature for public method
    let mut form = params_map;
    form.insert("format", "json".to_string());

    let resp = state
        .http
        .post("https://ws.audioscrobbler.com/2.0/")
        .form(&form)
        .send()
        .await?
        .error_for_status()?;

    let json = resp.text().await?;
    Ok((StatusCode::OK, json).into_response())
}
