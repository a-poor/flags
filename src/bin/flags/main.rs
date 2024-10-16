use std::sync::{Arc, Mutex};
use axum::response::{IntoResponse, Response};
use clap::Parser;
use serde_json::{json, Value};
use anyhow::anyhow;
use axum::{Json, Router};
use axum::routing::get;
use axum::http::StatusCode;
use axum::extract::{
    Request,
    Path,
    Query,
    State,
    Json as JsonBody,
};
use headers::Authorization;
use headers::authorization::Bearer;
use axum_extra::TypedHeader;
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use base64::engine::Engine;
use base64::engine::general_purpose::URL_SAFE;
use chrono::{DateTime, Utc};
use nanoid::nanoid;

#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, default_value = "0.0.0.0:4132")]
    address: String,

    #[clap(short='p', long, default_value = "./flags.db")]
    db_path: String,

    #[clap(short='t', long, env)]
    admin_token: String,
    
    #[clap(short, long)]
    debug: bool,
}

struct AppState {
    db: Connection,
    admin_token_hash: String,
}

#[derive(Debug, Clone)]
struct Account {
    id: String,
    key_hash: String,
    desc: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct Flag {
    key: String,
    value: Value,
    desc: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl AppState {
    fn connect(args: &Args) -> anyhow::Result<Self> {
        let db = get_db_connection(&args.db_path)?;
        let admin_token_hash = hash_key(&args.admin_token);
        Ok(Self {
            db,
            admin_token_hash,
        })
    }

    fn list_users(&self) -> anyhow::Result<Vec<Account>> {
        unimplemented!()
    }

    fn create_users(&self, key: &str, desc: &str) -> anyhow::Result<Account> {
        unimplemented!()
    }

    fn get_user(&self, id: &str) -> anyhow::Result<Option<Account>> {
        unimplemented!()
    }

    fn get_user_by_key(&self, key: &str) -> anyhow::Result<Option<Account>> {
        unimplemented!()
    }

    fn update_user(&self, id: &str, key: Option<String>, desc: Option<String>) -> anyhow::Result<()> {
        unimplemented!()
    }

    fn delete_user(&self, id: &str) -> anyhow::Result<()> {
        unimplemented!()
    }

    fn list_flags(&self) -> anyhow::Result<Vec<Flag>> {
        unimplemented!()
    }

    fn create_flag(&self, key: &str, value: Value, desc: &str) -> anyhow::Result<Flag> {
        unimplemented!()
    }

    fn get_flag(&self, key: &str) -> anyhow::Result<Option<Flag>> {
        unimplemented!()
    }

    fn update_flag(&self, key: Option<String>, value: Option<Value>, desc: Option<String>) -> anyhow::Result<()> {
        unimplemented!()
    }

    fn delete_flag(&self, key: &str) -> anyhow::Result<()> {
        unimplemented!()
    }
}

fn hash_key(key: &str) -> String {
    let d = Sha256::digest(key);
    URL_SAFE
        .encode(d)
        .chars()
        .take(32)
        .collect::<String>()
}

fn get_db_connection(path: &str) -> anyhow::Result<Connection> {
    // Does the path exist? If yes, open and return...
    if path != ":memory:" && std::path::Path::new(&path).exists() {
        // TODO - Check that the required tables exist
        let db = Connection::open(path)?;
        return Ok(db);
    }

    // Otherwise, create it it...
    let db = if path == ":memory:" {
        Connection::open_in_memory()?
    } else {
        Connection::open(path)?
    };

    // And add required tables
    db.execute(
        "CREATE TABLE accounts (
            id         TEXT PRIMARY KEY,
            key_hash   TEXT,
            desc       TEXT NOT NULL,
            enabled    INT  NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );",
        [],
    )?;
    db.execute(
        "CREATE UNIQUE INDEX idx_accounts_key_hash ON accounts (key_hash);",
        [],
    )?;
    db.execute(
        "CREATE TABLE flags (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL,
            desc       TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )",
        [],
    )?;

    // Done
    Ok(db)
}

type AppResult<T> = Result<T, AppError>;

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "success": false,
                "message": self.0.to_string(),
            })),
        ).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(e: E) -> Self {
        Self(e.into())
    }
}

enum AuthResult {
    NoAuthHeader,
    NonBearerAuth,
    InvalidToken,
    Token(String),
}

fn get_auth_key<T>(req: &Request<T>) -> AuthResult {
    let headers = req.headers();
    let auth_header = match headers.get("Authorization") {
        None => return AuthResult::NoAuthHeader,
        Some(h) => h,
    };
    let auth_header = match auth_header.to_str() {
        Err(_) => return AuthResult::NoAuthHeader,
        Ok(h) => h,
    };

    if !auth_header.starts_with("Bearer ") {
        return AuthResult::NonBearerAuth;
    }

    let key = auth_header.trim_start_matches("Bearer ");
    if key.is_empty() {
        return AuthResult::InvalidToken;
    }

    AuthResult::Token(hash_key(key))
}

#[axum::debug_handler]
async fn list_accounts(
    State(state): State<Arc<Mutex<AppState>>>,
    request: Request<axum::body::Bytes>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match get_auth_key(&request) {
        AuthResult::Token(t) => hash_key(&t),
        _ => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
    };

    // Get the user
    let state = state.lock().map_err(|_| anyhow!("Failed to lock state"))?;
    match state.get_user_by_key(&token)? {
        None => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        _ => {},
    };

    // Get the list of users
    let data = state
        .list_users()?
        .iter()
        .map(|u| json!({
            "id": u.id.clone(),
            "desc": u.desc.clone(),
            "created_at": u.created_at.to_rfc3339(),
            "updated_at": u.updated_at.to_rfc3339(),
        }))
        .collect::<Vec<_>>();

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": data,
    }))))
}

async fn create_account() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn read_account() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn update_account() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn delete_account() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn list_flags() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn create_flag() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn read_flag() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn update_flag() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn delete_flag() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse and validate the input arguments
    let args = Args::parse();

    // Set up the application state
    let state = AppState::connect(&args)?;
    let state = Arc::new(Mutex::new(state));

    // Create the Axum app
    let app = Router::new()
        .route("/api/flags", get(list_flags).post(create_flag))
        .route("/api/flags/{id}", get(read_flag).put(update_flag).delete(delete_flag))
        .route("/api/accounts", get(list_accounts).post(create_account))
        .route("/api/accounts/{id}", get(read_account).put(update_account).delete(delete_account))
        .with_state(state)
        ;

    // Listen and serve
    let listener = tokio::net::TcpListener::bind(&args.address).await?;
    axum::serve(listener, app).await?;

    // Done (shouldn't get here)
    Ok(())
}
