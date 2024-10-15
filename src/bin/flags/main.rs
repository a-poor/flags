use std::sync::{Arc, Mutex};
use clap::Parser;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
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
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use base64::engine::Engine;
use base64::engine::general_purpose::URL_SAFE;

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

impl AppState {
    fn connect(args: &Args) -> Result<Self> {
        let db = get_db_connection(&args.db_path)?;
        let admin_token_hash = hash_key(&args.admin_token);
        Ok(Self {
            db,
            admin_token_hash,
        })
    }
}

fn hash_key(key: &str) -> String {
    let d = Sha256::digest(key);
    URL_SAFE.encode(d)
}

fn get_db_connection(path: &str) -> Result<Connection> {
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
            key_hash   TEXT PRIMARY KEY,
            desc       TEXT NOT NULL,
            enabled    INT  NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );",
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

async fn root() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
}

async fn list_accounts() -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!({"message": "Hello, world!"})))
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
async fn main() -> Result<()> {
    // Parse and validate the input arguments
    let args = Args::parse();

    // Set up the application state
    let state = AppState::connect(&args)?;
    let state = Arc::new(Mutex::new(state));

    // Create the Axum app
    let app = Router::new()
        .route("/", get(root))
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
