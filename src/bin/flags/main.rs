use std::sync::{Arc, Mutex};
use axum::response::{IntoResponse, Response};
use clap::Parser;
use nanoid::nanoid;
use serde_json::{json, Value};
use serde::{Deserialize, Serialize};
use anyhow::anyhow;
use axum::{extract, Json, Router};
use axum::routing::get;
use axum::http::StatusCode;
use axum::extract::{
    Request,
    Path,
    State,
};
use axum::extract::MatchedPath;
use headers::Authorization;
use headers::authorization::Bearer;
use axum_extra::TypedHeader;
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use base64::engine::Engine;
use base64::engine::general_purpose::URL_SAFE;
use chrono::Utc;
use tower_http::trace::TraceLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Account {
    id: String,
    key_hash: String,
    desc: String,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Flag {
    key: String,
    value: Value,
    desc: String,
    created_at: String,
    updated_at: String,
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
        let mut stmt = self.db.prepare("SELECT id, key_hash, desc, created_at, updated_at FROM accounts")?;
        let rows = stmt.query_map([], |row| {
            Ok(Account {
                id: row.get(0)?,
                key_hash: row.get(1)?,
                desc: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        let mut users = Vec::new();
        for row in rows {
            users.push(row?);
        }
        Ok(users)
    }

    fn create_user(&self, key: &str, desc: &str) -> anyhow::Result<Account> {
        let id = nanoid!(10);
        let key_hash = hash_key(key);
        let now = Utc::now().to_rfc3339();
        let acct = Account {
            id: id.clone(),
            key_hash: key_hash.clone(),
            desc: desc.to_string(),
            created_at: now.clone(),
            updated_at: now,
        };
        self.db.execute(
            "INSERT INTO accounts (id, key_hash, desc, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
            [acct.id.clone(), acct.key_hash.clone(), acct.desc.clone(), acct.created_at.clone(), acct.updated_at.clone()],
        )?;
        Ok(acct)
    }

    fn get_user(&self, id: &str) -> anyhow::Result<Option<Account>> {
        let mut stmt = self.db.prepare("SELECT id, key_hash, desc, created_at, updated_at FROM accounts WHERE id = ?")?;
        match stmt.query_row([id], |row| {
            Ok(Account {
                id: row.get(0)?,
                key_hash: row.get(1)?,
                desc: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        }) {
            Ok(a) => Ok(Some(a)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn validate_user(&self, key: &str) -> anyhow::Result<bool> {
        let key_hash = hash_key(key);
        if key_hash == self.admin_token_hash {
            return Ok(true);
        }
        match self.get_user_by_key(&key)? {
            None => Ok(false),
            Some(_) => Ok(true),
        }
    }

    fn get_user_by_key(&self, key: &str) -> anyhow::Result<Option<Account>> {
        let hashed_key = hash_key(key);
        let mut stmt = self.db.prepare("SELECT id, key_hash, desc, created_at, updated_at FROM accounts WHERE key_hash = ?")?;
        let row = stmt.query_row([hashed_key], |row| {
            Ok(Account {
                id: row.get(0)?,
                key_hash: row.get(1)?,
                desc: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        Ok(Some(row))
    }

    fn update_user(&self, id: &str, key: Option<String>, desc: Option<String>) -> anyhow::Result<()> {
        match (key, desc) {
            (Some(k), Some(d)) => {
                self.db.execute(
                    "UPDATE accounts SET key = ?, desc = ?, updated_at = ? WHERE id = ?;",
                    [k, d, Utc::now().to_rfc3339(), id.to_string()],
                )?;
            },
            (Some(k), None) => {
                self.db.execute(
                    "UPDATE accounts SET key = ?, updated_at = ? WHERE id = ?;",
                    [k, Utc::now().to_rfc3339(), id.to_string()],
                )?;
            },
            (None, Some(d)) => {
                self.db.execute(
                    "UPDATE accounts SET desc = ?, updated_at = ? WHERE id = ?;",
                    [d, Utc::now().to_rfc3339(), id.to_string()],
                )?;
            },
            (None, None) => {},
        };
        Ok(())
    }

    fn delete_user(&self, id: &str) -> anyhow::Result<()> {
        let mut stmt = self.db.prepare("DELETE FROM accounts WHERE id = ?")?;
        stmt.execute([id])?;
        Ok(())
    }

    fn list_flags(&self) -> anyhow::Result<Vec<Flag>> {
        let mut stmt = self.db.prepare("SELECT key, value, desc, created_at, updated_at FROM flags")?;
        let rows = stmt.query_map([], |row| {
            Ok(Flag {
                key: row.get(0)?,
                value: Value::String(row.get(1)?),
                desc: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        })?;
        let mut flags = Vec::new();
        for row in rows {
            let row = row?;
            let value = match &row.value {
                Value::String(s) => s.clone(),
                _ => return Err(anyhow!("Invalid value type")),
            };
            let value = serde_json::from_str(&value)?;
            flags.push(Flag {
                key: row.key,
                value,
                desc: row.desc,
                created_at: row.created_at,
                updated_at: row.updated_at,
            });
        }
        Ok(flags)
    }

    fn create_flag(&self, key: &str, value: Value, desc: &str) -> anyhow::Result<Flag> {
        let now = Utc::now().to_rfc3339();
        let flag = Flag {
            key: key.to_string(),
            value,
            desc: desc.to_string(),
            created_at: now.clone(),
            updated_at: now,
        };
        let svalue = serde_json::to_string(&flag.value)?;
       
        self.db.execute(
            "INSERT INTO flags (key, value, desc, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
            [flag.key.clone(), svalue, flag.desc.clone(), flag.created_at.clone(), flag.updated_at.clone()],
        )?;
        Ok(flag)
    }

    fn get_flag(&self, key: &str) -> anyhow::Result<Option<Flag>> {
        let mut stmt = self.db.prepare("SELECT key, value, desc, created_at, updated_at FROM flags WHERE key = ?")?;
        let mut flag = match stmt.query_row([key], |row| {
            Ok(Flag {
                key: row.get(0)?,
                value: Value::String(row.get(1)?),
                desc: row.get(2)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            })
        }) {
            Ok(k) => k,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let value = match &flag.value {
            Value::String(s) => s.clone(),
            _ => return Err(anyhow!("Invalid value type")),
        };
        let value = serde_json::from_str(&value)?;
        flag.value = value;
        Ok(Some(flag))
    }

    fn update_flag(&self, key: &str, value: Option<Value>, desc: Option<String>) -> anyhow::Result<()> {
        match (value, desc) {
            (Some(v), Some(d)) => {
                let svalue = serde_json::to_string(&v)?;
                self.db.execute(
                    "UPDATE flags SET value = ?, desc = ?, updated_at = ? WHERE key = ?;",
                    [svalue, d, Utc::now().to_rfc3339(), key.to_string()],
                )?;
            },
            (Some(v), None) => {
                let svalue = serde_json::to_string(&v)?;
                self.db.execute(
                    "UPDATE flags SET value = ?, updated_at = ? WHERE key = ?;",
                    [svalue, Utc::now().to_rfc3339(), key.to_string()],
                )?;
            },
            (None, Some(d)) => {
                self.db.execute(
                    "UPDATE flags SET desc = ?, updated_at = ? WHERE key = ?;",
                    [d, Utc::now().to_rfc3339(), key.to_string()],
                )?;
            },
            (None, None) => {},
        };
        Ok(())
    }

    fn delete_flag(&self, key: &str) -> anyhow::Result<()> {
        self.db.execute("DELETE FROM flags WHERE key = ?;", [key])?;
        Ok(())
    }
}

fn generate_key() -> anyhow::Result<String> {
    let mut buf = [0u8; 32];
    getrandom::getrandom(&mut buf)?;
    Ok(URL_SAFE.encode(&buf))
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

async fn list_accounts(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Get the list of users
    let data = state
        .list_users()?
        .iter()
        .map(|u| json!({
            "id": u.id.clone(),
            "desc": u.desc.clone(),
            "created_at": u.created_at,
            "updated_at": u.updated_at,
        }))
        .collect::<Vec<_>>();

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": data,
    }))))
}

#[derive(serde::Deserialize)]
struct CreateAccountRequest {
    desc: Option<String>,
}

async fn create_account(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    extract::Json(req): extract::Json<CreateAccountRequest>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Create a random API key
    let key = generate_key()?;

    // Create the user
    let desc = req.desc.unwrap_or("".to_string());
    let user = state.create_user(
        key.as_str(),
        &desc,
    )?;

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": {
            "apiKey": key,
            "id": user.id,
            "desc": user.desc,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        },
    }))))
}

async fn read_account(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(id): Path<String>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Get the user
    let user = match state.get_user(&id)? {
        Some(u) => u,
        None => return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "message": "Account not found",
            }))
        )),
    };

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": {
            "id": user.id,
            "desc": user.desc,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        },
    }))))
}

#[derive(Deserialize)]
struct UpdateAccountRequest {
    key: Option<String>,
    desc: Option<String>,
}

async fn update_account(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(id): Path<String>,
    extract::Json(req): extract::Json<UpdateAccountRequest>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Get the list of users
    state.update_user(
        &id,
        req.key,
        req.desc,
    )?;
    
    // Get the user
    let user = match state.get_user(&id)? {
        Some(u) => u,
        None => return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "message": "Account not found",
            }))
        )),
    };

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": {
            "id": user.id,
            "desc": user.desc,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        },
    }))))
}

async fn delete_account(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(id): Path<String>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Get the list of users
    state.delete_user(&id)?;

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
    }))))
}

async fn list_flags(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Get the list of users
    let data = state.list_flags()?;

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": data,
    }))))
}

#[derive(serde::Deserialize)]
struct CreateFlagRequest {
    key: String,
    value: Value,
    desc: Option<String>,
}

async fn create_flag(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    extract::Json(req): extract::Json<CreateFlagRequest>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Create the flag
    let desc = req.desc.unwrap_or("".to_string());
    let flag = state.create_flag(
        &req.key,
        req.value,
        &desc,
    )?;

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": flag,
    }))))
}

async fn read_flag(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(key): Path<String>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Get the flag
    let flag = match state.get_flag(&key)? {
        Some(f) => f,
        None => return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "message": "Flag not found",
            }))
        )),
    };

    // Return the flag
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": flag,
    }))))
}

#[derive(Deserialize)]
struct UpdateFlagRequest {
    value: Option<Value>,
    desc: Option<String>,
}

async fn update_flag(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(key): Path<String>,
    extract::Json(req): extract::Json<UpdateFlagRequest>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Update the flag
    state.update_flag(
        &key,
        req.value,
        req.desc,
    )?;

    // Get the updated flag
    let flag = match state.get_flag(&key)? {
        Some(f) => f,
        None => return Ok((
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "message": "Flag not found",
            }))
        )),
    };

    // Return the flag
    Ok((StatusCode::OK, Json(json!({
        "success": true,
        "data": flag,
    }))))
}

async fn delete_flag(
    State(state): State<Arc<Mutex<AppState>>>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Path(key): Path<String>,
) -> AppResult<(StatusCode, Json<Value>)> {
    // Get the request token
    let token = match auth.token() {
        "" => return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        )),
        t => t,
    };

    // Get the user
    let state = state.lock().unwrap();
    if !state.validate_user(&token)? {
         return Ok((
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "success": false,
                "message": "Unauthorized",
            }))
        ));
    }

    // Get the list of users
    state.delete_flag(&key)?;

    // Return the list of users
    Ok((StatusCode::OK, Json(json!({
        "success": true,
    }))))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Parse and validate the input arguments
    let args = Args::parse();

    // Set up logging
    tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(if args.debug {
                    tracing_subscriber::filter::LevelFilter::DEBUG.into()
                } else {
                    tracing_subscriber::filter::LevelFilter::ERROR.into()
                })
                .from_env_lossy()
        )
        .with(tracing_subscriber::fmt::layer())
        .init()
        ;

    // Set up the application state
    let state = AppState::connect(&args)?;
    let state = Arc::new(Mutex::new(state));

    // Create the Axum app
    let app = Router::new()
        .route("/api/accounts", get(list_accounts).post(create_account))
        .route("/api/accounts/:id", get(read_account).put(update_account).delete(delete_account))
        .route("/api/flags", get(list_flags).post(create_flag))
        .route("/api/flags/:id", get(read_flag).put(update_flag).delete(delete_flag))
        .with_state(state)
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &Request<_>| {
                    let matched_path = req
                        .extensions()
                        .get::<MatchedPath>()
                        .map(|m| m.as_str());
                    tracing::info_span!(
                        "http_request",
                        method = ?req.method(),
                        matched_path,
                    )
                })
        )
        ;

    // Listen and serve
    tracing::info!("Listening on {}", args.address);
    let listener = tokio::net::TcpListener::bind(&args.address).await?;
    axum::serve(listener, app).await?;

    // Done (shouldn't get here)
    Ok(())
}
