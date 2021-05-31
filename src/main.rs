#![feature(async_closure)]
use clap::Clap;
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

mod utils;

mod auth_api;
mod auth_db_types;
mod auth_handlers;

// database interface
mod api_key_service;
mod password_reset_service;
mod password_service;
mod user_service;
mod verification_challenge_service;

static SERVICE_NAME: &str = "auth-service";

#[derive(Clap, Clone)]
struct Opts {
  #[clap(short, long)]
  database_url: String,
  #[clap(short, long)]
  port: u16,
  #[clap(short, long)]
  mail_service_url: String,
}

pub type Db = Arc<Mutex<Connection>>;

#[tokio::main]
async fn main() {
  let Opts {
    database_url,
    port,
    mail_service_url,
  } = Opts::parse();

  let db: Db = Arc::new(Mutex::new(Connection::open(database_url).unwrap()));

  let api = auth_api::api(db);

  warp::serve(api).run(([127, 0, 0, 1], port)).await;
}
