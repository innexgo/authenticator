#![feature(async_closure)]
use clap::Clap;
use rusqlite::Connection;
use std::sync::Arc;
use tokio::sync::Mutex;

use mail_service_api::client::MailService;

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
  port: u16,
  #[clap(short, long)]
  site_external_url: String,
  #[clap(short, long)]
  database_url: String,
  #[clap(short, long)]
  mail_service_url: String,
}

pub type Db = Arc<Mutex<Connection>>;

#[derive(Clone)]
pub struct Config {
    pub site_external_url:String,
}

#[tokio::main]
async fn main() {
  let Opts {
    port,
    database_url,
    mail_service_url,
    site_external_url,
  } = Opts::parse();

  // open connection to db
  let db: Db = Arc::new(Mutex::new(Connection::open(database_url).unwrap()));

  // open connection to mail service
  let mail_service = MailService::new(&mail_service_url).await;

  let api = auth_api::api(Config { site_external_url }, db, mail_service);

  warp::serve(api).run(([127, 0, 0, 1], port)).await;
}
