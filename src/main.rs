#![feature(async_closure)]
use warp::Filter;
use clap::Clap;
use tokio_postgres::{Client, NoTls};
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

pub type Db = Arc<Mutex<Client>>;

#[derive(Clone)]
pub struct Config {
    pub site_external_url:String,
}

#[tokio::main]
async fn main() -> Result<(), tokio_postgres::Error> {
  let Opts {
    port,
    database_url,
    mail_service_url,
    site_external_url,
  } = Opts::parse();

  let (client, connection) = tokio_postgres::connect(&database_url, NoTls).await?;

  // The connection object performs the actual communication with the database,
  // so spawn it off to run on its own.
  tokio::spawn(async move {
    if let Err(e) = connection.await {
      eprintln!("connection error: {}", e);
    }
  });

  let db: Db = Arc::new(Mutex::new(client));

  // open connection to mail service
  let mail_service = MailService::new(&mail_service_url).await;

  let api = auth_api::api(Config { site_external_url }, db, mail_service);

  let log = warp::log::custom(|info| {
    // Use a log macro, or slog, or println, or whatever!
    utils::log(utils::Event {
        msg: info.method().to_string(),
        source: Some(info.path().to_string()),
        severity: utils::SeverityKind::Info,
    });
  });

  warp::serve(api.with(log)).run(([0, 0, 0, 0], port)).await;

  Ok(())
}
