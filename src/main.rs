use clap::Clap;
use rusqlite::Connection;
use std::sync::Mutex;

mod auth_model;
mod auth_api;
mod auth_handlers;
mod log_service;

static SERVICE_NAME: &str = "auth-api";

#[derive(Clap, Clone)]
struct Opts {
  #[clap(short, long)]
  database_url: String,
  #[clap(short, long)]
  port: u16,
  #[clap(short, long)]
  mail_service_url: String,
  #[clap(short, long)]
  log_service_url: String,
  // named so people can say --verbose
  #[clap(short, long, parse(from_occurrences))]
  verbose: u32,
}


#[tokio::main]
async fn main() {
  let Opts {
    database_url,
    port,
    mail_service_url,
    log_service_url,
    verbose,
  } = Opts::parse();

  let logger = log_service::LogService::new(&log_service_url, SERVICE_NAME);

  let db:auth_model::Db = Mutex::new(Connection::open(database_url).unwrap());

  let api = auth_api::api(db, logger);

  warp::serve(api).run(([127, 0, 0, 1], port)).await;
}
