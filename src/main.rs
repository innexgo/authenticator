use clap::Parser;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};
use warp::Filter;

use mail_service_api::client::MailService;

mod utils;

mod api;
mod db_types;
mod handlers;

// database interface
mod api_key_service;
mod email_service;
mod password_reset_service;
mod password_service;
mod user_data_service;
mod user_service;
mod verification_challenge_service;

static SERVICE_NAME: &str = "auth-service";
static VERSION_MAJOR: i64 = 0;
static VERSION_MINOR: i64 = 0;
static VERSION_REV: i64 = 1;

#[derive(Parser, Clone)]
#[clap(about, version, author)]
struct Opts {
    #[clap(short, long)]
    port: u16,
    #[clap(short, long)]
    site_external_url: String,
    #[clap(short, long)]
    database_url: String,
    #[clap(short, long)]
    mail_service_url: String,
    #[clap(short, long)]
    permitted_sources: String,
}

#[derive(Clone)]
pub struct Data {
    pub db: Arc<Mutex<Client>>,
    pub mail_service: MailService,
    pub permitted_sources: Vec<String>,
    pub site_external_url: String,
}

#[tokio::main]
async fn main() -> Result<(), tokio_postgres::Error> {
    let Opts {
        port,
        database_url,
        mail_service_url,
        site_external_url,
        permitted_sources,
    } = Opts::parse();

    let (client, connection) = loop {
        match tokio_postgres::connect(&database_url, NoTls).await {
            Ok(v) => break v,
            Err(e) => utils::log(utils::Event {
                msg: e.to_string(),
                source: e.source().map(|x| x.to_string()),
                severity: utils::SeverityKind::Error,
            }),
        }

        // sleep for 5 seconds
        std::thread::sleep(std::time::Duration::from_secs(5));
    };

    // The connection object performs the actual communication with the database,
    // so spawn it off to run on its own.
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let data = Data {
        db: Arc::new(Mutex::new(client)),
        mail_service: MailService::new(&mail_service_url).await,
        permitted_sources: permitted_sources.split(',').map(|x| x.into()).collect(),
        site_external_url,
    };

    let api = api::api(data);

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
