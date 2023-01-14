use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use clap::Parser;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_postgres::{Client, NoTls};

use mail_service_api::client::MailService;

mod utils;

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

static SERVICE_NAME: &str = "authenticator";
static VERSION_MAJOR: i64 = 0;
static VERSION_MINOR: i64 = 0;
static VERSION_REV: i64 = 1;

#[derive(Parser, Clone)]
#[clap(about, version, author)]
struct Opts {
    #[clap(long)]
    port: u16,
    #[clap(long)]
    site_external_url: String,
    #[clap(long)]
    database_url: String,
    #[clap(long)]
    mail_service_url: String,
    #[clap(long)]
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
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    env_logger::init();

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
            Err(e) => {
                log::error!("{}", e);
            }
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

    HttpServer::new(move || {
        let cors = Cors::permissive();

        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(actix_web::web::Data::new(data.clone()))
            .service(web::resource("/public/info").route(web::route().to(handlers::info)))
            .service(
                web::resource("/public/verification_challenge/new")
                    .route(web::route().to(handlers::verification_challenge_new)),
            )
            .service(
                web::resource("public/api_key/new_with_email")
                    .route(web::route().to(handlers::api_key_new_with_email)),
            )
            .service(
                web::resource("public/api_key/new_with_username")
                    .route(web::route().to(handlers::api_key_new_with_username)),
            )
            .service(
                web::resource("public/api_key/new_cancel")
                    .route(web::route().to(handlers::api_key_new_cancel)),
            )
            .service(web::resource("public/user/new").route(web::route().to(handlers::user_new)))
            .service(
                web::resource("public/user_data/new")
                    .route(web::route().to(handlers::user_data_new)),
            )
            .service(web::resource("public/email/new").route(web::route().to(handlers::email_new)))
            .service(
                web::resource("public/password_reset/new")
                    .route(web::route().to(handlers::password_reset_new)),
            )
            .service(
                web::resource("public/password/new_reset")
                    .route(web::route().to(handlers::password_new_reset)),
            )
            .service(
                web::resource("public/password/new_change")
                    .route(web::route().to(handlers::password_new_change)),
            )
            .service(web::resource("public/user/view").route(web::route().to(handlers::user_view)))
            .service(
                web::resource("public/user_data/view")
                    .route(web::route().to(handlers::user_data_view)),
            )
            .service(
                web::resource("public/password/view")
                    .route(web::route().to(handlers::password_view)),
            )
            .service(
                web::resource("public/email/view").route(web::route().to(handlers::email_view)),
            )
            .service(
                web::resource("public/api_key/view").route(web::route().to(handlers::api_key_view)),
            )
            .service(
                web::resource("get_user_by_id").route(web::route().to(handlers::get_user_by_id)),
            )
            .service(
                web::resource("get_user_by_api_key_if_valid")
                    .route(web::route().to(handlers::get_user_by_api_key_if_valid)),
            )
    })
    .bind((Ipv4Addr::LOCALHOST, port))?
    .run()
    .await?;

    Ok(())
}
