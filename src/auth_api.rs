use super::auth_handlers;
use super::utils;
use super::Config;
use super::Db;
use super::SERVICE_NAME;
use auth_service_api::response::AuthError;
use mail_service_api::client::MailService;
use std::collections::HashMap;
use std::convert::Infallible;
use warp::http::StatusCode;
use warp::Filter;

/// The function that will show all ones to call
pub fn api(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = Infallible> + Clone {
  api_info()
    .or(verification_challenge_new(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .or(api_key_new_valid(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .or(api_key_new_cancel(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .or(user_new(config.clone(), db.clone(), mail_service.clone()))
    .or(password_reset_new(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .or(password_new_reset(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .or(password_new_change(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .or(password_new_cancel(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .or(user_view(config.clone(), db.clone(), mail_service.clone()))
    .or(password_view(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .or(api_key_view(
      config.clone(),
      db.clone(),
      mail_service.clone(),
    ))
    .recover(handle_rejection)
}

fn api_info() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  let mut info = HashMap::new();
  info.insert("version", "0.1");
  info.insert("name", SERVICE_NAME);
  warp::path!("info").map(move || warp::reply::json(&info))
}

// lets you pass in an arbitrary parameter
fn with<T: Clone + Send>(t: T) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
  warp::any().map(move || t.clone())
}

fn api_key_new_valid(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "api_key" / "new_valid")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::api_key_new_valid(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn api_key_new_cancel(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "api_key" / "new_cancel")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::api_key_new_cancel(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn verification_challenge_new(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "verification_challenge" / "new")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::verification_challenge_new(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn user_new(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "user" / "new")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::user_new(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_reset_new(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "password_reset" / "new")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::password_reset_new(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_new_reset(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "password" / "new_reset")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::password_new_reset(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_new_change(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "password" / "new_change")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::password_new_change(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_new_cancel(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "password" / "new_cancel")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::password_new_cancel(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn user_view(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "user" / "view")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::user_view(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_view(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "password" / "view")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::password_view(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn api_key_view(
  config: Config,
  db: Db,
  mail_service: MailService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("public" / "api_key" / "view")
    .and(with(config))
    .and(with(db))
    .and(with(mail_service))
    .and(warp::body::json())
    .and_then(async move |config, db, mail_service, props| {
      auth_handlers::api_key_view(config, db, mail_service, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

// This function receives a `Rejection` and tries to return a custom
// value, otherwise simply passes the rejection along.
async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
  let code;
  let message;

  if err.is_not_found() {
    code = StatusCode::NOT_FOUND;
    message = "NOT_FOUND";
  } else if err
    .find::<warp::filters::body::BodyDeserializeError>()
    .is_some()
  {
    message = "BAD_REQUEST";
    code = StatusCode::BAD_REQUEST;
  } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
    code = StatusCode::METHOD_NOT_ALLOWED;
    message = "METHOD_NOT_ALLOWED";
  } else if let Some(AuthErrorRejection(auth_error)) = err.find() {
    code = StatusCode::BAD_REQUEST;
    message = auth_error.as_ref();
  } else {
    // We should have expected this... Just log and say its a 500
    utils::log(utils::Event {
      msg: "unknown error kind".to_owned(),
      source: None,
      severity: utils::SeverityKind::Error,
    });
    code = StatusCode::INTERNAL_SERVER_ERROR;
    message = "UNKNOWN";
  }

  Ok(warp::reply::with_status(format!("\"{}\"", message), code))
}

// This type represents errors that we can generate
// These will be automatically converted to a proper string later
#[derive(Debug)]
pub struct AuthErrorRejection(pub AuthError);
impl warp::reject::Reject for AuthErrorRejection {}

fn auth_error(auth_error: AuthError) -> warp::reject::Rejection {
  warp::reject::custom(AuthErrorRejection(auth_error))
}
