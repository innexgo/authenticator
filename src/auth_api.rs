use super::auth_handlers;
use super::Db;
use super::SERVICE_NAME;
use auth_service_api::response::AuthError;
use log_service_api::client::LogService;
use std::collections::HashMap;
use std::convert::Infallible;
use warp::http::StatusCode;
use warp::Filter;

/// The function that will show all ones to call
pub fn api(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = Infallible> + Clone {
  api_info()
    .or(verification_challenge_new(db.clone(), ls.clone()))
    .or(api_key_new_valid(db.clone(), ls.clone()))
    .or(api_key_new_cancel(db.clone(), ls.clone()))
    .or(user_new(db.clone(), ls.clone()))
    .or(password_reset_new(db.clone(), ls.clone()))
    .or(password_new_reset(db.clone(), ls.clone()))
    .or(password_new_change(db.clone(), ls.clone()))
    .or(password_new_cancel(db.clone(), ls.clone()))
    .or(user_view(db.clone(), ls.clone()))
    .or(password_view(db.clone(), ls.clone()))
    .or(api_key_view(db.clone(), ls.clone()))
    .recover(handle_rejection)
}

fn api_info() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  let mut info = HashMap::new();
  info.insert("version", "0.1");
  info.insert("name", SERVICE_NAME);
  warp::path!("").map(move || warp::reply::json(&info))
}

// lets you pass in an arbitrary parameter
fn with<T: Clone + Send>(t: T) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
  warp::any().map(move || t.clone())
}

fn api_key_new_valid(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("api_key/new_valid")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::api_key_new_valid(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn api_key_new_cancel(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("api_key/new_cancel")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::api_key_new_cancel(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn verification_challenge_new(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("verification_challenge/new")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::verification_challenge_new(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn user_new(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("user/new")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::user_new(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_reset_new(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password_reset/new")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::password_reset_new(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_new_reset(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password/new_reset")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::password_new_reset(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_new_change(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password/new_change")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::password_new_change(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_new_cancel(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password/new_cancel")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::password_new_cancel(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn user_view(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("user/view")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::user_view(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn password_view(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password/view")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::password_view(db, &ls, props)
        .await
        .map_err(auth_error)
    })
    .map(|x| warp::reply::json(&x))
}

fn api_key_view(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("api_key/view")
    .and(with(db))
    .and(with(ls))
    .and(warp::body::json())
    .and_then(async move |db, ls, props| {
      auth_handlers::api_key_view(db, &ls, props)
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
  } else if err.find::<warp::filters::body::BodyDeserializeError>().is_some() {
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
    // TODO
    eprintln!("unhandled rejection: {:?}", err);
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
