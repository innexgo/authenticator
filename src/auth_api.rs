use super::auth_handlers;
use super::log_service::LogService;
use super::Db;
use super::SERVICE_NAME;
use std::collections::HashMap;
use std::convert::Infallible;
use warp::Filter;
use warp::http::StatusCode;

/// The function that will show all ones to call
pub fn api(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = Infallible> + Clone {
  api_info()
    .or(verification_challenge_new(db.clone(), ls.clone()))
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
fn with_T<T: Clone + Send>(
  t: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
  warp::any().map(move || t.clone())
}

 fn api_key_new_valid(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("api_key/new_valid")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::api_key_new_valid(db, ls, props))
}

 fn api_key_new_cancel(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("api_key/new_cancel")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::api_key_new_cancel(db, ls, props))
}

 fn verification_challenge_new(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("verification_challenge/new")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::verification_challenge_new(db, ls, props))
}

 fn user_new(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("user/new")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::user_new(db, ls, props))
}

 fn password_reset_new(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password_reset/new")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::password_reset_new(db, ls, props))
}

 fn password_new_reset(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password/new_reset")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::password_new_reset(db, ls, props))
}

 fn password_new_change(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password/new_change")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::password_new_change(db, ls, props))
}

 fn password_new_cancel(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password/new_cancel")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::password_new_cancel(db, ls, props))
}

 fn user_view(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("user/view")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::user_view(db, ls, props))
}

 fn password_view(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("password/view")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::password_view(db, ls, props))
}

 fn api_key_view(
  db: Db,
  ls: LogService,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
  warp::path!("api_key/view")
    .and(with_T((db, ls)))
    .and(warp::body::json())
    .and_then(|(db, ls), props| auth_handlers::api_key_view(db, ls, props))
}


// This function receives a `Rejection` and tries to return a custom
// value, otherwise simply passes the rejection along.
async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND";
    } else if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        message = "BAD_REQUEST";
        code = StatusCode::BAD_REQUEST;
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD_NOT_ALLOWED";
    } else if let Some(auth_handlers::AuthErrorRejection(auth_error)) = err.find() {
        code = StatusCode::BAD_REQUEST;
        message = auth_error.as_ref();
    } else {
        // We should have expected this... Just log and say its a 500
        eprintln!("unhandled rejection: {:?}", err);
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "UNKNOWN";
    }

    Ok(warp::reply::with_status(format!("\"{}\"", message), code))
}
