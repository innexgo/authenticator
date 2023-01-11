use super::handlers;
use super::utils;
use super::Config;
use super::Db;
use auth_service_api::response::AuthError;
use mail_service_api::client::MailService;
use std::convert::Infallible;
use std::future::Future;
use warp::http::StatusCode;
use warp::Filter;

/// Helper to combine the multiple filters together with Filter::or, possibly boxing the types in
/// the process. This greatly helps the build times for `ipfs-http`.
/// https://github.com/seanmonstar/warp/issues/507#issuecomment-615974062
macro_rules! combine {
  ($x:expr, $($y:expr),+) => {{
      let filter = ($x).boxed();
      $( let filter = (filter.or($y)).boxed(); )+
      filter
  }}
}

/// The function that will show all ones to call
pub fn api(
    config: Config,
    db: Db,
    mail_service: MailService,
) -> impl Filter<Extract = (impl warp::Reply,), Error = Infallible> + Clone {
    // public API
    api_info(config.clone())
        .or(combine!(
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "verification_challenge" / "new"),
                handlers::verification_challenge_new,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "api_key" / "new_with_email"),
                handlers::api_key_new_with_email,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "api_key" / "new_with_username"),
                handlers::api_key_new_with_username,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "api_key" / "new_cancel"),
                handlers::api_key_new_cancel,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "user" / "new"),
                handlers::user_new,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "user_data" / "new"),
                handlers::user_data_new,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "email" / "new"),
                handlers::email_new,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "password_reset" / "new"),
                handlers::password_reset_new,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "password" / "new_reset"),
                handlers::password_new_reset,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "password" / "new_change"),
                handlers::password_new_change,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "user" / "view"),
                handlers::user_view,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "user_data" / "view"),
                handlers::user_data_view,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "password" / "view"),
                handlers::password_view,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "email" / "view"),
                handlers::email_view,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("public" / "api_key" / "view"),
                handlers::api_key_view,
            ),
            // Private API (note that there's no "public" at the beginning, so nginx won't expose it)
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("get_user_by_id"),
                handlers::get_user_by_id,
            ),
            adapter(
                config.clone(),
                db.clone(),
                mail_service.clone(),
                warp::path!("get_user_by_api_key_if_valid"),
                handlers::get_user_by_api_key_if_valid,
            )
        ))
        .recover(handle_rejection)
}

fn api_info(
    config: Config,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone {
    let info = auth_service_api::response::Info {
        service: String::from(crate::SERVICE_NAME),
        version_major: crate::VERSION_MAJOR,
        version_minor: crate::VERSION_MINOR,
        version_rev: crate::VERSION_REV,
        site_external_url: config.site_external_url,
    };
    warp::path!("public" / "info").map(move || warp::reply::json(&info))
}

// this function adapts a handler function to a warp filter
// it accepts an initial path filter
fn adapter<PropsType, ResponseType, F>(
    config: Config,
    db: Db,
    mail_service: MailService,
    filter: impl Filter<Extract = (), Error = warp::Rejection> + Clone,
    handler: fn(Config, Db, MailService, PropsType) -> F,
) -> impl Filter<Extract = (impl warp::Reply,), Error = warp::Rejection> + Clone
where
    F: Future<Output = Result<ResponseType, AuthError>> + Send,
    PropsType: Send + serde::de::DeserializeOwned,
    ResponseType: Send + serde::ser::Serialize,
{
    // lets you pass in an arbitrary parameter
    fn with<T: Clone + Send>(t: T) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
        warp::any().map(move || t.clone())
    }

    filter
        .and(with(config))
        .and(with(db))
        .and(with(mail_service))
        .and(warp::body::json())
        .and_then(move |config, db, mail_service, props| async move {
            handler(config, db, mail_service, props)
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
        message = AuthError::NotFound;
    } else if err
        .find::<warp::filters::body::BodyDeserializeError>()
        .is_some()
    {
        message = AuthError::DecodeError;
        code = StatusCode::BAD_REQUEST;
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = AuthError::MethodNotAllowed;
    } else if let Some(AuthErrorRejection(auth_error)) = err.find() {
        code = StatusCode::BAD_REQUEST;
        message = auth_error.clone();
    } else {
        // We should have expected this... Just log and say its a 500
        utils::log(utils::Event {
            msg: "intercepted unknown error kind".to_owned(),
            source: None,
            severity: utils::SeverityKind::Error,
        });
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = AuthError::Unknown;
    }

    Ok(warp::reply::with_status(warp::reply::json(&message), code))
}

// This type represents errors that we can generate
// These will be automatically converted to a proper string later
#[derive(Debug)]
pub struct AuthErrorRejection(pub AuthError);
impl warp::reject::Reject for AuthErrorRejection {}

fn auth_error(auth_error: AuthError) -> warp::reject::Rejection {
    warp::reject::custom(AuthErrorRejection(auth_error))
}
