use super::Db;
use auth_service_api::*;
use std::convert::Infallible;
use log_service_api::client::LogService;

// This type represents errors that we can generate
// These will be automatically converted to a proper string later
#[derive(Debug)]
pub struct AuthErrorRejection(pub AuthError);
impl warp::reject::Reject for AuthErrorRejection{}

fn auth_error(auth_error:AuthError) -> warp::reject::Rejection {
  warp::reject::custom(AuthErrorRejection(AuthError::API_KEY_UNAUTHORIZED))
}

pub async fn api_key_new_valid(
  db: Db,
  ls: LogService,
  props: ApiKeyNewValidProps,
) -> Result<impl warp::Reply, warp::reject::Rejection> {

}


pub async fn api_key_new_cancel(
  db: Db,
  ls: LogService,
  props: ApiKeyNewCancelProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn verification_challenge_new(
  db: Db,
  ls: LogService,
  props: VerificationChallengeNewProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn user_new(
  db: Db,
  ls: LogService,
  props: UserNewProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn password_reset_new(
  db: Db,
  ls: LogService,
  props: PasswordResetNewProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn password_new_reset(
  db: Db,
  ls: LogService,
  props: PasswordNewResetProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn password_new_change(
  db: Db,
  ls: LogService,
  props: PasswordNewChangeProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn password_new_cancel(
  db: Db,
  ls: LogService,
  props: PasswordNewCancelProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn user_view(
  db: Db,
  ls: LogService,
  props: PasswordNewCancelProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn password_view(
  db: Db,
  ls: LogService,
  props: PasswordNewCancelProps,
) -> Result<impl warp::Reply, Infallible> {
}
pub async fn api_key_view(
  db: Db,
  ls: LogService,
  props: PasswordNewCancelProps,
) -> Result<impl warp::Reply, Infallible> {
}
