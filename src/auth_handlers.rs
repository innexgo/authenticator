use super::Db;
use auth_service_api::*;
use log_service_api::client::LogService;

use super::api_key_service;
use super::password_reset_service;
use super::password_service;
use super::user_service;

async fn report_unk_err<T, E: std::error::Error>(
  ls: &LogService,
  v: Result<T, E>,
) -> Result<T, AuthError> {
  match v {
    // handle rustqlite error
    Err(x) => {
      ls.error(&x.to_string()).await;
      Err(AuthError::UNKNOWN)
    }
    Ok(x) => Ok(x),
  }
}

pub async fn api_key_new_valid(
  db: Db,
  ls: LogService,
  props: ApiKeyNewValidProps,
) -> Result<impl warp::Reply, AuthError> {
  let connection = &mut *db.lock().await;

  let maybe_user = user_service::get_by_user_email(connection, &props.user_email);
  let user = report_unk_err(&ls, maybe_user)
    .await?
    .ok_or(AuthError::USER_NONEXISTENT)?;

  let maybe_password = password_service::get_by_password_id(connection, user.user_id);
  let password = report_unk_err(&ls, maybe_password)
    .await?
    .ok_or(AuthError::PASSWORD_NONEXISTENT)?;

  // validate password with bcrypt
  let bcryptresult = bcrypt::verify(&props.user_password, &password.password_hash);
  if report_unk_err(&ls, bcryptresult).await? {
    return Err(AuthError::PASSWORD_INCORRECT);
  }

  Ok(warp::reply::json(&user))
}

pub async fn api_key_new_cancel(
  db: Db,
  ls: LogService,
  props: ApiKeyNewCancelProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn verification_challenge_new(
  db: Db,
  ls: LogService,
  props: VerificationChallengeNewProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn user_new(
  db: Db,
  ls: LogService,
  props: UserNewProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn password_reset_new(
  db: Db,
  ls: LogService,
  props: PasswordResetNewProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn password_new_reset(
  db: Db,
  ls: LogService,
  props: PasswordNewResetProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn password_new_change(
  db: Db,
  ls: LogService,
  props: PasswordNewChangeProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn password_new_cancel(
  db: Db,
  ls: LogService,
  props: PasswordNewCancelProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn user_view(
  db: Db,
  ls: LogService,
  props: PasswordNewCancelProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn password_view(
  db: Db,
  ls: LogService,
  props: PasswordNewCancelProps,
) -> Result<impl warp::Reply, AuthError> {
}
pub async fn api_key_view(
  db: Db,
  ls: LogService,
  props: PasswordNewCancelProps,
) -> Result<impl warp::Reply, AuthError> {
}
