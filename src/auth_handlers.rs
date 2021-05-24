use super::Db;
use auth_service_api::*;
use log_service_api::client::LogService;

use super::api_key_service;
use super::auth_db_types::*;
use super::password_reset_service;
use super::verification_challenge_service;
use super::password_service;
use super::user_service;
use super::utils;

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

pub async fn get_api_key_if_valid(
  con: &mut rusqlite::Connection,
  ls: LogService,
  api_key: &str,
) -> Result<ApiKey, AuthError> {
  let maybe_api_key = api_key_service::get_by_api_key_hash(con, &utils::hash_str(api_key));
  let creator_api_key = report_unk_err(&ls, maybe_api_key)
    .await?
    .ok_or(AuthError::API_KEY_NONEXISTENT)?;

  if utils::current_time_millis() > creator_api_key.creation_time + creator_api_key.duration {
    return Err(AuthError::API_KEY_UNAUTHORIZED);
  }

  Ok(creator_api_key)
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
  let con = &mut *db.lock().await;

  let creator_key = get_api_key_if_valid(con, ls, &props.api_key).await?;

  let to_cancel_key = get_api_key_if_valid(con, ls, &props.api_key_to_cancel).await?;

  if creator_key.creator_user_id != to_cancel_key.creator_user_id {
    return Err(AuthError::API_KEY_UNAUTHORIZED);
  }

  // cancel keys
  let maybe_key_cancel = api_key_service::add(
    con,
    creator_key.creator_user_id,
    to_cancel_key.api_key_hash,
    ApiKeyKind::CANCEL,
    0,
  );

  let key_cancel =report_unk_err(&ls, maybe_key_cancel).await?;

  // return json
  Ok(warp::reply::json(&key_cancel))
}

pub async fn verification_challenge_new(
  db: Db,
  ls: LogService,
  props: VerificationChallengeNewProps,
) -> Result<impl warp::Reply, AuthError> {
    if !utils::is_email(&props.user_email) {
        return Err(AuthError::USER_EMAIL_EMPTY);
    }

    if props.user_name.is_empty() {
        return Err(AuthError::USER_NAME_EMPTY);
    }

    if !utils::is_secure(&props.user_password) {
        return Err(AuthError::PASSWORD_INSECURE);
    }

    let con = &mut *db.lock().await;

    let maybe_last_email_sent_time = verification_challenge_service::get_last_email_sent_time(con, &props.user_email);
    let last_email_sent_time = report_unk_err(&ls, maybe_last_email_sent_time).await?;

    if last_email_sent_time.is_some() && last_email_sent_time.unwrap() + 15*1000*60 > utils::current_time_millis(): {
        return Err(AuthError::EMAIL_RATELIMIT);
    }

    let verification_challenge_key = utils::gen_random_string();

    verification_challenge_service::add(
        con,
        utils::hash_str(&verification_challenge_key),
        props.user_name,
        props.user_email,
        utils::hash_password(&props.user_password).

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
