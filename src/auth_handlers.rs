use super::Db;
use auth_service_api::request;
use auth_service_api::response;
use log_service_api::client::LogService;

use super::api_key_service;
use super::auth_db_types::*;
use super::password_reset_service;
use super::password_service;
use super::user_service;
use super::utils;
use super::verification_challenge_service;

static fifteen_minutes: u64 = 15 * 60 * 1000;

#[tokio::main]
async fn report_unk_err<E: std::error::Error>(ls: &LogService, e: E) -> response::AuthError {
  ls.error(&e.to_string()).await;
  response::AuthError::UNKNOWN
}

pub fn get_api_key_if_valid(
  con: &mut rusqlite::Connection,
  ls: &LogService,
  api_key: &str,
) -> Result<ApiKey, response::AuthError> {
  let creator_api_key = api_key_service::get_by_api_key_hash(con, &utils::hash_str(api_key))
    .map_err(|e| report_unk_err(ls, e))?
    .ok_or(response::AuthError::API_KEY_NONEXISTENT)?;

  if utils::current_time_millis() > creator_api_key.creation_time + creator_api_key.duration {
    return Err(response::AuthError::API_KEY_UNAUTHORIZED);
  }

  Ok(creator_api_key)
}

pub async fn api_key_new_valid(
  db: Db,
  ls: &LogService,
  props: request::ApiKeyNewValidProps,
) -> Result<ApiKey, response::AuthError> {
  let con = &mut *db.lock().await;

  let user = user_service::get_by_user_email(con, &props.user_email)
    .map_err(|e| report_unk_err(ls, e))?
    .ok_or(response::AuthError::USER_NONEXISTENT)?;

  let password = password_service::get_by_password_id(con, user.user_id)
    .map_err(|e| report_unk_err(ls, e))?
    .ok_or(response::AuthError::PASSWORD_NONEXISTENT)?;

  // validate password with bcrypt
  if !utils::verify_password(&props.user_password, &password.password_hash)
    .map_err(|e| report_unk_err(ls, e))?
  {
    return Err(response::AuthError::PASSWORD_INCORRECT);
  }

  let raw_api_key = utils::gen_random_string();

  // add new api key
  let api_key = api_key_service::add(
    con,
    user.user_id,
    utils::hash_str(&raw_api_key),
    request::ApiKeyKind::VALID,
    props.duration,
  )
  .map_err(|e| report_unk_err(ls, e))?;

  Ok(api_key)
}

pub async fn api_key_new_cancel(
  db: Db,
  ls: &LogService,
  props: request::ApiKeyNewCancelProps,
) -> Result<ApiKey, response::AuthError> {
  let con = &mut *db.lock().await;

  // validate api key
  let creator_key = get_api_key_if_valid(con, ls, &props.api_key)?;

  let to_cancel_key = get_api_key_if_valid(con, ls, &props.api_key_to_cancel)?;

  if creator_key.creator_user_id != to_cancel_key.creator_user_id {
    return Err(response::AuthError::API_KEY_UNAUTHORIZED);
  }

  // cancel keys
  let key_cancel = api_key_service::add(
    con,
    creator_key.creator_user_id,
    to_cancel_key.api_key_hash,
    request::ApiKeyKind::CANCEL,
    0,
  )
  .map_err(|e| report_unk_err(ls, e))?;

  // return json
  Ok(key_cancel)
}

pub async fn verification_challenge_new(
  db: Db,
  ls: &LogService,
  props: request::VerificationChallengeNewProps,
) -> Result<VerificationChallenge, response::AuthError> {
  // perform basic validation
  if props.user_email.is_empty() {
    return Err(response::AuthError::USER_EMAIL_EMPTY);
  }

  // make sure user name is typable
  if props.user_name.is_empty() {
    return Err(response::AuthError::USER_NAME_EMPTY);
  }

  // server side validation of password strength
  if !utils::is_secure_password(&props.user_password) {
    return Err(response::AuthError::PASSWORD_INSECURE);
  }

  let con = &mut *db.lock().await;

  // if user name is taken
  if user_service::exists_by_email(con, &props.user_email).map_err(|e| report_unk_err(ls, e))? {
    return Err(response::AuthError::USER_EXISTENT);
  }

  let last_email_sent_time =
    verification_challenge_service::get_last_email_sent_time(con, &props.user_email)
      .map_err(|e| report_unk_err(ls, e))?;

  if let Some(time) = last_email_sent_time {
    if time + fifteen_minutes as i64 > utils::current_time_millis() {
      return Err(response::AuthError::EMAIL_RATELIMIT);
    }
  }

  // generate random string
  let verification_challenge_key = utils::gen_random_string();

  let verification_challenge = verification_challenge_service::add(
    con,
    utils::hash_str(&verification_challenge_key),
    props.user_name,
    props.user_email,
    utils::hash_password(&props.user_password).map_err(|e| report_unk_err(ls, e))?,
  )
  .map_err(|e| report_unk_err(ls, e))?;

  // TODO sent email

  // return json
  Ok(verification_challenge)
}
pub async fn user_new(
  db: Db,
  ls: &LogService,
  props: request::UserNewProps,
) -> Result<User, response::AuthError> {
  let con = &mut *db.lock().await;

  let vckh = &utils::hash_str(&props.verification_challenge_key);

  // check that the verification challenge exists
  let vc = verification_challenge_service::get_by_verification_challenge_key_hash(con, vckh)
    .map_err(|e| report_unk_err(ls, e))?
    .ok_or(response::AuthError::VERIFICATION_CHALLENGE_NONEXISTENT)?;

  // check if the verification challenge was not already used
  // and that the email isn't already in use by another user
  if user_service::exists_by_verification_challenge_key_hash(con, vckh)
    .map_err(|e| report_unk_err(ls, e))?
    || user_service::exists_by_email(con, &vc.email).map_err(|e| report_unk_err(ls, e))?
  {
    return Err(response::AuthError::USER_EXISTENT);
  }

  let now = utils::current_time_millis();

  if fifteen_minutes as i64 + vc.creation_time < now {
    return Err(response::AuthError::VERIFICATION_CHALLENGE_TIMED_OUT);
  }

  let mut transaction = con.savepoint().map_err(|e| report_unk_err(ls, e))?;

  let vc_password_hash = vc.password_hash.clone();

  // create user
  let user = user_service::add(&transaction, vc).map_err(|e| report_unk_err(ls, e))?;

  // create password
  let p = password_service::add(
    &mut transaction,
    user.user_id,
    user.user_id,
    request::PasswordKind::CHANGE,
    vc_password_hash,
    String::new(),
  );

  transaction.commit();

  Ok(user)
}
pub async fn password_reset_new(
  db: Db,
  ls: &LogService,
  props: request::PasswordResetNewProps,
) -> Result<PasswordReset, response::AuthError> {
  let con = &mut *db.lock().await;

  let user = user_service::get_by_user_email(con, &props.user_email)
    .map_err(|e| report_unk_err(ls, e))?
    .ok_or(response::AuthError::USER_NONEXISTENT)?;

  let raw_key = utils::gen_random_string();

  let password_reset = password_reset_service::add(con, utils::hash_str(&raw_key), user.user_id)
    .map_err(|e| report_unk_err(ls, e))?;

  // TODO send email

  Ok(password_reset)
}

pub async fn password_new_reset(
  db: Db,
  ls: &LogService,
  props: request::PasswordNewResetProps,
) -> Result<Password, response::AuthError> {
  // no api key verification needed

  let con = &mut *db.lock().await;

  // get password reset
  let psr = password_reset_service::get_by_password_reset_key_hash(
    con,
    &utils::hash_str(&props.password_reset_key),
  )
  .map_err(|e| report_unk_err(ls, e))?
  .ok_or(response::AuthError::PASSWORD_RESET_NONEXISTENT)?;

  // deny if we alread created a password from this reset
  if password_service::exists_by_password_reset_key_hash(con, &psr.password_reset_key_hash)
    .map_err(|e| report_unk_err(ls, e))?
  {
    return Err(response::AuthError::PASSWORD_EXISTENT);
  }

  // deny if timed out
  if fifteen_minutes as i64 + psr.creation_time < utils::current_time_millis() {
    return Err(response::AuthError::PASSWORD_RESET_TIMED_OUT);
  }

  // reject insecure passwords
  if !utils::is_secure_password(&props.new_password) {
    return Err(response::AuthError::PASSWORD_INSECURE);
  }

  // attempt to hash password
  let new_password_hash =
    utils::hash_password(&props.new_password).map_err(|e| report_unk_err(ls, e))?;

  // create password
  let password = password_service::add(
    con,
    psr.creator_user_id,
    psr.creator_user_id,
    request::PasswordKind::RESET,
    new_password_hash,
    psr.password_reset_key_hash,
  )
  .map_err(|e| report_unk_err(ls, e))?;

  Ok(password)
}

pub async fn password_new_change(
  db: Db,
  ls: &LogService,
  props: request::PasswordNewChangeProps,
) -> Result<Password, response::AuthError> {
  let con = &mut *db.lock().await;

  // api key verification required
  let creator_key = get_api_key_if_valid(con, ls, &props.api_key)?;

  // reject insecure passwords
  if !utils::is_secure_password(&props.new_password) {
    return Err(response::AuthError::PASSWORD_INSECURE);
  }

  // attempt to hash password
  let new_password_hash =
    utils::hash_password(&props.new_password).map_err(|e| report_unk_err(ls, e))?;

  // create password
  let password = password_service::add(
    con,
    creator_key.creator_user_id,
    creator_key.creator_user_id,
    request::PasswordKind::CHANGE,
    new_password_hash,
    String::new(),
  )
  .map_err(|e| report_unk_err(ls, e))?;

  Ok(password)
}
pub async fn password_new_cancel(
  db: Db,
  ls: &LogService,
  props: request::PasswordNewCancelProps,
) -> Result<impl warp::Reply, response::AuthError> {
}

pub async fn user_view(
  db: Db,
  ls: &LogService,
  props: request::PasswordNewCancelProps,
) -> Result<impl warp::Reply, response::AuthError> {
}
pub async fn password_view(
  db: Db,
  ls: &LogService,
  props: request::PasswordNewCancelProps,
) -> Result<impl warp::Reply, response::AuthError> {
}
pub async fn api_key_view(
  db: Db,
  ls: &LogService,
  props: request::PasswordNewCancelProps,
) -> Result<impl warp::Reply, response::AuthError> {
}
