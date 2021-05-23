use auth_service_api::ApiKeyKind;
use auth_service_api::PasswordKind;

#[derive(Clone, Debug)]
pub struct VerificationChallenge {
  pub verification_challenge_key_hash: String,
  pub creation_time: i64,
  pub name: String,
  pub email: String,
  pub password_hash: String,
}

#[derive(Clone, Debug)]
pub struct User {
  pub user_id: i64,
  pub creation_time: i64,
  pub name: String,
  pub email: String,
  pub verification_challenge_key_hash: String,
}

#[derive(Clone, Debug)]
pub struct PasswordReset {
  pub password_reset_key_hash: String,
  pub creation_time: i64,
  pub creator_user_id: i64,
}

#[derive(Clone, Debug)]
pub struct Password {
  pub password_id: i64,
  pub creation_time: i64,
  pub creator_user_id: i64,
  pub user_id: i64,
  pub password_kind: PasswordKind,
  pub password_hash: String,
  pub password_reset_key_hash: String,
}

#[derive(Clone, Debug)]
pub struct ApiKey {
  pub api_key_id: i64,
  pub creation_time: i64,
  pub creator_user_id: i64,
  pub api_key_hash: String,
  pub api_key_kind: ApiKeyKind,
  pub duration: i64,
}
