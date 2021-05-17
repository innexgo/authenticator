use serde::{Deserialize, Serialize};
use auth_service_api::PasswordKind;
use auth_service_api::ApiKeyKind;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationChallenge {
  verification_challenge_key_hash: String,
  creation_time: u64,
  name: String,
  email: String,
  password_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
  user_id: u64,
  creation_time: u64,
  name: String,
  email: String,
  verification_challenge_key_hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasswordReset {
  password_reset_key_hash: String,
  creation_time: u64,
  creator_user_id: u64,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Password {
  password_id: u64,
  creation_time: u64,
  creator_user_id: u64,
  user_id: u64,
  password_kind: PasswordKind,
  password_hash: String,
  password_reset_key_hash: String,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiKey {
  api_key_id: u64,
  creator_user_id: u64,
  api_key_hash: String,
  api_key_kind: ApiKeyKind,
  duration: u64,
}
