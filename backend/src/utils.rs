use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
pub fn current_time_millis() -> i64 {
  let since_the_epoch = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("time went backwards");

  since_the_epoch.as_millis() as i64
}

pub fn gen_random_string() -> String {
  // encode 32 bytes of random in base64
  base64_url::encode(&thread_rng().gen::<[u8; 32]>())
}

pub fn hash_str(key: &str) -> String {
  let mut hasher = Sha256::new();
  hasher.update(key);
  let result = hasher.finalize();
  base64_url::encode(&result)
}

pub fn is_secure_password(password: &str) -> bool {
  let len = password.len();

  let numdigits = password.matches(char::is_numeric).count();

  len >= 8 && numdigits > 0
}

pub fn is_username_valid(username: &str) -> bool {
  // length must be 0..=20
  if username.len() == 0 || username.len() > 20 {
    return false;
  }

  if !username
    .chars()
    .all(|x| char::is_ascii_lowercase(&x) || char::is_ascii_digit(&x))
  {
    return false;
  }

  return true;
}

pub fn is_realname_valid(realname: &str) -> bool {
  return !realname.is_empty();
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, argon2::Error> {
  argon2::verify_encoded(password_hash, password.as_bytes())
}

pub fn hash_password(password: &str) -> Result<String, argon2::Error> {
  argon2::hash_encoded(
    // password
    password.as_bytes(),
    // salt
    &thread_rng().gen::<[u8; 32]>(),
    //config
    &argon2::Config::default(),
  )
}
