use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_time_millis() -> i64 {
  let since_the_epoch = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("time went backwards");

  since_the_epoch
    .as_millis()
    .try_into()
    .expect("time overflow")
}

pub fn hash_str(key: &str) -> String {
  let mut hasher = Sha256::new();
  hasher.update(key);
  let result = hasher.finalize();
  base64::encode(result)
}
