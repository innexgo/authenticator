use super::auth_db_types::VerificationChallenge;
use super::utils::current_time_millis;
use rusqlite::{params, Connection, OptionalExtension};

fn add(
  con: &mut Connection,
  verification_challenge_key_hash: String,
  name: String,
  email: String,
  password_hash: String,
) -> Result<VerificationChallenge, rusqlite::Error> {
  let sql = "INSERT INTO verification_challenge values (?, ?, ?, ?, ?)";
  let creation_time = current_time_millis();
  con.execute(
    sql,
    params![
      verification_challenge_key_hash,
      creation_time,
      name,
      email,
      password_hash
    ],
  )?;

  Ok(VerificationChallenge {
    verification_challenge_key_hash,
    creation_time,
    name,
    email,
    password_hash,
  })
}

pub fn get_by_verification_challenge_key_hash(
  con: &mut Connection,
  verification_challenge_key_hash: &str,
) -> Result<Option<VerificationChallenge>, rusqlite::Error> {
  let sql = "SELECT * FROM verification_challenge WHERE verification_challenge_key_hash=?";
  con
    .query_row(sql, [verification_challenge_key_hash], |row| {
      Ok(VerificationChallenge {
        verification_challenge_key_hash: row.get(0).unwrap(),
        creation_time: row.get(1).unwrap(),
        name: row.get(2).unwrap(),
        email: row.get(3).unwrap(),
        password_hash: row.get(4).unwrap(),
      })
    })
    .optional()
}
