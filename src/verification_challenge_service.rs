use super::auth_db_types::VerificationChallenge;
use super::utils::current_time_millis;
use rusqlite::{params, Connection, OptionalExtension};
use std::convert::{TryFrom, TryInto};

impl TryFrom<&rusqlite::Row<'_>> for VerificationChallenge {
  type Error = rusqlite::Error;

  // select * from user order only, otherwise it will fail
  fn try_from(row: &rusqlite::Row) -> Result<VerificationChallenge, rusqlite::Error> {
    Ok(VerificationChallenge {
      verification_challenge_key_hash: row.get(0)?,
      creation_time: row.get(1)?,
      name: row.get(2)?,
      email: row.get(3)?,
      password_hash: row.get(4)?,
    })
  }
}

pub fn add(
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
    .query_row(sql, [verification_challenge_key_hash], |row| row.try_into())
    .optional()
}

pub fn get_last_email_sent_time(
  con: &mut Connection,
  email: &str,
) -> Result<Option<i64>, rusqlite::Error> {
  let sql = "SELECT * FROM verification_challenge WHERE email=? ORDER BY creation_time LIMIT 1";
  con
    .query_row(sql, [email], |row| row.try_into())
    .optional()
    .map(|vco| vco.map(|vc: VerificationChallenge| vc.creation_time))
}
