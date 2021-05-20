use super::auth_db_types::*;
use super::utils::current_time_millis;
use rusqlite::{named_params, params, Connection, OptionalExtension};
use std::convert::{TryFrom, TryInto};

// returns the max password id and adds 1 to it
fn next_id(con: &mut Connection) -> Result<i64, rusqlite::Error> {
  let sql = "SELECT max(password_id) FROM password";
  con.query_row(sql, [], |row| row.get(0))
}


impl TryFrom<&rusqlite::Row<'_>> for Password {
  type Error = rusqlite::Error;

  // select * from password order only, otherwise it will fail
  fn try_from(row: &rusqlite::Row) -> Result<Password, rusqlite::Error> {
      Ok(Password {
        password_id: row.get(0)?,
        creation_time: row.get(1)?,
        creator_user_id: row.get(2)?,
      password_kind: row
        .get::<_, u8>(3)?
        .try_into()
        .map_err(|x| rusqlite::Error::IntegralValueOutOfRange(3, x))?,
        verification_challenge_key_hash: row.get(4)?,
      })
    }
}

pub fn add(con: &mut Connection, v: VerificationChallenge) -> Result<Password, rusqlite::Error> {
  let sp = con.savepoint()?;
  let password_id = next_id(&mut sp)?;
  let creation_time = current_time_millis();

  let sql = "INSERT INTO password values (?, ?, ?, ?, ?, ?, ?)";
  sp.execute(
    sql,
    params![
      password_id,
      creation_time,
      creator_user_id,
      user_id,
      password_kind as u8,
      &password_hash,
      &password_reset_key_hash,
    ],
  )?;

  // commit savepoint
  sp.commit();

  // return password
  Ok(Password {
    password_id,
    creation_time,
    name: v.name,
    email: v.email,
    verification_challenge_key_hash: v.verification_challenge_key_hash,
  })
}

pub fn get_by_password_id(con: &mut Connection, password_id: i64) -> Result<Option<Password>, rusqlite::Error> {
  let sql = "SELECT * FROM password WHERE password_id=?";
  con
    .query_row(sql, params![password_id], |row| row.try_into())
    .optional()
}

pub fn exists_by_email(con: &mut Connection, email: &str) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM password WHERE email=?";
  let count: i64 = con.query_row(sql, params![email], |row| row.get(0))?;
  Ok(count != 0)
}

pub fn exists_by_password_id(con: &mut Connection, password_id: i64) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM password WHERE password_id=?";
  let count: i64 = con.query_row(sql, params![password_id], |row| row.get(0))?;
  Ok(count != 0)
}

pub fn exists_by_verification_challenge_key_hash(
  con: &mut Connection,
  verification_challenge_key_hash: &str,
) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM password WHERE verification_challenge_key_hash=?";
  let count: i64 = con.query_row(sql, params![verification_challenge_key_hash], |row| {
    row.get(0)
  })?;
  Ok(count != 0)
}

pub fn query(
  con: &mut Connection,
  password_id: Option<i64>,
  creation_time: Option<i64>,
  min_creation_time: Option<i64>,
  max_creation_time: Option<i64>,
  name: Option<&str>,
  email: Option<&str>,
  offset: u64,
  count: u64,
) -> Result<Vec<Password>, rusqlite::Error> {
  let sql = [
    "SELECT u.* FROM password u WHERE 1 = 1",
    " AND (:password_id       == NULL OR u.password_id = :password_id)",
    " AND (:creation_time == NULL OR u.creation_time = :creation_time)",
    " AND (:creation_time == NULL OR u.creation_time > :min_creation_time)",
    " AND (:creation_time == NULL OR u.creation_time > :max_creation_time)",
    " AND (:name          == NULL OR u.name = :name)",
    " AND (:email         == NULL OR u.email = :email)",
    " ORDER BY u.password_id",
    " LIMIT :offset, :count",
  ]
  .join("");

  let stmnt = con.prepare(&sql)?;

  let results = stmnt
    .query(named_params! {
        "password_id": password_id,
        "creation_time": creation_time,
        "min_creation_time": min_creation_time,
        "max_creation_time": max_creation_time,
        "name": name,
        "email": email,
        "offset": offset,
        "count": offset,
    })?
    .and_then(|row| row.try_into())
    .filter_map(|x: Result<Password, rusqlite::Error>| x.ok());
  Ok(results.collect::<Vec<Password>>())
}
