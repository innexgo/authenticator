use super::auth_db_types::*;
use super::utils::current_time_millis;
use rusqlite::{named_params, params, Connection, Savepoint, OptionalExtension};
use std::convert::{TryFrom, TryInto};

// returns the max user id and adds 1 to it
fn next_id(con: &Connection) -> Result<i64, rusqlite::Error> {
  let sql = "SELECT max(user_id) FROM user";
  con.query_row(sql, [], |row| row.get(0))
}


impl TryFrom<&rusqlite::Row<'_>> for User {
  type Error = rusqlite::Error;

  // select * from user order only, otherwise it will fail
  fn try_from(row: &rusqlite::Row) -> Result<User, rusqlite::Error> {
      Ok(User {
        user_id: row.get(0)?,
        creation_time: row.get(1)?,
        name: row.get(2)?,
        email: row.get(3)?,
        verification_challenge_key_hash: row.get(4)?,
      })
    }
}

pub fn add(con: &mut Savepoint, v: VerificationChallenge) -> Result<User, rusqlite::Error> {
  let sp = con.savepoint()?;
  let user_id = next_id(&sp)?;
  let creation_time = current_time_millis();

  let sql = "INSERT INTO user values (?, ?, ?, ?, ?)";
  sp.execute(
    sql,
    params![
      user_id,
      creation_time,
      &v.name,
      &v.email,
      &v.verification_challenge_key_hash
    ],
  )?;

  // commit savepoint
  sp.commit()?;

  // return user
  Ok(User {
    user_id,
    creation_time,
    name: v.name,
    email: v.email,
    verification_challenge_key_hash: v.verification_challenge_key_hash,
  })
}

pub fn get_by_user_id(con: &Connection, user_id: i64) -> Result<Option<User>, rusqlite::Error> {
  let sql = "SELECT * FROM user WHERE user_id=?";
  con
    .query_row(sql, params![user_id], |row| row.try_into())
    .optional()
}

pub fn get_by_user_email(con: &Connection, user_email: &str) -> Result<Option<User>, rusqlite::Error> {
  let sql = "SELECT * FROM user WHERE email=?";
  con
    .query_row(sql, params![user_email], |row| row.try_into())
    .optional()
}


pub fn exists_by_email(con: &Connection, email: &str) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM user WHERE email=?";
  let count: i64 = con.query_row(sql, params![email], |row| row.get(0))?;
  Ok(count != 0)
}

pub fn exists_by_user_id(con: &Connection, user_id: i64) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM user WHERE user_id=?";
  let count: i64 = con.query_row(sql, params![user_id], |row| row.get(0))?;
  Ok(count != 0)
}

pub fn exists_by_verification_challenge_key_hash(
  con: &Connection,
  verification_challenge_key_hash: &str,
) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM user WHERE verification_challenge_key_hash=?";
  let count: i64 = con.query_row(sql, params![verification_challenge_key_hash], |row| {
    row.get(0)
  })?;
  Ok(count != 0)
}

pub fn query(
  con: &Connection,
  props: auth_service_api::request::UserViewProps
) -> Result<Vec<User>, rusqlite::Error> {
  let sql = [
    "SELECT u.* FROM user u WHERE 1 = 1",
    " AND (:user_id       == NULL OR u.user_id = :user_id)",
    " AND (:creation_time == NULL OR u.creation_time = :creation_time)",
    " AND (:creation_time == NULL OR u.creation_time > :min_creation_time)",
    " AND (:creation_time == NULL OR u.creation_time > :max_creation_time)",
    " AND (:name          == NULL OR u.name = :name)",
    " AND (:email         == NULL OR u.email = :email)",
    " ORDER BY u.user_id",
    " LIMIT :offset, :count",
  ]
  .join("");

  let mut stmnt = con.prepare(&sql)?;

  let results = stmnt
    .query(named_params! {
        "user_id": props.user_id,
        "creation_time": props.creation_time,
        "min_creation_time": props.min_creation_time,
        "max_creation_time": props.max_creation_time,
        "name": props.user_name,
        "email": props.user_email,
        "offset": props.offset,
        "count": props.offset,
    })?
    .and_then(|row| row.try_into())
    .filter_map(|x: Result<User, rusqlite::Error>| x.ok());
  Ok(results.collect::<Vec<User>>())
}
