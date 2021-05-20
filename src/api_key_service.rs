use super::auth_db_types::*;
use super::utils::current_time_millis;
use rusqlite::{named_params, params, Connection, OptionalExtension};

// returns the max api_key id and adds 1 to it
fn next_id(con: &mut Connection) -> Result<i64, rusqlite::Error> {
  let sql = "SELECT max(api_key_id) FROM api_key";
  con.query_row(sql, [], |row| row.get(0))
}

pub fn add(con: &mut Connection, creator_user_id:i64, ) -> Result<ApiKey, rusqlite::Error> {
  let sp = con.savepoint()?;
  let api_key_id = next_id(&mut sp)?;
  let creation_time = current_time_millis();

  let sql = "INSERT INTO api_key values (?, ?, ?, ?, ?, ?)";
  sp.execute(
    sql,
    params![
      api_key_id,
      creation_time,
      &v.name,
      &v.email,
      &v.verification_challenge_key_hash
    ],
  )?;

  // commit savepoint
  sp.commit();

  // return api_key
  Ok(ApiKey {
    api_key_id,
    creation_time,
    name: v.name,
    email: v.email,
    verification_challenge_key_hash: v.verification_challenge_key_hash,
  })
}

pub fn get_by_api_key_id(con: &mut Connection, api_key_id: i64) -> Result<Option<ApiKey>, rusqlite::Error> {
  let sql = "SELECT * FROM api_key WHERE api_key_id=?";
  con
    .query_row(sql, params![api_key_id], |row| {
      Ok(ApiKey {
        api_key_id: row.get(0)?,
        creation_time: row.get(1)?,
        name: row.get(2)?,
        email: row.get(3)?,
        verification_challenge_key_hash: row.get(4)?,
      })
    })
    .optional()
}

pub fn exists_by_email(con: &mut Connection, email: &str) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM api_key WHERE email=?";
  let count: i64 = con.query_row(sql, params![email], |row| row.get(0))?;
  Ok(count != 0)
}

pub fn exists_by_api_key_id(con: &mut Connection, api_key_id: i64) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM api_key WHERE api_key_id=?";
  let count: i64 = con.query_row(sql, params![api_key_id], |row| row.get(0))?;
  Ok(count != 0)
}

pub fn exists_by_verification_challenge_key_hash(
  con: &mut Connection,
  verification_challenge_key_hash: &str,
) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM api_key WHERE verification_challenge_key_hash=?";
  let count: i64 = con.query_row(sql, params![verification_challenge_key_hash], |row| {
    row.get(0)
  })?;
  Ok(count != 0)
}

pub fn query(
  con: &mut Connection,
  api_key_id: Option<i64>,
  creation_time: Option<i64>,
  min_creation_time: Option<i64>,
  max_creation_time: Option<i64>,
  name: Option<&str>,
  email: Option<&str>,
  offset: u64,
  count: u64,
) -> Result<Vec<ApiKey>, rusqlite::Error> {
  let sql = [
    "SELECT u.* FROM api_key u WHERE 1 = 1",
    " AND (:api_key_id       == NULL OR u.api_key_id = :api_key_id)",
    " AND (:creation_time == NULL OR u.creation_time = :creation_time)",
    " AND (:creation_time == NULL OR u.creation_time > :min_creation_time)",
    " AND (:creation_time == NULL OR u.creation_time > :max_creation_time)",
    " AND (:name          == NULL OR u.name = :name)",
    " AND (:email         == NULL OR u.email = :email)",
    " ORDER BY u.api_key_id",
    " LIMIT :offset, :count",
  ]
  .join("");

  let stmnt = con.prepare(&sql)?;

  let results = stmnt
    .query(named_params! {
        "api_key_id": api_key_id,
        "creation_time": creation_time,
        "min_creation_time": min_creation_time,
        "max_creation_time": max_creation_time,
        "name": name,
        "email": email,
        "offset": offset,
        "count": offset,
    })?
    .and_then(|row| {
      Ok(ApiKey {
        api_key_id: row.get(0)?,
        creation_time: row.get(1)?,
        name: row.get(2)?,
        email: row.get(3)?,
        verification_challenge_key_hash: row.get(4)?,
      })
    })
    .filter_map(|x: Result<ApiKey, rusqlite::Error>| x.ok());
  Ok(results.collect::<Vec<ApiKey>>())
}
