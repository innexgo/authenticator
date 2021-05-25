use super::auth_db_types::*;
use super::utils::current_time_millis;
use rusqlite::{named_params, params, Connection, OptionalExtension};
use std::convert::{TryFrom, TryInto};

// returns the max password id and adds 1 to it
fn next_id(con: &Connection) -> Result<i64, rusqlite::Error> {
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
      user_id: row.get(3)?,
      password_kind: row
        .get::<_, u8>(4)?
        .try_into()
        .map_err(|x| rusqlite::Error::IntegralValueOutOfRange(4, x as i64))?,
      password_hash: row.get(5)?,
      password_reset_key_hash: row.get(6)?,
    })
  }
}

pub fn add(
  con: &Connection,
  creator_user_id: i64,
  user_id: i64,
  password_kind: auth_service_api::request::PasswordKind,
  password_hash: String,
  password_reset_key_hash: String,
) -> Result<Password, rusqlite::Error> {
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
    creator_user_id,
    user_id,
    password_kind,
    password_hash,
    password_reset_key_hash,
  })
}

pub fn get_by_password_id(
  con: &Connection,
  password_id: i64,
) -> Result<Option<Password>, rusqlite::Error> {
  let sql = "SELECT * FROM password WHERE user_id=? ORDER BY password_id DESC LIMIT 1";
  con
    .query_row(sql, params![password_id], |row| row.try_into())
    .optional()
}

pub fn get_by_user_id(
  con: &Connection,
  user_id: i64,
) -> Result<Option<Password>, rusqlite::Error> {
  let sql = "SELECT * FROM password WHERE user_id=?";
  con
    .query_row(sql, params![user_id], |row| row.try_into())
    .optional()
}

pub fn exists_by_password_id(
  con: &Connection,
  password_id: i64,
) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM password WHERE password_id=?";
  let count: i64 = con.query_row(sql, params![password_id], |row| row.get(0))?;
  Ok(count != 0)
}

pub fn exists_by_password_reset_key_hash(
  con: &Connection,
  password_reset_key_hash: &str,
) -> Result<bool, rusqlite::Error> {
  let sql = "SELECT count(*) FROM password WHERE password_reset_key_hash=?";
  let count: i64 = con.query_row(sql, params![password_reset_key_hash], |row| row.get(0))?;
  Ok(count != 0)
}

pub fn query(
  con: &Connection,
  props: auth_service_api::request::PasswordViewProps,
) -> Result<Vec<Password>, rusqlite::Error> {
  let sql = [

    "SELECT a.* FROM api_key a",
    if props.only_recent {
        " INNER JOIN (SELECT max(api_key_id) id FROM api_key GROUP BY api_key_hash) maxids ON maxids.id = a.api_key_id"
    } else {
        ""
    },
    " AND (:password_id     == NULL OR p.password_id = :password_id)",
    " AND (:creation_time   == NULL OR p.creation_time = :creation_time)",
    " AND (:creation_time   == NULL OR p.creation_time > :min_creation_time)",
    " AND (:creation_time   == NULL OR p.creation_time > :max_creation_time)",
    " AND (:creator_user_id == NULL OR p.creator_user_id = :creator_user_id)",
    " AND (:user_id         == NULL OR p.user_id = :user_id)",
    " AND (:password_kind   == NULL OR p.password_kind = :password_kind)",
    " ORDER BY u.password_id",
    " LIMIT :offset, :count",
  ]
  .join("");

  let stmnt = con.prepare(&sql)?;

  let results = stmnt
    .query(named_params! {
        "password_id": props.password_id,
        "creation_time": props.creation_time,
        "min_creation_time": props.min_creation_time,
        "max_creation_time": props.max_creation_time,
        "creator_user_id": props.creator_user_id,
        "user_id": props.user_id,
        "password_kind": props.password_kind.map(|x| x as u8),
        "offset": props.offset,
        "count": props.offset,
    })?
    .and_then(|row| row.try_into())
    .filter_map(|x: Result<Password, rusqlite::Error>| x.ok());
  Ok(results.collect::<Vec<Password>>())
}
