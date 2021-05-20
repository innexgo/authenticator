use super::auth_db_types::*;
use super::utils::current_time_millis;
use rusqlite::{named_params, params, Connection, OptionalExtension};
use std::convert::{TryFrom, TryInto};

// returns the max api_key id and adds 1 to it
fn next_id(con: &mut Connection) -> Result<i64, rusqlite::Error> {
  let sql = "SELECT max(api_key_id) FROM api_key";
  con.query_row(sql, [], |row| row.get(0))
}

impl TryFrom<&rusqlite::Row<'_>> for ApiKey {
  type Error = rusqlite::Error;

  // select * from api_key order only, otherwise it will fail
  fn try_from(row: &rusqlite::Row) -> Result<ApiKey, rusqlite::Error> {
    Ok(ApiKey {
      api_key_id: row.get(0)?,
      creation_time: row.get(1)?,
      creator_user_id: row.get(2)?,
      api_key_hash: row.get(3)?,
      // means that there's a mismatch between the values of the enum and the value stored in the column
      api_key_kind: row
        .get::<_, u8>(4)?
        .try_into()
        .map_err(|x| rusqlite::Error::IntegralValueOutOfRange(4, x))?,
      duration: row.get(5)?,
    })
  }
}

pub fn add(
  con: &mut Connection,
  creator_user_id: i64,
  api_key_hash: String,
  api_key_kind: auth_service_api::ApiKeyKind,
  duration: i64,
) -> Result<ApiKey, rusqlite::Error> {
  let sp = con.savepoint()?;
  let api_key_id = next_id(&mut sp)?;
  let creation_time = current_time_millis();

  let sql = "INSERT INTO api_key values (:api_key_id, :creation_time, :creator_user_id, :api_key_hash, :api_key_kind, :duration)";
  sp.execute(
    sql,
    named_params! {
      "api_key_id":api_key_id,
      "creation_time":creation_time,
      "creator_user_id":creator_user_id,
      "api_key_hash":api_key_hash,
      "api_key_kind":api_key_kind as u8,
      "duration":duration,
    },
  )?;

  // commit savepoint
  sp.commit();

  // return api_key
  Ok(ApiKey {
    api_key_id,
    creation_time,
    creator_user_id,
    api_key_hash,
    api_key_kind,
    duration,
  })
}

pub fn get_by_api_key_id(
  con: &mut Connection,
  api_key_id: i64,
) -> Result<Option<ApiKey>, rusqlite::Error> {
  let sql = "SELECT * FROM api_key WHERE api_key_id=?";
  con
    .query_row(sql, params![api_key_id], |row| row.try_into())
    .optional()
}

pub fn get_by_api_key_hash(
  con: &mut Connection,
  api_key_hash: String,
) -> Result<Option<ApiKey>, rusqlite::Error> {
  let sql = "SELECT * FROM api_key WHERE api_key_hash=? ORDER BY api_key_id DESC LIMIT 1";
  con
    .query_row(sql, params![api_key_hash], |row| row.try_into())
    .optional()
}

pub fn query(
  con: &mut Connection,
  api_key_id: Option<i64>,
  creator_user_id: Option<i64>,
  creation_time: Option<i64>,
  min_creation_time: Option<i64>,
  max_creation_time: Option<i64>,
  duration: Option<i64>,
  min_duration: Option<i64>,
  max_duration: Option<i64>,
  api_key_kind: Option<auth_service_api::ApiKeyKind>,
  only_recent: bool,
  offset: u64,
  count: u64,
) -> Result<Vec<ApiKey>, rusqlite::Error> {
  // TODO prevent getting meaningless duration

  let sql = [
    "SELECT a.* FROM api_key a",
    if only_recent {
        " INNER JOIN (SELECT max(api_key_id) id FROM api_key GROUP BY api_key_hash) maxids ON maxids.id = a.api_key_id"
    } else {
        ""
    },
    " WHERE 1 = 1",
    " AND (:api_key_id      == NULL OR u.api_key_id = :api_key_id)",
    " AND (:creator_user_id == NULL OR u.creator_user_id = :creator_user_id)",
    " AND (:creation_time   == NULL OR u.creation_time = :creation_time)",
    " AND (:creation_time   == NULL OR u.creation_time > :min_creation_time)",
    " AND (:creation_time   == NULL OR u.creation_time > :max_creation_time)",
    " AND (:duration        == NULL OR u.duration = :duration)",
    " AND (:duration        == NULL OR u.duration > :min_duration)",
    " AND (:duration        == NULL OR u.duration > :max_duration)",
    " AND (:api_key_kind    == NULL OR u.api_key_kind = :api_key_kind)",
    " ORDER BY u.api_key_id",
    " LIMIT :offset, :count",
  ]
  .join("");

  let stmnt = con.prepare(&sql)?;

  let results = stmnt
    .query(named_params! {
        "api_key_id": api_key_id,
        "creator_user_id": creator_user_id,
        "creation_time": creation_time,
        "min_creation_time": min_creation_time,
        "max_creation_time": max_creation_time,
        "duration": duration,
        "min_duration": min_duration,
        "max_duration": max_duration,
        "api_key_kind": api_key_kind.map(|x| x as u8),
        "offset": offset,
        "count": offset,
    })?
    .and_then(|row| row.try_into())
    .filter_map(|x: Result<ApiKey, rusqlite::Error>| x.ok());
  Ok(results.collect::<Vec<ApiKey>>())
}
