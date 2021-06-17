use super::auth_db_types::*;
use super::utils::current_time_millis;
use tokio_postgres::GenericClient;
use std::convert::TryInto;

impl From<tokio_postgres::row::Row> for ApiKey {
  // select * from api_key order only, otherwise it will fail
  fn from(row: tokio_postgres::row::Row) -> ApiKey {
    ApiKey {
      api_key_id: row.get("api_key_id"),
      creation_time: row.get("creation_time"),
      creator_user_id: row.get("creator_user_id"),
      api_key_hash: row.get("api_key_hash"),
      // means that there's a mismatch between the values of the enum and the value stored in the column
      api_key_kind: (row.get::<&str, i64>("api_key_kind") as u8)
        .try_into()
        .unwrap(),
      duration: row.get("duration"),
    }
  }
}

pub fn add(
  con: &mut impl GenericClient,
  creator_user_id: i64,
  api_key_hash: String,
  api_key_kind: auth_service_api::request::ApiKeyKind,
  duration: i64,
) -> Result<ApiKey, tokio_postgres::Error> {
  let creation_time = current_time_millis();

  let api_key_id = con
    .query_one(
      "INSERT INTO
       api_key(
           creation_time,
           creator_user_id,
           api_key_hash,
           api_key_kind,
           duration
       )
       VALUES($1, $2, $3, $4, $5)
       RETURNING api_key_id
      ",
      &[
        &creation_time,
        &creator_user_id,
        &api_key_hash,
        &(api_key_kind.clone() as i64),
        &duration,
      ],
    )?
    .get(0);

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

pub fn get_by_api_key_hash(
  con: &mut impl GenericClient,
  api_key_hash: &str,
) -> Result<Option<ApiKey>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT * FROM api_key WHERE api_key_hash=$1",
      &[&api_key_hash],
    )?
    .map(|x| x.into());

  Ok(result)
}

pub fn query(
  con: &mut impl GenericClient,
  props: auth_service_api::request::ApiKeyViewProps,
) -> Result<Vec<ApiKey>, tokio_postgres::Error> {
  // TODO prevent getting meaningless duration

  let sql = [
    "SELECT a.* FROM api_key a",
    if props.only_recent {
        " INNER JOIN (SELECT max(api_key_id) id FROM api_key GROUP BY api_key_hash) maxids ON maxids.id = a.api_key_id"
    } else {
        ""
    },
    " WHERE 1 = 1",
    " AND ($1 == NULL OR a.api_key_id = $1)",
    " AND ($2 == NULL OR a.creation_time = $2)",
    " AND ($3 == NULL OR a.creation_time >= $3)",
    " AND ($4 == NULL OR a.creation_time <= $4)",
    " AND ($5 == NULL OR a.creator_user_id = $5)",
    " AND ($6 == NULL OR a.duration = $6)",
    " AND ($7 == NULL OR a.duration >= $7)",
    " AND ($8 == NULL OR a.duration <= $8)",
    " AND ($9 == NULL OR a.api_key_kind = $9)",
    " ORDER BY a.api_key_id",
    " LIMIT $10, $11",
  ]
  .join("");

  let stmnt = con.prepare(&sql)?;

  let results = con
    .query(
      &stmnt,
      &[
        &props.api_key_id,
        &props.creator_user_id,
        &props.creation_time,
        &props.min_creation_time,
        &props.max_creation_time,
        &props.duration,
        &props.min_duration,
        &props.max_duration,
        &props.api_key_kind.map(|x| x as i64),
        &props.offset,
        &props.count,
      ],
    )?
    .into_iter()
    .map(|x| x.into())
    .collect();

  Ok(results)
}
