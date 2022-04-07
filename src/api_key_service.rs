use super::db_types::*;
use std::convert::TryInto;
use tokio_postgres::GenericClient;

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

pub async fn add(
  con: &mut impl GenericClient,
  creator_user_id: i64,
  api_key_hash: String,
  api_key_kind: auth_service_api::request::ApiKeyKind,
  duration: i64,
) -> Result<ApiKey, tokio_postgres::Error> {
  let row = con
    .query_one(
      "INSERT INTO
       api_key_t(
           creator_user_id,
           api_key_hash,
           api_key_kind,
           duration
       )
       VALUES($1, $2, $3, $4)
       RETURNING api_key_id, creation_time
      ",
      &[
        &creator_user_id,
        &api_key_hash,
        &(api_key_kind.clone() as i64),
        &duration,
      ],
    )
    .await?;

  // return api_key
  Ok(ApiKey {
    api_key_id: row.get(0),
    creation_time: row.get(1),
    creator_user_id,
    api_key_hash,
    api_key_kind,
    duration,
  })
}

pub async fn get_by_api_key_hash(
  con: &mut impl GenericClient,
  api_key_hash: &str,
) -> Result<Option<ApiKey>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT * FROM recent_api_key_v WHERE api_key_hash=$1",
      &[&api_key_hash],
    )
    .await?
    .map(|x| x.into());

  Ok(result)
}

pub async fn query(
  con: &mut impl GenericClient,
  props: auth_service_api::request::ApiKeyViewProps,
) -> Result<Vec<ApiKey>, tokio_postgres::Error> {
  // TODO prevent getting meaningless duration

  let sql = [
    if props.only_recent {
      "SELECT ak.* FROM recent_api_key_v ak"
    } else {
      "SELECT ak.* FROM api_key_t ak"
    },
    " WHERE 1 = 1",
    " AND ($1::bigint[] IS NULL OR ak.api_key_id IN $1)",
    " AND ($2::bigint   IS NULL OR ak.creation_time >= $2)",
    " AND ($3::bigint   IS NULL OR ak.creation_time <= $3)",
    " AND ($4::bigint[] IS NULL OR ak.creator_user_id IN $4)",
    " AND ($5::bigint   IS NULL OR ak.duration >= $5)",
    " AND ($6::bigint   IS NULL OR ak.duration <= $6)",
    " AND ($7::bigint[] IS NULL OR ak.api_key_kind = ANY($7))",
    " ORDER BY ak.api_key_id",
  ]
  .join("");

  let stmnt = con.prepare(&sql).await?;

  let results = con
    .query(
      &stmnt,
      &[
        &props.api_key_id,
        &props.min_creation_time,
        &props.max_creation_time,
        &props.creator_user_id,
        &props.min_duration,
        &props.max_duration,
        &props
          .api_key_kind
          .map(|x| x.into_iter().map(|e| e as i64).collect::<Vec<i64>>()),
      ],
    )
    .await?
    .into_iter()
    .map(|x| x.into())
    .collect();

  Ok(results)
}
