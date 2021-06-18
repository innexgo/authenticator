use super::auth_db_types::*;
use super::utils::current_time_millis;
use tokio_postgres::GenericClient;
use std::convert::TryInto;

impl From<tokio_postgres::row::Row> for Password {
  // select * from password order only, otherwise it will fail
  fn from(row: tokio_postgres::row::Row) -> Password {
    Password {
      password_id: row.get("password_id"),
      creation_time: row.get("creation_time"),
      creator_user_id: row.get("creator_user_id"),
      password_kind: (row.get::<_, i64>("password_kind") as u8)
        .try_into()
        .unwrap(),
      password_hash: row.get("password_hash"),
      password_reset_key_hash: row.get("password_reset_key_hash"),
    }
  }
}

pub async fn add(
  con: &mut impl GenericClient,
  creator_user_id: i64,
  password_kind: auth_service_api::request::PasswordKind,
  password_hash: String,
  password_reset_key_hash: String,
) -> Result<Password, tokio_postgres::Error> {
  let creation_time = current_time_millis();

  let password_id = con
    .query_one(
      "INSERT INTO
       password(
         creation_time,
         creator_user_id,
         password_kind,
         password_hash,
         password_reset_key_hash
       )
       VALUES ($1, $2, $3, $4, $5)
       RETURNING password_id
      ",
      &[
        &creation_time,
        &creator_user_id,
        &(password_kind.clone() as i64),
        &password_hash,
        &password_reset_key_hash,
      ],
    ).await?
    .get(0);

  // return password
  Ok(Password {
    password_id,
    creation_time,
    creator_user_id,
    password_kind,
    password_hash,
    password_reset_key_hash,
  })
}

pub async fn get_by_user_id(
  con: &mut impl GenericClient,
  user_id: i64,
) -> Result<Option<Password>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT p.* FROM password p
       INNER JOIN (SELECT max(password_id) id FROM password GROUP BY creator_user_id) maxids ON maxids.id = p.password_id
       WHERE p.creator_user_id = $1
      ",
      &[&user_id],
    ).await?
    .map(|x| x.into());

  Ok(result)
}

#[allow(unused)]
pub async fn get_by_password_id(
  con: &mut impl GenericClient,
  password_id: i64,
) -> Result<Option<Password>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT * FROM password WHERE password_id=$1",
      &[&password_id],
    ).await?
    .map(|x| x.into());
  Ok(result)
}

pub async fn exists_by_password_reset_key_hash(
  con: &mut impl GenericClient,
  password_reset_key_hash: &str,
) -> Result<bool, tokio_postgres::Error> {
  let count: i64 = con
    .query_one(
      "SELECT count(*) FROM password WHERE password_reset_key_hash=$1",
      &[&password_reset_key_hash],
    ).await?
    .get(0);
  Ok(count != 0)
}

pub async fn query(
  con: &mut impl GenericClient,
  props: auth_service_api::request::PasswordViewProps,
) -> Result<Vec<Password>, tokio_postgres::Error> {
  let sql = [

    "SELECT p.* FROM password p",
    if props.only_recent {
        " INNER JOIN (SELECT max(password_id) id FROM password GROUP BY creator_user_id) maxids ON maxids.id = p.password_id"
    } else {
        ""
    },
    " AND ($1 == NULL OR p.password_id = $1)",
    " AND ($2 == NULL OR p.creation_time = $2)",
    " AND ($3 == NULL OR p.creation_time >= $3)",
    " AND ($4 == NULL OR p.creation_time <= $4)",
    " AND ($5 == NULL OR p.creator_user_id = $5)",
    " AND ($6 == NULL OR p.password_kind = $6)",
    " ORDER BY p.password_id",
    " LIMIT $7, $8",
  ]
  .join("");

  let stmnt = con.prepare(&sql).await?;

  let results = con
    .query(
      &stmnt,
      &[
        &props.password_id,
        &props.creation_time,
        &props.min_creation_time,
        &props.max_creation_time,
        &props.creator_user_id,
        &props.password_kind.map(|x| x as i64),
        &props.offset,
        &props.count,
      ],
    ).await?
    .into_iter()
    .map(|x| x.into())
    .collect();
  Ok(results)
}
