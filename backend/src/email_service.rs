use super::db_types::*;
use super::utils::current_time_millis;
use tokio_postgres::GenericClient;

impl From<tokio_postgres::row::Row> for Email {
  // select * from user order only, otherwise it will fail
  fn from(row: tokio_postgres::row::Row) -> Email {
    Email {
      email_id: row.get("email_id"),
      creation_time: row.get("creation_time"),
      verification_challenge_key_hash: row.get("verification_challenge_key_hash"),
    }
  }
}

pub async fn add(
  con: &mut impl GenericClient,
  verification_challenge_key_hash: String,
) -> Result<Email, tokio_postgres::Error> {
  let creation_time = current_time_millis();

  let email_id = con
    .query_one(
      "INSERT INTO
       email_t(
        creation_time,
        verification_challenge_key_hash
       )
       VALUES($1, $2)
       RETURNING email_id
      ",
      &[&creation_time, &verification_challenge_key_hash],
    )
    .await?
    .get(0);

  // return user
  Ok(Email {
    email_id,
    creation_time,
    verification_challenge_key_hash,
  })
}

#[allow(unused)]
pub async fn get_by_email_id(
  con: &mut impl GenericClient,
  email_id: i64,
) -> Result<Option<Email>, tokio_postgres::Error> {
  let result = con
    .query_opt("SELECT * FROM email_t WHERE email_id=$1", &[&email_id])
    .await?
    .map(|row| row.into());

  Ok(result)
}

pub async fn get_by_verification_challenge_key_hash(
  con: &mut impl GenericClient,
  verification_challenge_key_hash: &str,
) -> Result<Option<Email>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT * FROM email_t WHERE verification_challenge_key_hash=$1",
      &[&verification_challenge_key_hash],
    )
    .await?
    .map(|row| row.into());

  Ok(result)
}

// gets most recent email
pub async fn get_by_own_email(
  con: &mut impl GenericClient,
  email: &str,
) -> Result<Option<Email>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT e.* FROM recent_own_email_v e
       INNER JOIN verification_challenge_t vc ON vc.verification_challenge_key_hash = e.verification_challenge_key_hash
       WHERE vc.email = $1
      ",
      &[&email],
    ).await?
    .map(|x| x.into());

  Ok(result)
}

pub async fn get_own_by_user_id(
  con: &mut impl GenericClient,
  user_id: i64,
) -> Result<Option<Email>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT e.* FROM recent_own_email_v e
       JOIN verification_challenge_t vc USING(verification_challenge_key_hash)
       WHERE vc.creator_user_id = $1
      ",
      &[&user_id],
    )
    .await?
    .map(|x| x.into());
  Ok(result)
}

pub async fn get_parent_by_user_id(
  con: &mut impl GenericClient,
  user_id: i64,
) -> Result<Option<Email>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT e.* FROM recent_parent_email_v e
       JOIN verification_challenge_t vc USING(verification_challenge_key_hash)
       WHERE vc.creator_user_id = $1
      ",
      &[&user_id],
    )
    .await?
    .map(|x| x.into());
  Ok(result)
}

pub async fn query(
  con: &mut impl GenericClient,
  props: auth_service_api::request::EmailViewProps,
) -> Result<Vec<Email>, tokio_postgres::Error> {
  let sql = [
    if props.only_recent {
      if props.to_parent {
        "SELECT e.* FROM recent_parent_email_v e"
      } else {
        "SELECT e.* FROM recent_own_email_v e"
      }
    } else {
      "SELECT e.* FROM email_t e"
    },
    " JOIN verification_challenge_t vc USING(verification_challenge_key_hash)",
    " WHERE 1 = 1",
    " AND vc.to_parent = $1",
    " AND ($2::bigint[] IS NULL OR e.email_id = ANY($2))",
    " AND ($3::bigint   IS NULL OR e.creation_time >= $3)",
    " AND ($4::bigint   IS NULL OR e.creation_time <= $4)",
    " AND ($5::bigint[] IS NULL OR vc.creator_user_id = ANY($5))",
    " AND ($6::text[]   IS NULL OR vc.email = ANY($6))",
    " ORDER BY e.email_id",
  ]
  .join("\n");

  let stmnt = con.prepare(&sql).await?;

  let results = con
    .query(
      &stmnt,
      &[
        &props.to_parent,
        &props.email_id,
        &props.min_creation_time,
        &props.max_creation_time,
        &props.creator_user_id,
        &props.email,
      ],
    )
    .await?
    .into_iter()
    .map(|row| row.into())
    .collect();
  Ok(results)
}
