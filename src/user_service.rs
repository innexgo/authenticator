use super::db_types::*;
use super::utils::current_time_millis;
use tokio_postgres::GenericClient;

impl From<tokio_postgres::row::Row> for User {
  // select * from user order only, otherwise it will fail
  fn from(row: tokio_postgres::row::Row) -> User {
    User {
      user_id: row.get("user_id"),
      creation_time: row.get("creation_time"),
      name: row.get("name"),
      email: row.get("email"),
      verification_challenge_key_hash: row.get("verification_challenge_key_hash"),
    }
  }
}

pub async fn add(
  con: &mut impl GenericClient,
  v: VerificationChallenge,
) -> Result<User, tokio_postgres::Error> {
  let creation_time = current_time_millis();

  let user_id = con
    .query_one(
      "INSERT INTO
       user_t(
        creation_time,
        name,
        email,
        verification_challenge_key_hash
       )
       VALUES($1, $2, $3, $4)
       RETURNING user_id
      ",
      &[
        &creation_time,
        &v.name,
        &v.email,
        &v.verification_challenge_key_hash,
      ],
    ).await?
    .get(0);

  // return user
  Ok(User {
    user_id,
    creation_time,
    name: v.name,
    email: v.email,
    verification_challenge_key_hash: v.verification_challenge_key_hash,
  })
}

pub async fn get_by_user_id(
  con: &mut impl GenericClient,
  user_id: i64,
) -> Result<Option<User>, tokio_postgres::Error> {
  let result = con
    .query_opt("SELECT * FROM user_t WHERE user_id=$1", &[&user_id]).await?
    .map(|row| row.into());

  Ok(result)
}

pub async fn get_by_user_email(
  con: &mut impl GenericClient,
  user_email: &str,
) -> Result<Option<User>, tokio_postgres::Error> {
  let result = con
    .query_opt("SELECT * FROM user_t WHERE email=$1", &[&user_email]).await?
    .map(|row| row.into());

  Ok(result)
}

pub async fn exists_by_email(con: &mut impl GenericClient, email: &str) -> Result<bool, tokio_postgres::Error> {
  let count: i64 = con
    .query_one("SELECT count(*) FROM user_t WHERE email=$1", &[&email]).await?
    .get(0);
  Ok(count != 0)
}

#[allow(unused)]
pub async fn exists_by_user_id(
  con: &mut impl GenericClient,
  user_id: i64,
) -> Result<bool, tokio_postgres::Error> {
  let count: i64 = con
    .query_one("SELECT count(*) FROM user_t WHERE user_id=$1", &[&user_id]).await?
    .get(0);
  Ok(count != 0)
}

pub async fn exists_by_verification_challenge_key_hash(
  con: &mut impl GenericClient,
  verification_challenge_key_hash: &str,
) -> Result<bool, tokio_postgres::Error> {
  let count: i64 = con
    .query_one(
      "SELECT count(*) FROM user_t WHERE verification_challenge_key_hash=$1",
      &[&verification_challenge_key_hash],
    ).await?
    .get(0);
  Ok(count != 0)
}

pub async fn query(
  con: &mut impl GenericClient,
  props: auth_service_api::request::UserViewProps,
) -> Result<Vec<User>, tokio_postgres::Error> {
  let results = con
    .query(
      "SELECT u.* FROM user_t u WHERE 1 = 1
       AND ($1::bigint[] IS NULL OR u.user_id = ANY($1))
       AND ($2::bigint   IS NULL OR u.creation_time >= $2)
       AND ($3::bigint   IS NULL OR u.creation_time <= $3)
       AND ($4::text[]   IS NULL OR u.name = ANY($4))
       AND ($5::text     IS NULL OR u.name LIKE CONCAT('%',$5,'%'))
       AND ($6::text[]   IS NULL OR u.email = ANY($6))
       ORDER BY u.user_id
      ",
      &[
        &props.user_id,
        &props.min_creation_time,
        &props.max_creation_time,
        &props.user_name,
        &props.partial_user_name,
        &props.user_email,
      ],
    ).await?
    .into_iter()
    .map(|row| row.into())
    .collect();
  Ok(results)
}
