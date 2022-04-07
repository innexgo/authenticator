use super::db_types::VerificationChallenge;
use tokio_postgres::GenericClient;

impl From<tokio_postgres::row::Row> for VerificationChallenge {
  // select * from user order only, otherwise it will fail
  fn from(row: tokio_postgres::row::Row) -> VerificationChallenge {
    VerificationChallenge {
      verification_challenge_key_hash: row.get("verification_challenge_key_hash"),
      creation_time: row.get("creation_time"),
      creator_user_id: row.get("creator_user_id"),
      to_parent: row.get("to_parent"),
      email: row.get("email"),
    }
  }
}

pub async fn add(
  con: &mut impl GenericClient,
  verification_challenge_key_hash: String,
  email: String,
  creator_user_id: i64,
  to_parent: bool,
) -> Result<VerificationChallenge, tokio_postgres::Error> {
   let row = con
    .query_one(
      "
      INSERT INTO
      verification_challenge_t(
          verification_challenge_key_hash,
          creator_user_id,
          to_parent,
          email
      )
      VALUES($1, $2, $3, $4)
      ",
      &[
        &verification_challenge_key_hash,
        &creator_user_id,
        &to_parent,
        &email,
      ],
    )
    .await?;

  Ok(VerificationChallenge {
    verification_challenge_key_hash,
    creation_time: row.get(0),
    creator_user_id,
    to_parent,
    email,
  })
}

pub async fn get_by_verification_challenge_key_hash(
  con: &mut impl GenericClient,
  verification_challenge_key_hash: &str,
) -> Result<Option<VerificationChallenge>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT * FROM verification_challenge_t WHERE verification_challenge_key_hash=$1",
      &[&verification_challenge_key_hash],
    )
    .await?
    .map(|row| row.into());

  Ok(result)
}

pub async fn get_num_challenges_by_creator_between(
  con: &mut impl GenericClient,
  creator_user_id: i64,
  min_time: i64,
  max_time: i64,
) -> Result<i64, tokio_postgres::Error> {
  let time = con
    .query_one(
      "
      SELECT COUNT(*)
      FROM verification_challenge_t
      WHERE 1 = 1
      AND creator_user_id=$1
      AND creation_time >= $2
      AND creation_time <= $3
      ",
      &[&creator_user_id, &min_time, &max_time],
    )
    .await?
    .get(0);

  Ok(time)
}
