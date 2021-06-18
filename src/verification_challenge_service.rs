use super::auth_db_types::VerificationChallenge;
use super::utils::current_time_millis;
use tokio_postgres::GenericClient;

impl From<tokio_postgres::row::Row> for VerificationChallenge {
  // select * from user order only, otherwise it will fail
  fn from(row: tokio_postgres::row::Row) -> VerificationChallenge {
    VerificationChallenge {
      verification_challenge_key_hash: row.get("verification_challenge_key_hash"),
      creation_time: row.get("creation_time"),
      name: row.get("name"),
      email: row.get("email"),
      password_hash: row.get("password_hash"),
    }
  }
}

pub async fn add(
  con: &mut impl GenericClient,
  verification_challenge_key_hash: String,
  name: String,
  email: String,
  password_hash: String,
) -> Result<VerificationChallenge, tokio_postgres::Error> {
  let creation_time = current_time_millis();

  con.execute(
    "INSERT INTO
     verification_challenge(
         verification_challenge_key_hash,
         creation_time,
         name,
         email,
         password_hash
     )
     VALUES($1, $2, $3, $4, $5)",
    &[
      &verification_challenge_key_hash,
      &creation_time,
      &name,
      &email,
      &password_hash,
    ],
  ).await?;

  Ok(VerificationChallenge {
    verification_challenge_key_hash,
    creation_time,
    name,
    email,
    password_hash,
  })
}

pub async fn get_by_verification_challenge_key_hash(
  con: &mut impl GenericClient,
  verification_challenge_key_hash: &str,
) -> Result<Option<VerificationChallenge>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT * FROM verification_challenge WHERE verification_challenge_key_hash=$1",
      &[&verification_challenge_key_hash],
    ).await?
    .map(|row| row.into());

  Ok(result)
}

pub async fn get_last_email_sent_time(
  con: &mut impl GenericClient,
  email: &str,
) -> Result<Option<i64>, tokio_postgres::Error> {
  let time = con
    .query_one(
      "SELECT MAX(creation_time) FROM verification_challenge WHERE email=$1",
      &[&email],
    ).await?
    .get(0);

  Ok(time)
}
