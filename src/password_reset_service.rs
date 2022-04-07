use super::db_types::PasswordReset;
use tokio_postgres::GenericClient;

pub async fn add(
    con: &mut impl GenericClient,
    password_reset_key_hash: String,
    creator_user_id: i64,
) -> Result<PasswordReset, tokio_postgres::Error> {
    let row = con
        .query_one(
            "
            INSERT INTO password_reset_t(
                password_reset_key_hash,
                creator_user_id
            ) VALUES ($1, $2)
            RETURNING creation_time
            ",
            &[&password_reset_key_hash, &creator_user_id],
        )
        .await?;

    Ok(PasswordReset {
        password_reset_key_hash,
        creation_time: row.get(0),
        creator_user_id,
    })
}

pub async fn get_by_password_reset_key_hash(
    con: &mut impl GenericClient,
    password_reset_key_hash: &str,
) -> Result<Option<PasswordReset>, tokio_postgres::Error> {
    let result = con
        .query_opt(
            "SELECT * FROM password_reset_t WHERE password_reset_key_hash=$1",
            &[&password_reset_key_hash],
        )
        .await?
        .map(|row| PasswordReset {
            password_reset_key_hash: row.get("password_reset_key_hash"),
            creation_time: row.get("creation_time"),
            creator_user_id: row.get("creator_user_id"),
        });

    Ok(result)
}
