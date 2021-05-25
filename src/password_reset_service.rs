use super::auth_db_types::PasswordReset;
use super::utils::current_time_millis;
use rusqlite::{params, Savepoint, Connection, OptionalExtension};

pub fn add(
  con: &mut Savepoint,
  password_reset_key_hash: String,
  creator_user_id: i64,
) -> Result<PasswordReset, rusqlite::Error> {
  let sql = "INSERT INTO password_reset values (?, ?, ?)";
  let creation_time = current_time_millis();
  con.execute(
    sql,
    params![password_reset_key_hash, creation_time, creator_user_id],
  )?;

  Ok(PasswordReset {
    password_reset_key_hash,
    creation_time,
    creator_user_id,
  })
}

pub fn get_by_password_reset_key_hash(
  con: &Connection,
  password_reset_key_hash: &str,
) -> Result<Option<PasswordReset>, rusqlite::Error> {
  let sql = "SELECT * FROM password_reset WHERE password_reset_key_hash=?";
  con
    .query_row(sql, [password_reset_key_hash], |row| {
      Ok(PasswordReset {
        password_reset_key_hash: row.get(0).unwrap(),
        creation_time: row.get(1).unwrap(),
        creator_user_id: row.get(2).unwrap(),
      })
    })
    .optional()
}
