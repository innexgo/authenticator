use super::db_types::*;
use super::utils::current_time_millis;
use tokio_postgres::GenericClient;

impl From<tokio_postgres::row::Row> for UserData {
  // select * from user order only, otherwise it will fail
  fn from(row: tokio_postgres::row::Row) -> UserData {
    UserData {
      user_data_id: row.get("user_data_id"),
      creation_time: row.get("creation_time"),
      creator_user_id: row.get("creator_user_id"),
      dateofbirth: row.get("dateofbirth"),
      username: row.get("username"),
      realname: row.get("realname"),
    }
  }
}

pub async fn add(
  con: &mut impl GenericClient,
  creator_user_id: i64,
  dateofbirth: i64,
  username: String,
  realname: String,
) -> Result<UserData, tokio_postgres::Error> {
  let creation_time = current_time_millis();

  let user_data_id = con
    .query_one(
      "INSERT INTO
       user_data_t(
        creation_time,
        creator_user_id,
        dateofbirth,
        username,
        realname
       )
       VALUES($1, $2, $3, $4, $5)
       RETURNING user_data_id
      ",
      &[
        &creation_time,
        &creator_user_id,
        &dateofbirth,
        &username,
        &realname,
      ],
    )
    .await?
    .get(0);

  // return user
  Ok(UserData {
    user_data_id,
    creation_time,
    creator_user_id,
    dateofbirth,
    username,
    realname,
  })
}

// gets most recent user data by user_id
pub async fn get_by_user_id(
  con: &mut impl GenericClient,
  user_id: i64,
) -> Result<Option<UserData>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT ud.* FROM recent_user_data_v ud
       WHERE ud.creator_user_id = $1
      ",
      &[&user_id],
    )
    .await?
    .map(|x| x.into());

  Ok(result)
}

pub async fn get_by_username(
  con: &mut impl GenericClient,
  username: &str,
) -> Result<Option<UserData>, tokio_postgres::Error> {
  let result = con
    .query_opt(
      "SELECT * FROM recent_user_data_v WHERE username=$1",
      &[&username],
    )
    .await?
    .map(|row| row.into());

  Ok(result)
}

pub async fn query(
  con: &mut impl GenericClient,
  props: auth_service_api::request::UserDataViewProps,
) -> Result<Vec<UserData>, tokio_postgres::Error> {
  let sql = [
    if props.only_recent {
      "SELECT ud.* FROM recent_user_data_v ud"
    } else {
      "SELECT ud.* FROM user_data_t ud"
    },
    " WHERE 1 = 1",
    " AND ($1::bigint[] IS NULL OR ud.user_data_id = ANY($1))",
    " AND ($2::bigint   IS NULL OR ud.creation_time >= $2)",
    " AND ($3::bigint   IS NULL OR ud.creation_time <= $3)",
    " AND ($4::bigint[] IS NULL OR ud.creator_user_id = ANY($4))",
    " AND ($5::bigint   IS NULL OR ud.dateofbirth >= $5)",
    " AND ($6::bigint   IS NULL OR ud.dateofbirth <= $6)",
    " AND ($7::text[]   IS NULL OR ud.username= ANY($7))",
    " AND ($8::text[]   IS NULL OR ud.realname = ANY($8))",
    " ORDER BY ud.user_data_id",
  ]
  .join("\n");

  let stmnt = con.prepare(&sql).await?;

  let results = con
    .query(
      &stmnt,
      &[
        &props.user_data_id,
        &props.min_creation_time,
        &props.max_creation_time,
        &props.creator_user_id,
        &props.min_dateofbirth,
        &props.max_dateofbirth,
        &props.username,
        &props.realname,
      ],
    )
    .await?
    .into_iter()
    .map(|row| row.into())
    .collect();
  Ok(results)
}
