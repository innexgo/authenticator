use std::fmt::Display;

use super::Data;
use actix_web::web;
use actix_web::HttpResponse;
use actix_web::Responder;
use actix_web::ResponseError;
use auth_service_api::request;
use auth_service_api::response;
use auth_service_api::response::AuthError;
use reqwest::StatusCode;

use super::api_key_service;
use super::db_types::*;
use super::email_service;
use super::password_reset_service;
use super::password_service;
use super::user_data_service;
use super::user_service;
use super::utils;
use super::verification_challenge_service;

use mail_service_api::client::MailService;
use mail_service_api::response::MailError;

static FIFTEEN_MINUTES: i64 = 15 * 60 * 1000;
static THIRTEEN_YEARS: i64 = (13.0 * 365.25 * 24.0 * 60.0 * 60.0 * 1000.0) as i64;

#[derive(Debug, Clone)]
pub struct AppError(response::AuthError);

fn report_internal_err<E: std::error::Error>(e: E) -> AppError {
    log::error!("{}", e);
    AppError(response::AuthError::Unknown)
}

fn report_postgres_err(e: tokio_postgres::Error) -> AppError {
    log::error!("{}", e);
    AppError(response::AuthError::InternalServerError)
}

fn report_mail_err(e: MailError) -> AppError {
    let ae = match e {
        MailError::DestinationBounced => response::AuthError::EmailBounced,
        MailError::DestinationProhibited => response::AuthError::EmailBounced,
        // TODO: log this
        _ => response::AuthError::InternalServerError,
    };
    log::warn!("{}", e);
    AppError(ae)
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<response::AuthError> for AppError {
    fn from(value: response::AuthError) -> Self {
        Self(value)
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(&self.0)
    }
    fn status_code(&self) -> StatusCode {
        match self.0 {
            AuthError::DecodeError => StatusCode::BAD_GATEWAY,
            AuthError::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::ApiKeyUnauthorized => StatusCode::UNAUTHORIZED,
            AuthError::BadRequest => StatusCode::BAD_REQUEST,
            AuthError::NotFound => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

async fn fill_user(
    _con: &mut tokio_postgres::Client,
    user: User,
) -> Result<response::User, AppError> {
    Ok(response::User {
        user_id: user.user_id,
        creation_time: user.creation_time,
    })
}

async fn fill_user_data(
    _con: &mut tokio_postgres::Client,
    user_data: UserData,
) -> Result<response::UserData, AppError> {
    Ok(response::UserData {
        user_data_id: user_data.user_data_id,
        creation_time: user_data.creation_time,
        creator_user_id: user_data.creator_user_id,
        dateofbirth: user_data.dateofbirth,
        username: user_data.username,
        realname: user_data.realname,
    })
}

async fn fill_api_key(
    _con: &mut tokio_postgres::Client,
    api_key: ApiKey,
    key: Option<String>,
) -> Result<response::ApiKey, AppError> {
    Ok(response::ApiKey {
        api_key_id: api_key.api_key_id,
        creation_time: api_key.creation_time,
        creator_user_id: api_key.creator_user_id,
        api_key_kind: api_key.api_key_kind,
        duration: api_key.duration,
        key,
    })
}

async fn fill_email(
    con: &mut tokio_postgres::Client,
    email: Email,
) -> Result<response::Email, AppError> {
    let verification_challenge =
        verification_challenge_service::get_by_verification_challenge_key_hash(
            con,
            &email.verification_challenge_key_hash,
        )
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::VerificationChallengeNonexistent)?;

    Ok(response::Email {
        email_id: email.email_id,
        creation_time: email.creation_time,
        verification_challenge: fill_verification_challenge(con, verification_challenge).await?,
    })
}

async fn fill_password(
    con: &mut tokio_postgres::Client,
    password: Password,
) -> Result<response::Password, AppError> {
    let password_reset = match password.password_reset_key_hash {
        Some(password_reset_key_hash) => {
            let password_reset = password_reset_service::get_by_password_reset_key_hash(
                con,
                &password_reset_key_hash,
            )
            .await
            .map_err(report_postgres_err)?
            .ok_or(response::AuthError::PasswordResetNonexistent)?;
            Some(fill_password_reset(con, password_reset).await?)
        }
        _ => None,
    };

    Ok(response::Password {
        password_id: password.password_id,
        creation_time: password.creation_time,
        creator_user_id: password.creator_user_id,
        password_reset,
    })
}

async fn fill_password_reset(
    _con: &tokio_postgres::Client,
    password_reset: PasswordReset,
) -> Result<response::PasswordReset, AppError> {
    Ok(response::PasswordReset {
        creation_time: password_reset.creation_time,
    })
}

async fn fill_verification_challenge(
    _con: &tokio_postgres::Client,
    verification_challenge: VerificationChallenge,
) -> Result<response::VerificationChallenge, AppError> {
    Ok(response::VerificationChallenge {
        creation_time: verification_challenge.creation_time,
        to_parent: verification_challenge.to_parent,
        email: verification_challenge.email,
    })
}

// returns the api key if not cancelled and the time is in bounds
pub async fn get_api_key_if_current_noverify(
    con: &mut tokio_postgres::Client,
    api_key: &str,
) -> Result<ApiKey, AppError> {
    let creator_api_key = api_key_service::get_by_api_key_hash(con, &utils::hash_str(api_key))
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::ApiKeyNonexistent)?;

    if utils::current_time_millis() > creator_api_key.creation_time + creator_api_key.duration {
        Err(response::AuthError::ApiKeyUnauthorized)?;
    }

    // ensure is valid, noemail, or noparent
    match creator_api_key.api_key_kind {
        request::ApiKeyKind::Valid => Ok(creator_api_key),
        request::ApiKeyKind::NoEmail => Ok(creator_api_key),
        request::ApiKeyKind::NoParent => Ok(creator_api_key),
        _ => Err(response::AuthError::ApiKeyUnauthorized)?,
    }
}

// returns the api key if in bounds and it is valid
pub async fn get_api_key_if_valid(
    con: &mut tokio_postgres::Client,
    api_key: &str,
) -> Result<ApiKey, AppError> {
    let creator_api_key = api_key_service::get_by_api_key_hash(con, &utils::hash_str(api_key))
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::ApiKeyNonexistent)?;

    if utils::current_time_millis() > creator_api_key.creation_time + creator_api_key.duration {
        Err(response::AuthError::ApiKeyUnauthorized)?;
    }

    // ensure is valid
    match creator_api_key.api_key_kind {
        request::ApiKeyKind::Valid => Ok(creator_api_key),
        _ => Err(response::AuthError::ApiKeyUnauthorized)?,
    }
}

// respond with info about stuff
pub async fn info(data: web::Data<Data>) -> Result<impl Responder, AppError> {
    return Ok(web::Json(response::Info {
        service: String::from(crate::SERVICE_NAME),
        version_major: crate::VERSION_MAJOR,
        version_minor: crate::VERSION_MINOR,
        version_rev: crate::VERSION_REV,
        app_pub_api_href: format!("{}/public/", data.app_pub_origin_api),
        app_authenticator_href: format!("{}/login", data.app_pub_origin_web),
        permitted_origins: data.permitted_origins.clone(),
    }));
}

pub async fn api_key_new_with_email(
    data: web::Data<Data>,
    props: web::Json<request::ApiKeyNewWithEmailProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;

    let email = email_service::get_by_own_email(con, &props.email)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::EmailNonexistent)?;

    let verification_challenge =
        verification_challenge_service::get_by_verification_challenge_key_hash(
            con,
            &email.verification_challenge_key_hash,
        )
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::InternalServerError)?;

    let userdata = user_data_service::get_by_user_id(con, verification_challenge.creator_user_id)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::UserNonexistent)?;

    // now delegate
    internal_api_key_new_valid(con, userdata, props.password.clone(), props.duration).await
}

pub async fn api_key_new_with_username(
    data: web::Data<Data>,
    props: web::Json<request::ApiKeyNewWithUsernameProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;

    let userdata = user_data_service::get_by_username(con, &props.username)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::UserNonexistent)?;

    // now delegate
    internal_api_key_new_valid(con, userdata, props.password.clone(), props.duration).await
}

pub async fn internal_api_key_new_valid(
    con: &mut tokio_postgres::Client,
    user_data: UserData,
    user_password: String,
    duration: i64,
) -> Result<impl Responder, AppError> {
    // get user password
    let password = password_service::get_by_user_id(con, user_data.creator_user_id)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::PasswordNonexistent)?;

    // validate password with argon2 (password hashing algorithm)
    if !utils::verify_password(&user_password, &password.password_hash)
        .map_err(report_internal_err)?
    {
        Err(response::AuthError::PasswordIncorrect)?;
    }

    let verification_status = if email_service::get_own_by_user_id(con, user_data.creator_user_id)
        .await
        .map_err(report_postgres_err)?
        .is_some()
    {
        if utils::current_time_millis() - user_data.dateofbirth < THIRTEEN_YEARS {
            match email_service::get_parent_by_user_id(con, user_data.creator_user_id)
                .await
                .map_err(report_postgres_err)?
            {
                Some(_) => request::ApiKeyKind::Valid,
                None => request::ApiKeyKind::NoParent,
            }
        } else {
            request::ApiKeyKind::Valid
        }
    } else {
        request::ApiKeyKind::NoEmail
    };

    let mut sp = con.transaction().await.map_err(report_postgres_err)?;

    let raw_api_key = utils::gen_random_string();
    // add new api key
    let api_key = api_key_service::add(
        &mut sp,
        user_data.creator_user_id,
        utils::hash_str(&raw_api_key),
        verification_status,
        duration,
    )
    .await
    .map_err(report_postgres_err)?;

    sp.commit().await.map_err(report_postgres_err)?;

    Ok(web::Json(
        fill_api_key(con, api_key, Some(raw_api_key)).await?,
    ))
}

pub async fn api_key_new_cancel(
    data: web::Data<Data>,
    props: web::Json<request::ApiKeyNewCancelProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;

    // validate api key
    let creator_key = get_api_key_if_valid(con, &props.api_key).await?;

    let to_cancel_key = get_api_key_if_valid(con, &props.api_key_to_cancel).await?;

    if creator_key.creator_user_id != to_cancel_key.creator_user_id {
        Err(response::AuthError::ApiKeyUnauthorized)?;
    }

    let mut sp = con.transaction().await.map_err(report_postgres_err)?;

    // cancel keys
    let key_cancel = api_key_service::add(
        &mut sp,
        creator_key.creator_user_id,
        to_cancel_key.api_key_hash,
        request::ApiKeyKind::Cancel,
        0,
    )
    .await
    .map_err(report_postgres_err)?;

    sp.commit().await.map_err(report_postgres_err)?;

    // return json
    Ok(web::Json(fill_api_key(con, key_cancel, None).await?))
}

pub async fn send_parent_permission_email(
    mail_service: &MailService,
    target_email: &str,
    user_name: &str,
    app_pub_origin: &str,
    verification_challenge_key: &str,
) -> Result<(), AppError> {
    let _ = mail_service
        .mail_new(mail_service_api::request::MailNewProps {
            request_id: 0,
            destination: target_email.to_owned(),
            topic: "parent_permission".to_owned(),
            title: format!("{}: Parent Permission For {}", app_pub_origin, user_name),
            content: [
                &format!(
          "<p>Your child, <code>{}</code>, has requested permission to use: <code>{}</code></p>",
          user_name, app_pub_origin
        ),
                "<p>If you did not make this request, then feel free to ignore.</p>",
                "<p>This link is valid for up to 15 minutes.</p>",
                "<p>Do not share this link with others.</p>",
                &format!(
          "<p>Verification link: {}/parent_permission_confirm?verificationChallengeKey={}</p>",
          app_pub_origin, verification_challenge_key
        ),
            ]
            .join(""),
        })
        .await
        .map_err(report_mail_err)?;

    Ok(())
}

pub async fn send_email_verification_email(
    mail_service: &MailService,
    target_email: &str,
    user_name: &str,
    app_pub_origin: &str,
    verification_challenge_key: &str,
) -> Result<(), AppError> {
    let _ = mail_service
        .mail_new(mail_service_api::request::MailNewProps {
            request_id: 0,
            destination: target_email.to_owned(),
            topic: "verification_challenge".to_owned(),
            title: format!("{}: Email Verification", app_pub_origin),
            content: [
                &format!(
                    "<p>This email has been sent to verify for: <code>{}</code> </p>",
                    &user_name
                ),
                "<p>If you did not make this request, then feel free to ignore.</p>",
                "<p>This link is valid for up to 15 minutes.</p>",
                "<p>Do not share this link with others.</p>",
                &format!(
                    "<p>Verification link: {}/email_confirm?verificationChallengeKey={}</p>",
                    app_pub_origin, verification_challenge_key
                ),
            ]
            .join(""),
        })
        .await
        .map_err(report_mail_err)?;
    Ok(())
}

pub async fn verification_challenge_new(
    data: web::Data<Data>,
    props: web::Json<request::VerificationChallengeNewProps>,
) -> Result<impl Responder, AppError> {
    // avoid sending email to obviously bad addresses
    if props.email.is_empty() {
        Err(response::AuthError::EmailBounced)?;
    }

    let con = &mut *data.db.lock().await;

    // you need to have an account but its fine not to be verified yet
    let api_key = get_api_key_if_current_noverify(con, &props.api_key).await?;

    // don't let people spam emails
    let num_emails = verification_challenge_service::get_num_challenges_by_creator_between(
        con,
        api_key.creator_user_id,
        utils::current_time_millis() - FIFTEEN_MINUTES,
        utils::current_time_millis(),
    )
    .await
    .map_err(report_postgres_err)?;

    // limit to 4 emails in past 15 minutes
    if num_emails > 4 {
        // TODO: more descriptive error
        Err(response::AuthError::EmailCooldown)?;
    }

    // get user data to generate
    let user_data = user_data_service::get_by_user_id(con, api_key.creator_user_id)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::UserDataNonexistent)?;

    // generate random string
    let verification_challenge_key = utils::gen_random_string();

    // send email depending on kind
    if props.to_parent {
        send_parent_permission_email(
            &data.mail_service,
            &props.email,
            &user_data.realname,
            &data.app_pub_origin_web,
            &verification_challenge_key,
        )
        .await?;
    } else {
        send_email_verification_email(
            &data.mail_service,
            &props.email,
            &user_data.realname,
            &data.app_pub_origin_web,
            &verification_challenge_key,
        )
        .await?;
    }

    // insert into database
    let verification_challenge = verification_challenge_service::add(
        con,
        utils::hash_str(&verification_challenge_key),
        props.email.clone(),
        api_key.creator_user_id,
        props.to_parent,
    )
    .await
    .map_err(report_postgres_err)?;

    // return json
    Ok(web::Json(
        fill_verification_challenge(con, verification_challenge).await?,
    ))
}

pub async fn user_new(
    data: web::Data<Data>,
    props: web::Json<request::UserNewProps>,
) -> Result<impl Responder, AppError> {
    if !utils::is_realname_valid(&props.realname) {
        Err(response::AuthError::UserRealnameInvalid)?;
    }

    if !utils::is_username_valid(&props.username) {
        Err(response::AuthError::UserUsernameInvalid)?;
    }

    // server side validation of password strength
    if !utils::is_secure_password(&props.password) {
        Err(response::AuthError::PasswordInsecure)?;
    }

    let con = &mut *data.db.lock().await;

    let mut sp = con.transaction().await.map_err(report_postgres_err)?;

    // check username is not used
    if user_data_service::get_by_username(&mut sp, &props.username)
        .await
        .map_err(report_postgres_err)?
        .is_some()
    {
        Err(response::AuthError::UserUsernameTaken)?;
    }

    // create user
    let user = user_service::add(&mut sp)
        .await
        .map_err(report_postgres_err)?;

    // create user data
    let user_data = user_data_service::add(
        &mut sp,
        user.user_id,
        props.dateofbirth,
        props.username.clone(),
        props.realname.clone(),
    )
    .await
    .map_err(report_postgres_err)?;

    // create password
    let password_hash = utils::hash_password(&props.password).map_err(report_internal_err)?;
    password_service::add(&mut sp, user.user_id, password_hash, None)
        .await
        .map_err(report_postgres_err)?;

    let raw_api_key = utils::gen_random_string();
    // add new api key
    let api_key = api_key_service::add(
        &mut sp,
        user_data.creator_user_id,
        utils::hash_str(&raw_api_key),
        request::ApiKeyKind::NoEmail,
        // 1 hour
        props.api_key_duration as i64,
    )
    .await
    .map_err(report_postgres_err)?;

    sp.commit().await.map_err(report_postgres_err)?;

    // return api key
    Ok(web::Json(
        fill_api_key(con, api_key, Some(raw_api_key)).await?,
    ))
}

pub async fn user_data_new(
    data: web::Data<Data>,
    props: web::Json<request::UserDataNewProps>,
) -> Result<impl Responder, AppError> {
    // ensure names are valid
    if !utils::is_realname_valid(&props.realname) {
        Err(response::AuthError::UserRealnameInvalid)?;
    }

    if !utils::is_username_valid(&props.username) {
        Err(response::AuthError::UserUsernameInvalid)?;
    }

    let con = &mut *data.db.lock().await;

    // api key verification required (email or parent permission not needed)
    let creator_key = get_api_key_if_current_noverify(con, &props.api_key).await?;

    // check username is not used
    let maybe_user_data = user_data_service::get_by_username(con, &props.username)
        .await
        .map_err(report_postgres_err)?;

    let username_not_taken = match maybe_user_data {
        Some(UserData {
            creator_user_id, ..
        }) => creator_user_id == creator_key.creator_user_id,
        None => true,
    };

    if !username_not_taken {
        Err(response::AuthError::UserUsernameTaken)?;
    }

    // create key data
    let user_data = user_data_service::add(
        con,
        creator_key.creator_user_id,
        props.dateofbirth,
        props.username.clone(),
        props.realname.clone(),
    )
    .await
    .map_err(report_postgres_err)?;

    // return json
    Ok(web::Json(fill_user_data(con, user_data).await?))
}

pub async fn email_new(
    data: web::Data<Data>,
    props: web::Json<request::EmailNewProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;

    let vckh = utils::hash_str(&props.verification_challenge_key);

    // check that the verification challenge exists
    let vc = verification_challenge_service::get_by_verification_challenge_key_hash(con, &vckh)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::VerificationChallengeNonexistent)?;

    // check that it hasn't timed out
    if FIFTEEN_MINUTES as i64 + vc.creation_time < utils::current_time_millis() {
        Err(response::AuthError::VerificationChallengeTimedOut)?;
    }

    // check that the verification challenge is meant for the correct purpose
    if vc.to_parent != props.to_parent {
        Err(response::AuthError::VerificationChallengeWrongKind)?;
    }

    // check if the verification challenge was not already used to make a new email
    if email_service::get_by_verification_challenge_key_hash(con, &vckh)
        .await
        .map_err(report_postgres_err)?
        .is_some()
    {
        Err(response::AuthError::VerificationChallengeUsed)?;
    }

    // (if not parent) check that the email isn't already in use by another user
    if !vc.to_parent {
        if email_service::get_by_own_email(con, &vc.email)
            .await
            .map_err(report_postgres_err)?
            .is_some()
        {
            Err(response::AuthError::EmailExistent)?;
        }
    }

    // create key data
    let email = email_service::add(con, vckh)
        .await
        .map_err(report_postgres_err)?;

    // return json
    Ok(web::Json(fill_email(con, email).await?))
}

pub async fn password_reset_new(
    data: web::Data<Data>,
    props: web::Json<request::PasswordResetNewProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;

    let email = email_service::get_by_own_email(con, &props.email)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::EmailNonexistent)?;

    let verification_challenge =
        verification_challenge_service::get_by_verification_challenge_key_hash(
            con,
            &email.verification_challenge_key_hash,
        )
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::VerificationChallengeNonexistent)?;

    let raw_key = utils::gen_random_string();

    // send mail
    let _ = data
        .mail_service
        .mail_new(mail_service_api::request::MailNewProps {
            request_id: 0,
            destination: props.email.clone(),
            topic: "password_reset".to_owned(),
            title: format!("{}: Password Reset", &data.app_pub_origin_web),
            content: [
                "<p>Requested password reset service: </p>",
                "<p>If you did not make this request, then feel free to ignore.</p>",
                "<p>This link is valid for up to 15 minutes.</p>",
                "<p>Do not share this link with others.</p>",
                &format!(
                    "<p>Password change link: {}/reset_password?resetKey={}</p>",
                    &data.app_pub_origin_web, raw_key
                ),
            ]
            .join(""),
        })
        .await
        .map_err(report_mail_err)?;

    let mut sp = con.transaction().await.map_err(report_postgres_err)?;

    let password_reset = password_reset_service::add(
        &mut sp,
        utils::hash_str(&raw_key),
        verification_challenge.creator_user_id,
    )
    .await
    .map_err(report_postgres_err)?;

    sp.commit().await.map_err(report_postgres_err)?;

    // fill struct
    Ok(web::Json(fill_password_reset(con, password_reset).await?))
}

pub async fn password_new_reset(
    data: web::Data<Data>,
    props: web::Json<request::PasswordNewResetProps>,
) -> Result<impl Responder, AppError> {
    // no api key verification needed

    let con = &mut *data.db.lock().await;

    // get password reset
    let psr = password_reset_service::get_by_password_reset_key_hash(
        con,
        &utils::hash_str(&props.password_reset_key),
    )
    .await
    .map_err(report_postgres_err)?
    .ok_or(response::AuthError::PasswordResetNonexistent)?;

    // deny if we alread created a password from this reset
    if password_service::exists_by_password_reset_key_hash(con, &psr.password_reset_key_hash)
        .await
        .map_err(report_postgres_err)?
    {
        Err(response::AuthError::PasswordExistent)?;
    }

    // deny if timed out
    if FIFTEEN_MINUTES as i64 + psr.creation_time < utils::current_time_millis() {
        Err(response::AuthError::PasswordResetTimedOut)?;
    }

    // reject insecure passwords
    if !utils::is_secure_password(&props.new_password) {
        Err(response::AuthError::PasswordInsecure)?;
    }

    // attempt to hash password
    let new_password_hash =
        utils::hash_password(&props.new_password).map_err(report_internal_err)?;

    let mut sp = con.transaction().await.map_err(report_postgres_err)?;

    // create password
    let password = password_service::add(
        &mut sp,
        psr.creator_user_id,
        new_password_hash,
        Some(psr.password_reset_key_hash),
    )
    .await
    .map_err(report_postgres_err)?;

    sp.commit().await.map_err(report_postgres_err)?;

    Ok(web::Json(fill_password(con, password).await?))
}

pub async fn password_new_change(
    data: web::Data<Data>,
    props: web::Json<request::PasswordNewChangeProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;

    // api key verification required (no parent permission needed tho)
    let creator_key = get_api_key_if_current_noverify(con, &props.api_key).await?;

    // reject insecure passwords
    if !utils::is_secure_password(&props.new_password) {
        Err(response::AuthError::PasswordInsecure)?;
    }

    // attempt to hash password
    let new_password_hash =
        utils::hash_password(&props.new_password).map_err(report_internal_err)?;

    let mut sp = con.transaction().await.map_err(report_postgres_err)?;

    // create password
    let password = password_service::add(
        &mut sp,
        creator_key.creator_user_id,
        new_password_hash,
        None,
    )
    .await
    .map_err(report_postgres_err)?;

    sp.commit().await.map_err(report_postgres_err)?;

    // return filled struct
    Ok(web::Json(fill_password(con, password).await?))
}

pub async fn user_view(
    data: web::Data<Data>,
    props: web::Json<request::UserViewProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get users
    let users = user_service::query(con, props.into_inner())
        .await
        .map_err(report_postgres_err)?;

    let mut resp_users = vec![];
    for u in users.into_iter() {
        resp_users.push(fill_user(con, u).await?);
    }

    Ok(web::Json(resp_users))
}

pub async fn user_data_view(
    data: web::Data<Data>,
    props: web::Json<request::UserDataViewProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get user_datas
    let user_datas = user_data_service::query(con, props.into_inner())
        .await
        .map_err(report_postgres_err)?;

    let mut resp_user_datas = vec![];
    for u in user_datas.into_iter() {
        resp_user_datas.push(fill_user_data(con, u).await?);
    }

    Ok(web::Json(resp_user_datas))
}

pub async fn email_view(
    data: web::Data<Data>,
    props: web::Json<request::EmailViewProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get emails
    let emails = email_service::query(con, props.into_inner())
        .await
        .map_err(report_postgres_err)?;

    // return emails
    let mut resp_emails = vec![];
    for u in emails.into_iter() {
        resp_emails.push(fill_email(con, u).await?);
    }

    Ok(web::Json(resp_emails))
}

pub async fn password_view(
    data: web::Data<Data>,
    props: web::Json<request::PasswordViewProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get passwords
    let passwords = password_service::query(con, props.into_inner())
        .await
        .map_err(report_postgres_err)?;

    // return passwords
    let mut resp_passwords = vec![];
    for u in passwords.into_iter() {
        resp_passwords.push(fill_password(con, u).await?);
    }

    Ok(web::Json(resp_passwords))
}

pub async fn api_key_view(
    data: web::Data<Data>,
    props: web::Json<request::ApiKeyViewProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get users
    let api_keys = api_key_service::query(con, props.into_inner())
        .await
        .map_err(report_postgres_err)?;

    // return
    let mut resp_api_keys = vec![];
    for u in api_keys.into_iter() {
        resp_api_keys.push(fill_api_key(con, u, None).await?);
    }

    Ok(web::Json(resp_api_keys))
}

// special internal api
pub async fn get_user_by_id(
    data: web::Data<Data>,
    props: web::Json<request::GetUserByIdProps>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;

    let user = user_service::get_by_user_id(con, props.user_id)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::UserNonexistent)?;

    Ok(web::Json(fill_user(con, user).await?))
}

pub async fn get_user_by_api_key_if_valid(
    data: web::Data<Data>,
    props: web::Json<request::GetUserByApiKeyIfValid>,
) -> Result<impl Responder, AppError> {
    let con = &mut *data.db.lock().await;

    let api_key = get_api_key_if_valid(con, &props.api_key).await?;

    let user = user_service::get_by_user_id(con, api_key.creator_user_id)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::UserNonexistent)?;

    Ok(web::Json(fill_user(con, user).await?))
}
