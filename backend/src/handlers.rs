use std::error::Error;

use super::Data;
use auth_service_api::request;
use auth_service_api::response;

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

fn report_internal_err<E: std::error::Error>(e: E) -> response::AuthError {
    utils::log(utils::Event {
        msg: e.to_string(),
        source: e.source().map(|e| e.to_string()),
        severity: utils::SeverityKind::Error,
    });
    response::AuthError::Unknown
}

fn report_postgres_err(e: tokio_postgres::Error) -> response::AuthError {
    utils::log(utils::Event {
        msg: e.to_string(),
        source: e.source().map(|e| e.to_string()),
        severity: utils::SeverityKind::Error,
    });
    response::AuthError::InternalServerError
}

fn report_mail_err(e: MailError) -> response::AuthError {
    let ae = match e {
        MailError::DestinationBounced => response::AuthError::EmailBounced,
        MailError::DestinationProhibited => response::AuthError::EmailBounced,
        // TODO: log this
        _ => response::AuthError::InternalServerError,
    };

    utils::log(utils::Event {
        msg: ae.to_string(),
        source: Some(format!("email service: {}", e)),
        severity: utils::SeverityKind::Error,
    });

    ae
}

async fn fill_user(
    _con: &mut tokio_postgres::Client,
    user: User,
) -> Result<response::User, response::AuthError> {
    Ok(response::User {
        user_id: user.user_id,
        creation_time: user.creation_time,
    })
}

async fn fill_user_data(
    _con: &mut tokio_postgres::Client,
    user_data: UserData,
) -> Result<response::UserData, response::AuthError> {
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
) -> Result<response::ApiKey, response::AuthError> {
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
) -> Result<response::Email, response::AuthError> {
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
) -> Result<response::Password, response::AuthError> {
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
) -> Result<response::PasswordReset, response::AuthError> {
    Ok(response::PasswordReset {
        creation_time: password_reset.creation_time,
    })
}

async fn fill_verification_challenge(
    _con: &tokio_postgres::Client,
    verification_challenge: VerificationChallenge,
) -> Result<response::VerificationChallenge, response::AuthError> {
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
) -> Result<ApiKey, response::AuthError> {
    let creator_api_key = api_key_service::get_by_api_key_hash(con, &utils::hash_str(api_key))
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::ApiKeyNonexistent)?;

    if utils::current_time_millis() > creator_api_key.creation_time + creator_api_key.duration {
        return Err(response::AuthError::ApiKeyUnauthorized);
    }

    // ensure is valid, noemail, or noparent
    match creator_api_key.api_key_kind {
        request::ApiKeyKind::Valid => Ok(creator_api_key),
        request::ApiKeyKind::NoEmail => Ok(creator_api_key),
        request::ApiKeyKind::NoParent => Ok(creator_api_key),
        _ => Err(response::AuthError::ApiKeyUnauthorized),
    }
}

// returns the api key if in bounds and it is valid
pub async fn get_api_key_if_valid(
    con: &mut tokio_postgres::Client,
    api_key: &str,
) -> Result<ApiKey, response::AuthError> {
    let creator_api_key = api_key_service::get_by_api_key_hash(con, &utils::hash_str(api_key))
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::ApiKeyNonexistent)?;

    if utils::current_time_millis() > creator_api_key.creation_time + creator_api_key.duration {
        return Err(response::AuthError::ApiKeyUnauthorized);
    }

    // ensure is valid
    match creator_api_key.api_key_kind {
        request::ApiKeyKind::Valid => Ok(creator_api_key),
        _ => Err(response::AuthError::ApiKeyUnauthorized),
    }
}

pub async fn api_key_new_with_email(
    data: Data,
    props: request::ApiKeyNewWithEmailProps,
) -> Result<response::ApiKey, response::AuthError> {
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
    internal_api_key_new_valid(con, userdata, props.password, props.duration).await
}

pub async fn api_key_new_with_username(
    data: Data,
    props: request::ApiKeyNewWithUsernameProps,
) -> Result<response::ApiKey, response::AuthError> {
    let con = &mut *data.db.lock().await;

    let userdata = user_data_service::get_by_username(con, &props.username)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::UserNonexistent)?;

    // now delegate
    internal_api_key_new_valid(con, userdata, props.password, props.duration).await
}

pub async fn internal_api_key_new_valid(
    con: &mut tokio_postgres::Client,
    user_data: UserData,
    user_password: String,
    duration: i64,
) -> Result<response::ApiKey, response::AuthError> {
    // get user password
    let password = password_service::get_by_user_id(con, user_data.creator_user_id)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::PasswordNonexistent)?;

    // validate password with argon2 (password hashing algorithm)
    if !utils::verify_password(&user_password, &password.password_hash)
        .map_err(report_internal_err)?
    {
        return Err(response::AuthError::PasswordIncorrect);
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

    fill_api_key(con, api_key, Some(raw_api_key)).await
}

pub async fn api_key_new_cancel(
    data: Data,
    props: request::ApiKeyNewCancelProps,
) -> Result<response::ApiKey, response::AuthError> {
    let con = &mut *data.db.lock().await;

    // validate api key
    let creator_key = get_api_key_if_valid(con, &props.api_key).await?;

    let to_cancel_key = get_api_key_if_valid(con, &props.api_key_to_cancel).await?;

    if creator_key.creator_user_id != to_cancel_key.creator_user_id {
        return Err(response::AuthError::ApiKeyUnauthorized);
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
    fill_api_key(con, key_cancel, None).await
}

pub async fn send_parent_permission_email(
    mail_service: &MailService,
    target_email: &str,
    user_name: &str,
    site_external_url: &str,
    verification_challenge_key: &str,
) -> Result<(), response::AuthError> {
    let _ = mail_service
        .mail_new(mail_service_api::request::MailNewProps {
            request_id: 0,
            destination: target_email.to_owned(),
            topic: "parent_permission".to_owned(),
            title: format!("{}: Parent Permission For {}", site_external_url, user_name),
            content: [
                &format!(
          "<p>Your child, <code>{}</code>, has requested permission to use: <code>{}</code></p>",
          user_name, site_external_url
        ),
                "<p>If you did not make this request, then feel free to ignore.</p>",
                "<p>This link is valid for up to 15 minutes.</p>",
                "<p>Do not share this link with others.</p>",
                &format!(
          "<p>Verification link: {}/parent_permission_confirm?verificationChallengeKey={}</p>",
          site_external_url, verification_challenge_key
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
    site_external_url: &str,
    verification_challenge_key: &str,
) -> Result<(), response::AuthError> {
    let _ = mail_service
        .mail_new(mail_service_api::request::MailNewProps {
            request_id: 0,
            destination: target_email.to_owned(),
            topic: "verification_challenge".to_owned(),
            title: format!("{}: Email Verification", site_external_url),
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
                    site_external_url, verification_challenge_key
                ),
            ]
            .join(""),
        })
        .await
        .map_err(report_mail_err)?;
    Ok(())
}

pub async fn verification_challenge_new(
    data: Data,
    props: request::VerificationChallengeNewProps,
) -> Result<response::VerificationChallenge, response::AuthError> {
    // avoid sending email to obviously bad addresses
    if props.email.is_empty() {
        return Err(response::AuthError::EmailBounced);
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
        return Err(response::AuthError::EmailCooldown);
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
            &data.site_external_url,
            &verification_challenge_key,
        )
        .await?;
    } else {
        send_email_verification_email(
            &data.mail_service,
            &props.email,
            &user_data.realname,
            &data.site_external_url,
            &verification_challenge_key,
        )
        .await?;
    }

    // insert into database
    let verification_challenge = verification_challenge_service::add(
        con,
        utils::hash_str(&verification_challenge_key),
        props.email,
        api_key.creator_user_id,
        props.to_parent,
    )
    .await
    .map_err(report_postgres_err)?;

    // return json
    fill_verification_challenge(con, verification_challenge).await
}

pub async fn user_new(
    data: Data,
    props: request::UserNewProps,
) -> Result<response::ApiKey, response::AuthError> {
    if !utils::is_realname_valid(&props.realname) {
        return Err(response::AuthError::UserRealnameInvalid);
    }

    if !utils::is_username_valid(&props.username) {
        return Err(response::AuthError::UserUsernameInvalid);
    }

    // server side validation of password strength
    if !utils::is_secure_password(&props.password) {
        return Err(response::AuthError::PasswordInsecure);
    }

    let con = &mut *data.db.lock().await;

    let mut sp = con.transaction().await.map_err(report_postgres_err)?;

    // check username is not used
    if user_data_service::get_by_username(&mut sp, &props.username)
        .await
        .map_err(report_postgres_err)?
        .is_some()
    {
        return Err(response::AuthError::UserUsernameTaken);
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
        props.username,
        props.realname,
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
    fill_api_key(con, api_key, Some(raw_api_key)).await
}

pub async fn user_data_new(
    data: Data,
    props: request::UserDataNewProps,
) -> Result<response::UserData, response::AuthError> {
    // ensure names are valid
    if !utils::is_realname_valid(&props.realname) {
        return Err(response::AuthError::UserRealnameInvalid);
    }

    if !utils::is_username_valid(&props.username) {
        return Err(response::AuthError::UserUsernameInvalid);
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
        return Err(response::AuthError::UserUsernameTaken);
    }

    // create key data
    let user_data = user_data_service::add(
        con,
        creator_key.creator_user_id,
        props.dateofbirth,
        props.username,
        props.realname,
    )
    .await
    .map_err(report_postgres_err)?;

    // return json
    fill_user_data(con, user_data).await
}

pub async fn email_new(
    data: Data,
    props: request::EmailNewProps,
) -> Result<response::Email, response::AuthError> {
    let con = &mut *data.db.lock().await;

    let vckh = utils::hash_str(&props.verification_challenge_key);

    // check that the verification challenge exists
    let vc = verification_challenge_service::get_by_verification_challenge_key_hash(con, &vckh)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::VerificationChallengeNonexistent)?;

    // check that it hasn't timed out
    if FIFTEEN_MINUTES as i64 + vc.creation_time < utils::current_time_millis() {
        return Err(response::AuthError::VerificationChallengeTimedOut);
    }

    // check that the verification challenge is meant for the correct purpose
    if vc.to_parent != props.to_parent {
        return Err(response::AuthError::VerificationChallengeWrongKind);
    }

    // check if the verification challenge was not already used to make a new email
    if email_service::get_by_verification_challenge_key_hash(con, &vckh)
        .await
        .map_err(report_postgres_err)?
        .is_some()
    {
        return Err(response::AuthError::VerificationChallengeUsed);
    }

    // (if not parent) check that the email isn't already in use by another user
    if !vc.to_parent {
        if email_service::get_by_own_email(con, &vc.email)
            .await
            .map_err(report_postgres_err)?
            .is_some()
        {
            return Err(response::AuthError::EmailExistent);
        }
    }

    // create key data
    let email = email_service::add(con, vckh)
        .await
        .map_err(report_postgres_err)?;

    // return json
    fill_email(con, email).await
}

pub async fn password_reset_new(
    data: Data,
    props: request::PasswordResetNewProps,
) -> Result<response::PasswordReset, response::AuthError> {
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
            destination: props.email,
            topic: "password_reset".to_owned(),
            title: format!("{}: Password Reset", &data.site_external_url),
            content: [
                "<p>Requested password reset service: </p>",
                "<p>If you did not make this request, then feel free to ignore.</p>",
                "<p>This link is valid for up to 15 minutes.</p>",
                "<p>Do not share this link with others.</p>",
                &format!(
                    "<p>Password change link: {}/reset_password?resetKey={}</p>",
                    &data.site_external_url, raw_key
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
    fill_password_reset(con, password_reset).await
}

pub async fn password_new_reset(
    data: Data,
    props: request::PasswordNewResetProps,
) -> Result<response::Password, response::AuthError> {
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
        return Err(response::AuthError::PasswordExistent);
    }

    // deny if timed out
    if FIFTEEN_MINUTES as i64 + psr.creation_time < utils::current_time_millis() {
        return Err(response::AuthError::PasswordResetTimedOut);
    }

    // reject insecure passwords
    if !utils::is_secure_password(&props.new_password) {
        return Err(response::AuthError::PasswordInsecure);
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

    fill_password(con, password).await
}

pub async fn password_new_change(
    data: Data,
    props: request::PasswordNewChangeProps,
) -> Result<response::Password, response::AuthError> {
    let con = &mut *data.db.lock().await;

    // api key verification required (no parent permission needed tho)
    let creator_key = get_api_key_if_current_noverify(con, &props.api_key).await?;

    // reject insecure passwords
    if !utils::is_secure_password(&props.new_password) {
        return Err(response::AuthError::PasswordInsecure);
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
    fill_password(con, password).await
}

pub async fn user_view(
    data: Data,
    props: request::UserViewProps,
) -> Result<Vec<response::User>, response::AuthError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get users
    let users = user_service::query(con, props)
        .await
        .map_err(report_postgres_err)?;

    let mut resp_users = vec![];
    for u in users.into_iter() {
        resp_users.push(fill_user(con, u).await?);
    }

    Ok(resp_users)
}

pub async fn user_data_view(
    data: Data,
    props: request::UserDataViewProps,
) -> Result<Vec<response::UserData>, response::AuthError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get user_datas
    let user_datas = user_data_service::query(con, props)
        .await
        .map_err(report_postgres_err)?;

    let mut resp_user_datas = vec![];
    for u in user_datas.into_iter() {
        resp_user_datas.push(fill_user_data(con, u).await?);
    }

    Ok(resp_user_datas)
}

pub async fn email_view(
    data: Data,
    props: request::EmailViewProps,
) -> Result<Vec<response::Email>, response::AuthError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get emails
    let emails = email_service::query(con, props)
        .await
        .map_err(report_postgres_err)?;

    // return emails
    let mut resp_emails = vec![];
    for u in emails.into_iter() {
        resp_emails.push(fill_email(con, u).await?);
    }

    Ok(resp_emails)
}

pub async fn password_view(
    data: Data,
    props: request::PasswordViewProps,
) -> Result<Vec<response::Password>, response::AuthError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get passwords
    let passwords = password_service::query(con, props)
        .await
        .map_err(report_postgres_err)?;

    // return passwords
    let mut resp_passwords = vec![];
    for u in passwords.into_iter() {
        resp_passwords.push(fill_password(con, u).await?);
    }

    Ok(resp_passwords)
}

pub async fn api_key_view(
    data: Data,
    props: request::ApiKeyViewProps,
) -> Result<Vec<response::ApiKey>, response::AuthError> {
    let con = &mut *data.db.lock().await;
    // api key verification required
    let _ = get_api_key_if_current_noverify(con, &props.api_key).await?;
    // get users
    let api_keys = api_key_service::query(con, props)
        .await
        .map_err(report_postgres_err)?;

    // return
    let mut resp_api_keys = vec![];
    for u in api_keys.into_iter() {
        resp_api_keys.push(fill_api_key(con, u, None).await?);
    }

    Ok(resp_api_keys)
}

// special internal api
pub async fn get_user_by_id(
    data: Data,
    props: request::GetUserByIdProps,
) -> Result<response::User, response::AuthError> {
    let con = &mut *data.db.lock().await;

    let user = user_service::get_by_user_id(con, props.user_id)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::UserNonexistent)?;

    fill_user(con, user).await
}

pub async fn get_user_by_api_key_if_valid(
    data: Data,
    props: request::GetUserByApiKeyIfValid,
) -> Result<response::User, response::AuthError> {
    let con = &mut *data.db.lock().await;

    let api_key = get_api_key_if_valid(con, &props.api_key).await?;

    let user = user_service::get_by_user_id(con, api_key.creator_user_id)
        .await
        .map_err(report_postgres_err)?
        .ok_or(response::AuthError::UserNonexistent)?;

    fill_user(con, user).await
}
