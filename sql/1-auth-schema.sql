-- Table Structure
-- Primary Key
-- Creation Time
-- Creator User Id (if applicable)
-- Everything else

CREATE DATABASE auth;
\c auth;

drop table if exists user_t cascade;
create table user_t(
  user_id bigserial primary key,
  creation_time bigint not null
);

drop table if exists user_data_t cascade;
create table user_data_t(
  user_data_id bigserial primary key,
  creation_time bigint not null,
  creator_user_id bigint not null references user_t(user_id),
  dateofbirth bigint not null,
  username text not null,
  realname text not null
);

create view recent_user_data_v as
  select ud.* from user_data_t ud
  inner join (
   select max(user_data_id) id 
   from user_data_t 
   group by creator_user_id
  ) maxids
  on maxids.id = ud.user_data_id;


drop table if exists verification_challenge_t cascade;
create table verification_challenge_t(
  verification_challenge_key_hash text not null primary key,
  creation_time bigint not null,
  creator_user_id bigint not null references user_t(user_id),
  to_parent bool not null,
  email text not null
);

drop table if exists email_t cascade;
create table email_t(
  email_id bigserial primary key,
  creation_time bigint not null,
  verification_challenge_key_hash text not null references verification_challenge_t(verification_challenge_key_hash)
);

create view recent_own_email_v as
  with maxids as (
    select max(email_id) email_id 
    from email_t e
    join verification_challenge_t vc using(verification_challenge_key_hash)
    where vc.to_parent = false
    group by vc.creator_user_id
  )
  select e.* from email_t e
  inner join maxids using(email_id);


create view recent_parent_email_v as
  with maxids as (
    select max(email_id) email_id 
    from email_t e
    join verification_challenge_t vc using(verification_challenge_key_hash)
    where vc.to_parent = true
    group by vc.creator_user_id
  )
  select e.* from email_t e
  inner join maxids using(email_id);

drop table if exists password_reset_t cascade;
create table password_reset_t(
  password_reset_key_hash text not null primary key,
  creation_time bigint not null,
  creator_user_id bigint not null references user_t(user_id)
);

drop table if exists password_t cascade;
create table password_t(
  password_id bigserial primary key,
  creation_time bigint not null,
  creator_user_id bigint not null references user_t(user_id),
  password_hash text not null,
  password_reset_key_hash text references password_reset_t(password_reset_key_hash)  -- only valid if change was made by RESET
);

create view recent_password_v as
  select p.* from password_t p
  inner join (
   select max(password_id) id 
   from password_t 
   group by creator_user_id
  ) maxids
  on maxids.id = p.password_id;


drop table if exists api_key_t cascade;
create table api_key_t(
  api_key_id bigserial primary key,
  creation_time bigint not null,
  creator_user_id bigint not null references user_t(user_id),
  api_key_hash text not null,
  api_key_kind bigint not null, -- VALID, NO_EMAIL, NO_PARENT, CANCEL
  duration bigint not null -- only valid if api_key_kind == VALID
);

create view recent_api_key_v as
  select ak.* from api_key_t ak
  inner join (
    select max(api_key_id) id 
    from api_key_t 
    group by api_key_hash
  ) maxids
  on maxids.id = ak.api_key_id;

