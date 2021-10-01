-- Table Structure
-- Primary Key
-- Creation Time
-- Creator User Id (if applicable)
-- Everything else

CREATE DATABASE auth;
\c auth;

drop table if exists user_t;
create table user_t(
  user_id bigserial primary key,
  creation_time bigint not null
);

drop table if exists user_data_t;
create table user_data_t(
  user_data_id bigserial primary key,
  creation_time bigint not null,
  creator_user_id bigint not null,
  name text not null
);

create view recent_user_data_v as
  select ud.* from user_data_t ud
  inner join (
   select max(user_data_id) id 
   from user_data_t 
   group by creator_user_id
  ) maxids
  on maxids.id = ud.user_data_id;


drop table if exists verification_challenge_t;
create table verification_challenge_t(
  verification_challenge_key_hash varchar(64) not null primary key,
  creation_time bigint not null,
  creator_user_id bigint not null,
  to_parent bool not null,
  email text not null
);

drop table if exists email_t;
create table email_t(
  email_id bigserial primary key,
  creation_time bigint not null,
  creator_user_id bigint not null,
  verification_challenge_key_hash text not null
);

create view recent_email_v as
  select e.* from email_t e
  inner join (
   select max(email_id) id 
   from email_t 
   group by creator_user_id
  ) maxids
  on maxids.id = e.email_id;


drop table if exists parent_permission_t;
create table parent_permission_t(
  parent_permission_id bigserial primary key,
  creation_time bigint not null,
  user_id bigint not null,
  -- INVARIANT: if email_verification_challege field is null, then user has self authorized
  verification_challenge_key_hash text -- NULLABLE
);

create view recent_parent_permission_v as
  select pp.* from parent_permission_t pp
  inner join (
    select max(parent_permission_id) id 
    from parent_permission_t 
    group by user_id
  ) maxids
  on maxids.id = pp.parent_permission_id;

drop table if exists password_reset_t;
create table password_reset_t(
  password_reset_key_hash varchar(64) not null primary key,
  creation_time bigint not null,
  creator_user_id bigint not null
);

drop table if exists password_t;
create table password_t(
  password_id bigserial primary key,
  creation_time bigint not null,
  creator_user_id bigint not null,
  password_hash varchar(128) not null,
  password_reset_key_hash varchar(64) -- only valid if change was made by RESET
);

create view recent_password_v as
  select p.* from password_t p
  inner join (
   select max(password_id) id 
   from password_t 
   group by creator_user_id
  ) maxids
  on maxids.id = p.password_id;


drop table if exists api_key_t;
create table api_key_t(
  api_key_id bigserial primary key,
  creation_time bigint not null,
  creator_user_id bigint not null,
  api_key_hash varchar(64) not null,
  api_key_kind bigint not null, -- VALID, CANCEL
  duration bigint not null -- only valid if api_key_kind == VALID
);

create view recent_api_key_v as
  select ak.* from api_key_t ak
  inner join (
   select max(api_key_id) id 
   from api_key_t 
   group by api_key_hash
  ) maxids
  on maxids.id = p.api_key_id;

