# auth-service

This service manages authentication and user registration.

## API Endpoints

- `public/verification_challenge/new`
- `public/api_key/new_valid`
- `public/api_key/new_cancel`
- `public/user/new`
- `public/user_data/new`
- `public/email/new`
- `public/parent_permission/new`
- `public/password_reset/new`
- `public/password/new_reset`
- `public/password/new_change`
- `public/user/view`
- `public/user_data/view`
- `public/password/view`
- `public/email/view`
- `public/parent_permission/view`
- `public/verification_challenge/view`
- `public/api_key/view`
- `get_user_by_id`
- `get_user_by_api_key_if_valid`

# Building a production image

1. Install docker: https://docs.docker.com/get-docker/
2. In the root directory of this repository, run:
   `docker build -t auth-service .`

# Breakdown of Each File

### api.rs

api()
Will show all the api paths that can be called.

api_info()
Returns basic information about the api.

adapter()
Accepts an initial path filter and adapts it into a warp filter.

handle_rejection()
Handles a rejection by returning a value or passing a rejection.

auth_error()
Handles an authentication error.

### struct_service.rs

add()
Creates and adds a struct to the database.

get_by_item()
Using an item, finds the wanted struct.

query()
Finds matching structs.

### db_types.rs

This file contains the structs used for authentication.
It has User, UserData, VerificationChallenge, Email, ParentPermission, PasswordReset, Password, and ApiKey.

### handlers.rs

report_internal_error()
Reports an authentication error described as "Unkown".

report_postgres_error()
Reports an internal server error.

report_mail_err()
Reports an error with an Email.

fill_struct()
This is the format of quite a few functions. Simply fills out a struct of the given name.
For example, fill_user_data will fill out a UserData struct.

get_api_key_if_valid_noverify()
Gets an ApiKey if valid.

get_api_key_if_verified()
Gets an ApiKey while checking for parent permission.

api_key_new_valid()
Creates a new ApiKey given valid info.

api_key_new_cancel()
After authenticating, cancels ApiKeys.

send_parent_permission_email()
Sends a parent permission email.

send_email_verification_email()
Sends a email verification email.

verification_challenge_new()
Creates a new verification challenge. This process will send an email for verification.

struct_new()
Creates a filled version of a struct.

password_new_reset()
Changes password when a user needs to reset the password.

password_new_change()
Changes password when a user requests a change (user is logged in).

struct_view()
Returns all matching versions of a stuct.

get_user_by_id()
Gets a user by their id.

get_user_by_api_key_if_valid()
Gets a user by an api_key.

###main.rs

This file will connect to the database and start the api server.

###util.rs

current_time_millis()
Returns the time since creation.

gen_random_string()
Generates a random string.

hash_str()
Encodes a string through hashing.

is_secure_password()
Checks that password is secure.

verify_password()
Verifies the password.

hash_password()
Hashes a password.

log()
Logs an event.

Event
A struct describing an event.
