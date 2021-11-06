# auth-service

This service manages authentication and user registration.

## API Endpoints

-   `public/verification_challenge/new`
-   `public/api_key/new_valid`
-   `public/api_key/new_cancel`
-   `public/user/new`
-   `public/user_data/new`
-   `public/email/new`
-   `public/parent_permission/new`
-   `public/password_reset/new`
-   `public/password/new_reset`
-   `public/password/new_change`
-   `public/user/view`
-   `public/user_data/view`
-   `public/password/view`
-   `public/email/view`
-   `public/parent_permission/view`
-   `public/verification_challenge/view`
-   `public/api_key/view`
-   `get_user_by_id`
-   `get_user_by_api_key_if_valid`

# Building a production image

1. Install docker: https://docs.docker.com/get-docker/
2. In the root directory of this repository, run:
   `docker build -t auth-service .`
