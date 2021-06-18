# We use glibc rust for dev purposes
# to set the environment to build our binary
FROM rust:1.50

# for dev version, build quickly
# the docker-compose should include the cache directories so that
# building is fast
RUN cargo build

COPY target/debug/auth-service "/bin/auth-service"

CMD ["/bin/auth-service"]
