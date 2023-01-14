#!/bin/sh
exec ./aarch64/auth-service \
  --port=8079 \
  --database-url=postgres://ubuntu:toor@localhost/auth \
  --site-external-url=https://critica.eaucla.org \
  --mail-service-url=http://localhost:8078
