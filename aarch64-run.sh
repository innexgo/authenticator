#!/bin/sh
./aarch64/auth-service \
  --port=8079 \
  --database-url=postgres://ubuntu:toor@localhost/auth \
  --site-external-url=critica.ucla.edu \
  --mail-service-url=http://localhost:8078
