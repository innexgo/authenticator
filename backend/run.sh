#!/bin/bash
./target/debug/auth-service \
  --port=8079 \
  --database-url=postgres://postgres:toor@localhost/auth \
  --site-external-url=http://localhost:2999 \
  --mail-service-url=http://localhost:8078 \
  --permitted-sources=localhost:3000
