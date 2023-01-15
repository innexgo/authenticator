#!/bin/bash
./target/debug/authenticator \
  --port=8079 \
  --database-url=postgres://postgres:toor@localhost/authenticator \
  --app-pub-origin=http://localhost:2999 \
  --mail-service-url=http://localhost:8078 \
  --permitted-origins=http://localhost:3000
