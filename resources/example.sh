#!/bin/bash

echo "SHELL Called with: $*"
read -sp "SHELL Password: " password

sleep 10

echo "SHELL Found password: $password"

exit 0
