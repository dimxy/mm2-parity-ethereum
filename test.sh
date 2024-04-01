#!/bin/sh

# Running tests
echo "Running Parity (fixed for MM2) Tests"
cargo test -p ethcore-transaction -p ethkey
