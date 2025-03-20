#!/bin/bash

set -e

# Install sqlite3
apt-get update && apt-get install -y sqlite3 curl jq

while true
do
    # Check if the schema is ready
    if sqlite3 /var/lib/netbird/store.db "SELECT name FROM sqlite_master WHERE type='table' AND name='accounts';" | grep -q accounts; then
        echo "Database schema detected."

        # Check if the database is empty
        if [ $(sqlite3 /var/lib/netbird/store.db "SELECT COUNT(*) FROM accounts;") -eq 0 ]; then
            echo "Seeding the database..."
            sqlite3 /var/lib/netbird/store.db < /app/seed_database.sql
            echo "Database seeded successfully."
            exit 0
        else
            echo "Database already contains data, skipping seeding."
            exit 1
        fi
    else
        echo "Database schema not found. Waiting..."
    fi
done