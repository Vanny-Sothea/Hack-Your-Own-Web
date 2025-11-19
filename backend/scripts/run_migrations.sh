#!/bin/bash
# Script to run database migrations

set -e

echo "Running database migrations..."

# Navigate to backend directory
cd "$(dirname "$0")/.."

# Run migrations
alembic upgrade head

echo "Migrations applied successfully!"
