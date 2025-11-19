#!/bin/bash
# Script to create Alembic migration for scan tables

set -e

echo "Creating Alembic migration for scan tables..."

# Navigate to backend directory
cd "$(dirname "$0")/.."

# Generate migration
alembic revision --autogenerate -m "add scan and scan_alert tables"

echo "Migration created successfully!"
echo "Review the migration file in alembic/versions/"
echo ""
echo "To apply the migration, run:"
echo "  alembic upgrade head"
