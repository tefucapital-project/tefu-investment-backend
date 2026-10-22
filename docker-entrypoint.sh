#!/bin/sh
set -eu

# MongoDB has no SQL migration history. Sync indexes/collections from schema.prisma.
echo "Syncing Prisma schema to MongoDB..."
npx prisma db push --skip-generate

exec "$@"
