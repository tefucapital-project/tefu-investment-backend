#!/bin/sh
set -eu

echo "Applying Prisma migrations..."
npx prisma migrate deploy

exec "$@"
