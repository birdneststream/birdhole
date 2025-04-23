#!/bin/sh
# Entrypoint script to fix volume permissions and run the main command

# Set ownership of the database directory to the app user/group
# This ensures the non-root user can write to the mounted volume
# Paths must match Dockerfile WORKDIR and volume mount target
echo "Fixing ownership for /app/birdhole.db..."
chown -R appuser:appgroup /app/birdhole.db || echo "Failed to chown /app/birdhole.db (might not be critical if permissions already ok)"

# Execute the command passed to the entrypoint (e.g., the CMD from Dockerfile)
# Use gosu or su-exec to run the command as the non-root user
# First, install su-exec (simpler than gosu)
# apk add --no-cache 'su-exec>=0.2' # Add this to Dockerfile RUN apk add... line

echo "Executing command as appuser: $@"
# exec su-exec appuser "$@" # Use this line

# Simpler alternative if the USER directive in Dockerfile works *after* entrypoint
# (Depends on Docker version/behavior - let's try this first)
# exec "$@" # Remove this line
exec su-exec appuser "$@" 