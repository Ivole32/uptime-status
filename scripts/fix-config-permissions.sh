#!/bin/sh
# Make config/admin.toml readable for the container, and for nobody else.
#
# The app runs as UID/GID 10001 inside the container. Which host user that is
# depends on Docker: without user-namespace remapping it is 10001, with
# userns-remap it is shifted (e.g. 110001). This script asks Docker for the
# real mapping, then sets owner and modes accordingly and checks the result.
#
# Usage (from anywhere, as root):  sudo scripts/fix-config-permissions.sh
set -eu

APP_ID=10001
cd "$(dirname "$0")/.."

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this as root, e.g. sudo $0" >&2
    exit 1
fi
if [ ! -f config/admin.toml ]; then
    echo "config/admin.toml does not exist yet. Create it first (see README, Quick start)." >&2
    exit 1
fi
if docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q rootless; then
    echo "Rootless Docker is not supported by this script. Make config/ and config/admin.toml" >&2
    echo "readable for container UID $APP_ID as mapped by your rootless setup." >&2
    exit 1
fi

# Runs a throwaway container of this project (building the image if needed) and
# prints its view of the ID mapping: "inside outside count" per line.
in_container() {
    docker compose run --rm --no-deps -T --entrypoint "$1" uptime "$2" 2>/dev/null
}

host_id() {
    awk -v id="$APP_ID" '$1 <= id && id < $1 + $3 { print $2 + id - $1; found = 1; exit }
                        END { if (!found) exit 1 }'
}

uid=$(in_container cat /proc/self/uid_map | host_id) || {
    echo "Could not determine the host UID of container UID $APP_ID." >&2
    exit 1
}
gid=$(in_container cat /proc/self/gid_map | host_id) || {
    echo "Could not determine the host GID of container GID $APP_ID." >&2
    exit 1
}

chown "$uid:$gid" config config/admin.toml
chmod 0500 config
chmod 0400 config/admin.toml

if [ "$uid" -eq "$APP_ID" ]; then
    echo "config/ is now owned by UID $uid (no user-namespace remapping)."
else
    echo "config/ is now owned by host UID $uid, which is UID $APP_ID inside the container"
    echo "(Docker user-namespace remapping is active)."
fi

if docker compose run --rm --no-deps -T --entrypoint python uptime \
    -c "open('/config/admin.toml', 'rb').read(1)" >/dev/null 2>&1; then
    echo "Verified: the container can read config/admin.toml."
else
    echo "The container still cannot read config/admin.toml. Check for SELinux or AppArmor" >&2
    echo "restrictions on the config directory." >&2
    exit 1
fi
