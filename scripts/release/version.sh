# Shared version logic for the Relavia release pipeline (Step 15).
#
# Single source of truth: the repo-root VERSION file
# (MAJOR.MINOR.PATCH, optionally with a -prerelease suffix).
# RELAVIA_VERSION overrides it (used by release.sh --version).
#
# Derived values, one encoding everywhere — the same encoding the
# update manifest uses (docs/relavia-update-v1.md §2) and the
# client stamps (app/service.ClientVersionCode):
#
#   RELAVIA_VERSION        e.g. 0.1.0
#   RELAVIA_VERSION_CODE   MAJOR*10000 + MINOR*100 + PATCH  (0.1.0 -> 100)
#   RELAVIA_GOGIO_VERSION  MAJOR.MINOR.PATCH.CODE           (0.1.0 -> 0.1.0.100)
#
# Sourcing this file sets those three variables; it exits the
# caller on a malformed version (it is meant for set -e scripts).

_relavia_version_raw="${RELAVIA_VERSION:-$(tr -d '[:space:]' < "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/VERSION")}"
RELAVIA_VERSION="$_relavia_version_raw"

_relavia_triple="${RELAVIA_VERSION#v}"
_relavia_triple="${_relavia_triple%%-*}"
IFS='.' read -r _relavia_major _relavia_minor _relavia_patch <<< "$_relavia_triple"
case "$_relavia_major$_relavia_minor$_relavia_patch" in
    ''|*[!0-9]*)
        echo "release/version.sh: VERSION '$_relavia_version_raw' is not MAJOR.MINOR.PATCH" >&2
        exit 2
        ;;
esac
RELAVIA_VERSION_CODE=$((10#${_relavia_major} * 10000 + 10#${_relavia_minor} * 100 + 10#${_relavia_patch}))
RELAVIA_GOGIO_VERSION="${_relavia_major}.${_relavia_minor}.${_relavia_patch}.${RELAVIA_VERSION_CODE}"
export RELAVIA_VERSION RELAVIA_VERSION_CODE RELAVIA_GOGIO_VERSION
unset _relavia_version_raw _relavia_triple _relavia_major _relavia_minor _relavia_patch
