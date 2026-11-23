#!/usr/bin/env bash
# -------------------------------------------------------------------------
# DMARC plugin for GLPI — installer
# Copyright (C) 2026 Yaco Melian — GPLv2+
# https://github.com/yacomelian/glpi-plugin-dmarc
# -------------------------------------------------------------------------
#
#   curl -fsSL https://raw.githubusercontent.com/yacomelian/glpi-plugin-dmarc/main/install.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/yacomelian/glpi-plugin-dmarc/main/install.sh | bash -s -- --path /var/www/glpi --yes
#
# Asks for the GLPI folder, checks that it is GLPI 11 or 12, downloads the
# release (and checks its SHA-256), keeps a backup of a previous version,
# installs it with the owner of the GLPI files and runs the plugin install.
# Run it on the GLPI server, as root or as the user that owns GLPI.
set -euo pipefail

REPO="${DMARC_REPO:-yacomelian/glpi-plugin-dmarc}"
PLUGIN="dmarc"
GLPI_PATH=""
VERSION=""
ARCHIVE=""
CONTAINER=""
ENGINE=""
ACTIVATE=1
ASSUME_YES=0

usage() {
    cat <<EOF
Installs or updates the DMARC plugin for GLPI 11/12.

Usage: install.sh [options]

  --path DIR        GLPI folder (asked if not given). With --container, the folder inside the container.
  --version X.Y.Z   Version to install (default: the latest release).
  --archive FILE    Install from a local glpi-dmarc-X.Y.Z.tar.gz (or .tar.bz2) instead of downloading it.
  --container NAME  GLPI runs in this Docker/Podman container.
  --no-activate     Install the files and the plugin, but do not activate it.
  --yes             Do not ask for confirmation.
  --repo OWNER/NAME GitHub repository (default: ${REPO}).
  -h, --help        This help.
EOF
}

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mError:\033[0m %s\n' "$*" >&2; exit 1; }

# Questions are read from the terminal, also when the script comes from "curl | bash".
ask() {
    local prompt="$1" default="${2:-}" answer=""
    if ! { true < /dev/tty; } 2> /dev/null; then
        [ -n "$default" ] || die "No terminal to ask \"$prompt\": use the command-line options (see --help)."
        printf '%s\n' "$default"
        return
    fi
    if [ -n "$default" ]; then
        printf '%s [%s]: ' "$prompt" "$default" > /dev/tty
    else
        printf '%s: ' "$prompt" > /dev/tty
    fi
    IFS= read -r answer < /dev/tty || true
    printf '%s\n' "${answer:-$default}"
}

confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    local a
    a="$(ask "$1 (y/N)" "n")"
    case "$a" in y|Y|yes|YES|s|S|si|SI|sí) return 0 ;; *) return 1 ;; esac
}

while [ $# -gt 0 ]; do
    case "$1" in
        --path) GLPI_PATH="${2:-}"; shift 2 ;;
        --version) VERSION="${2:-}"; shift 2 ;;
        --archive) ARCHIVE="${2:-}"; shift 2 ;;
        --container) CONTAINER="${2:-}"; shift 2 ;;
        --no-activate) ACTIVATE=0; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --repo) REPO="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "Unknown option: $1" ;;
    esac
done

case "$REPO" in */*) ;; *) die "Invalid --repo: $REPO" ;; esac
if [ -n "$VERSION" ] && ! printf '%s' "$VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$'; then
    die "Invalid version: $VERSION"
fi

# --- where GLPI runs: here, or in a container ---------------------------------
if [ -n "$CONTAINER" ]; then
    for e in docker podman; do
        if command -v "$e" > /dev/null 2>&1 && "$e" inspect "$CONTAINER" > /dev/null 2>&1; then
            ENGINE="$e"
            break
        fi
    done
    [ -n "$ENGINE" ] || die "Container \"$CONTAINER\" not found with docker or podman."
fi

# run a command where GLPI is (as root there)
on_glpi() {
    if [ -n "$CONTAINER" ]; then
        "$ENGINE" exec -u 0 "$CONTAINER" sh -c "$1"
    else
        sh -c "$1"
    fi
}

# run a GLPI console command as the owner of the GLPI files
console() {
    local cmd="cd '$GLPI_PATH' && php bin/console $*"
    if [ -n "$CONTAINER" ]; then
        "$ENGINE" exec -u "$OWNER" "$CONTAINER" sh -c "$cmd"
    elif [ "$(id -u)" = 0 ] && [ "$OWNER_USER" != root ]; then
        if command -v runuser > /dev/null 2>&1; then
            runuser -u "$OWNER_USER" -- sh -c "$cmd"
        elif command -v sudo > /dev/null 2>&1; then
            sudo -u "$OWNER_USER" sh -c "$cmd"
        else
            su -s /bin/sh "$OWNER_USER" -c "$cmd"
        fi
    else
        sh -c "$cmd"
    fi
}

is_glpi() {
    on_glpi "test -f '$1/bin/console' && test -d '$1/plugins' && { test -f '$1/src/autoload/constants.php' || test -f '$1/inc/define.php'; }" > /dev/null 2>&1
}

# --- the GLPI folder ----------------------------------------------------------
if [ -z "$GLPI_PATH" ]; then
    suggestion=""
    for d in /var/www/glpi /var/www/html/glpi /var/www/html /usr/share/glpi /srv/www/glpi /opt/glpi; do
        if is_glpi "$d"; then
            suggestion="$d"
            break
        fi
    done
    GLPI_PATH="$(ask "GLPI folder" "$suggestion")"
fi
GLPI_PATH="${GLPI_PATH%/}"
[ -n "$GLPI_PATH" ] || die "No GLPI folder given."
case "$GLPI_PATH" in /*) ;; *) die "The GLPI folder must be an absolute path: $GLPI_PATH" ;; esac
case "$GLPI_PATH" in *"'"*|*'"'*|*'$'*|*'`'*) die "Unsupported characters in the GLPI folder." ;; esac
is_glpi "$GLPI_PATH" || die "$GLPI_PATH does not look like GLPI (bin/console, plugins/ and src/autoload/constants.php are expected)."

# GLPI 11+: src/autoload/constants.php (older: inc/define.php)
GLPI_VERSION="$(on_glpi "cat '$GLPI_PATH/src/autoload/constants.php' '$GLPI_PATH/inc/define.php' 2>/dev/null"     | sed -nE "s/.*define\('GLPI_VERSION', *'([^']+)'.*/\1/p" | head -n1 || true)"
[ -n "$GLPI_VERSION" ] || die "Cannot read the GLPI version in $GLPI_PATH."
case "$GLPI_VERSION" in
    11.*|12.*) ;;
    *) die "GLPI $GLPI_VERSION is not supported: this plugin needs GLPI 11 or 12." ;;
esac

PHP_CHECK="$(on_glpi "php -r 'echo PHP_VERSION, \"|\", implode(\",\", array_filter([\"openssl\",\"zlib\",\"zip\",\"curl\",\"mbstring\",\"simplexml\"], fn(\$e) => !extension_loaded(\$e)));'" 2>/dev/null || true)"
[ -n "$PHP_CHECK" ] || die "PHP (CLI) is not available where GLPI runs."
PHP_VERSION="${PHP_CHECK%%|*}"
PHP_MISSING="${PHP_CHECK#*|}"
on_glpi "php -r 'exit(version_compare(PHP_VERSION, \"8.2.0\", \">=\") ? 0 : 1);'" || die "PHP $PHP_VERSION is too old: 8.2 or newer is needed."
[ -z "$PHP_MISSING" ] || die "Missing PHP extensions: $PHP_MISSING"

OWNER="$(on_glpi "stat -c '%U:%G' '$GLPI_PATH/plugins'")"
OWNER_USER="${OWNER%%:*}"
if [ "$OWNER_USER" = root ]; then
    OWNER="$(on_glpi "stat -c '%U:%G' '$GLPI_PATH/files' 2>/dev/null || stat -c '%U:%G' '$GLPI_PATH/plugins'")"
    OWNER_USER="${OWNER%%:*}"
fi
if [ -z "$CONTAINER" ] && [ "$(id -u)" != 0 ] && [ "$(id -un)" != "$OWNER_USER" ]; then
    die "Run this as root or as $OWNER_USER (the owner of $GLPI_PATH/plugins)."
fi

# existing copy (plugins/ or marketplace/)
TARGET_DIR="$GLPI_PATH/plugins"
CURRENT=""
for base in "$GLPI_PATH/plugins" "$GLPI_PATH/marketplace"; do
    if on_glpi "test -f '$base/$PLUGIN/setup.php'" 2>/dev/null; then
        TARGET_DIR="$base"
        CURRENT="$(on_glpi "grep -Eo \"PLUGIN_DMARC_VERSION', *'[^']+\" '$base/$PLUGIN/setup.php' | grep -Eo \"[0-9][^']*\$\"" 2>/dev/null || true)"
        break
    fi
done

# --- the release --------------------------------------------------------------
command -v tar > /dev/null 2>&1 || die "tar is needed."
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ -n "$ARCHIVE" ]; then
    [ -f "$ARCHIVE" ] || die "Archive not found: $ARCHIVE"
    cp "$ARCHIVE" "$WORK/plugin.tar"
    [ -n "$VERSION" ] || VERSION="$(basename "$ARCHIVE" | sed -nE 's/^glpi-dmarc-([0-9][^/]*)\.tar\.(gz|bz2)$/\1/p')"
    [ -n "$VERSION" ] || VERSION="(local archive)"
    if [ -f "$ARCHIVE.sha256" ]; then
        EXPECTED="$(awk '{print $1}' "$ARCHIVE.sha256")"
        ACTUAL="$(sha256sum "$WORK/plugin.tar" | awk '{print $1}')"
        [ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || die "SHA-256 check failed for $ARCHIVE."
    else
        warn "No $ARCHIVE.sha256 next to the archive: integrity not checked."
    fi
else
    command -v curl > /dev/null 2>&1 || die "curl is needed to download the plugin (or use --archive)."
    if [ -z "$VERSION" ]; then
        say "Looking for the latest release of $REPO"
        VERSION="$(curl -fsSL -H 'Accept: application/vnd.github+json' "https://api.github.com/repos/$REPO/releases/latest" \
            | grep -Eo '"tag_name": *"[^"]+"' | head -n1 | sed -E 's/.*"([^"]+)"$/\1/; s/^v//')" || true
        [ -n "$VERSION" ] || die "Cannot find the latest release of $REPO (no Internet access? use --archive)."
    fi
    BASE_URL="https://github.com/$REPO/releases/download/$VERSION"
    FILE="glpi-dmarc-$VERSION.tar.gz"
    say "Downloading $FILE"
    curl -fsSL -o "$WORK/plugin.tar" "$BASE_URL/$FILE" || die "Download failed: $BASE_URL/$FILE"
    curl -fsSL -o "$WORK/plugin.sha256" "$BASE_URL/$FILE.sha256" || die "Download failed: $BASE_URL/$FILE.sha256"
    EXPECTED="$(awk '{print $1}' "$WORK/plugin.sha256")"
    ACTUAL="$(sha256sum "$WORK/plugin.tar" | awk '{print $1}')"
    [ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ] || die "SHA-256 check failed for $FILE."
fi

mkdir -p "$WORK/x"
tar -xf "$WORK/plugin.tar" -C "$WORK/x" || die "Cannot extract the archive (a .tar.bz2 needs bzip2; the .tar.gz does not)."
[ -f "$WORK/x/$PLUGIN/setup.php" ] || die "The archive does not contain $PLUGIN/setup.php."
if find "$WORK/x" -type l | grep -q .; then
    die "The archive contains symbolic links: refused."
fi

# --- summary and confirmation ---------------------------------------------------
echo
echo "  GLPI          $GLPI_PATH ($GLPI_VERSION, PHP $PHP_VERSION)${CONTAINER:+ in container $CONTAINER}"
echo "  Plugin        DMARC $VERSION -> $TARGET_DIR/$PLUGIN"
[ -n "$CURRENT" ] && echo "  Installed     $CURRENT (a backup is kept)"
echo "  Owner         $OWNER"
echo
confirm "Install?" || die "Cancelled."

# --- backup of the previous version -------------------------------------------------
STAMP="$(date +%Y%m%d-%H%M%S)"
if [ -n "$CURRENT" ]; then
    BACKUP_DIR="/var/backups/glpi-dmarc"
    mkdir -p "$BACKUP_DIR" 2> /dev/null || BACKUP_DIR="${HOME:-/tmp}/glpi-dmarc-backups"
    mkdir -p "$BACKUP_DIR"
    BACKUP="$BACKUP_DIR/dmarc-$CURRENT-$STAMP.tar.gz"
    if [ -n "$CONTAINER" ]; then
        "$ENGINE" exec -u 0 "$CONTAINER" tar -czf - -C "$TARGET_DIR" "$PLUGIN" > "$BACKUP"
    else
        tar -czf "$BACKUP" -C "$TARGET_DIR" "$PLUGIN"
    fi
    say "Backup of the installed version: $BACKUP"
fi

# --- copy -------------------------------------------------------------------------
NEW="$TARGET_DIR/.$PLUGIN-new-$STAMP"
OLD="$TARGET_DIR/.$PLUGIN-old-$STAMP"
if [ -n "$CONTAINER" ]; then
    "$ENGINE" exec -u 0 "$CONTAINER" rm -rf "$NEW"
    "$ENGINE" cp "$WORK/x/$PLUGIN" "$CONTAINER:$NEW"
else
    cp -R "$WORK/x/$PLUGIN" "$NEW"
fi
on_glpi "chown -R '$OWNER' '$NEW' && find '$NEW' -type d -exec chmod 755 {} + && find '$NEW' -type f -exec chmod 644 {} +"
on_glpi "if [ -e '$TARGET_DIR/$PLUGIN' ]; then mv '$TARGET_DIR/$PLUGIN' '$OLD'; fi && mv '$NEW' '$TARGET_DIR/$PLUGIN' && rm -rf '$OLD'"
say "Files copied to $TARGET_DIR/$PLUGIN"

# --- install / update in GLPI -------------------------------------------------------------
say "Installing the plugin in GLPI"
# GLPI 11: glpi:plugin:*, GLPI 12: plugin:*
PCMD="glpi:plugin"
if console "list plugin --raw" 2> /dev/null | grep -q '^plugin:install'; then
    PCMD="plugin"
fi

# installs, or updates the database when the version changed ("already installed" is fine)
OUT="$(console "$PCMD:install $PLUGIN --username=glpi --no-interaction" 2>&1)" || {
    case "$OUT" in
        *"already installed"*) ;;
        *) printf '%s\n' "$OUT" >&2; die "$PCMD:install failed. Install it from Setup > Plugins." ;;
    esac
}
if [ "$ACTIVATE" = 1 ]; then
    OUT="$(console "$PCMD:activate $PLUGIN --no-interaction" 2>&1)" || {
        case "$OUT" in
            *"already active"*) ;;
            *) printf '%s\n' "$OUT" >&2; die "$PCMD:activate failed. Activate it from Setup > Plugins." ;;
        esac
    }
fi
console "cache:clear --no-interaction" > /dev/null 2>&1 || warn "cache:clear failed; clear GLPI's cache if the pages look outdated."

echo
if [ "$ACTIVATE" = 1 ]; then say "DMARC $VERSION installed and activated."; else say "DMARC $VERSION installed (not activated)."; fi
echo "    Next: Setup > Plugins > DMARC to configure the mailbox, and Administration > Profiles > DMARC"
echo "    to give the right to other profiles. Tools > DMARC shows the dashboard."
