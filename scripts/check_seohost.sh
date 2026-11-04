#!/usr/bin/env bash
# Read-only capability probe. Run only after SSH key authorization.
# Usage: ssh ... 'bash -s' < scripts/check_seohost.sh
# No configuration/environment dumps, package installs, file writes or daemons.

set -u
set -o pipefail
# Prevent optional ffmpeg report files and Node preload hooks during versions.
# This changes only the probe process environment; no environment is printed.
unset FFREPORT NODE_OPTIONS

section() {
    printf '\n%s\n' "== $1 =="
}

command_path() {
    type -P "$1" 2>/dev/null
}

limited() {
    if command_path timeout >/dev/null; then
        timeout 10 "$@"
    else
        "$@"
    fi
}

presence() {
    local executable
    if executable=$(command_path "$1"); then
        printf '%s: %s\n' "$1" "$executable"
    else
        printf '%s: unavailable in PATH\n' "$1"
    fi
}

version_line() {
    # sed consumes the stream without showing build options or extra lines.
    limited "$@" 2>/dev/null | sed -n '1p'
}

python_seen='|'
python_found=false
probe_python() {
    local interpreter="$1"
    case "$python_seen" in
        *"|$interpreter|"*) return ;;
    esac
    python_seen="${python_seen}${interpreter}|"
    python_found=true
    printf '\nPython executable: %s\n' "$interpreter"
    # Isolated mode ignores PYTHON* environment values; -S avoids site hooks,
    # and -B prevents bytecode writes. No user or application modules load.
    if ! limited "$interpreter" -I -B -S - 2>/dev/null <<'PY'
import importlib.util
import sys

print("version:", sys.version.split()[0])
print("AO Python 3.12 requirement:", "met" if sys.version_info[:2] == (3, 12) else "requires review")
for name in ("venv", "ensurepip"):
    print(name + ":", "available" if importlib.util.find_spec(name) else "unavailable")
try:
    import ssl
    print("SSL:", ssl.OPENSSL_VERSION)
except Exception:
    print("SSL: unavailable")
try:
    import sqlite3
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("SELECT 1").fetchone()
        print("SQLite:", sqlite3.sqlite_version, "(in-memory query OK)")
    finally:
        connection.close()
except Exception:
    print("SQLite: unavailable or in-memory query failed")
PY
    then
        printf '%s\n' 'Isolated Python 3 probe unavailable; interpreter may be older or restricted.'
        version_line "$interpreter" --version || true
    fi
}

printf '%s\n' 'AO / SEOHOST read-only capability report'
printf '%s\n' 'No application started, packages installed, files changed or secrets printed.'
printf '%s\n' 'CLI presence does not establish account entitlement, ASGI support or hosting policy.'

section 'System visible to this account'
if command_path uname >/dev/null; then
    uname -s -r 2>/dev/null || true
fi
if command_path date >/dev/null; then
    date -u '+UTC: %Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true
fi

section 'Python interpreters and standard libraries'
for python_command in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3 python; do
    if python_path=$(command_path "$python_command"); then
        probe_python "$python_path"
    fi
done
# Fixed CloudLinux locations only; do not scan user directories or configs.
for python_minor in 9 10 11 12 13 14; do
    for python_path in "/opt/alt/python3${python_minor}/bin/python3" "/opt/alt/python3${python_minor}/bin/python3.${python_minor}"; do
        if [[ -x "$python_path" && -f "$python_path" ]]; then
            probe_python "$python_path"
        fi
    done
done
if [[ "$python_found" == false ]]; then
    printf '%s\n' 'No interpreter found in PATH or checked fixed CloudLinux locations.'
fi

section 'Media tools'
for media_command in ffmpeg ffprobe; do
    if media_path=$(command_path "$media_command"); then
        printf '%s: %s\n' "$media_command" "$media_path"
        version_line "$media_path" -version || true
    else
        printf '%s: unavailable in PATH\n' "$media_command"
    fi
done

section 'Application manager and Node.js indicators (presence only)'
for selector_command in passenger-config passenger-status cloudlinux-selector selectorctl node npm; do
    presence "$selector_command"
done
for selector_path in /usr/bin/cloudlinux-selector /usr/bin/selectorctl /usr/sbin/cloudlinux-selector /usr/local/bin/passenger-config /usr/share/cloudlinux-selector; do
    if [[ -e "$selector_path" && -r "$selector_path" ]]; then
        printf 'Fixed selector path exists: %s\n' "$selector_path"
    fi
done
if node_path=$(command_path node); then
    version_line "$node_path" --version || true
fi
printf '%s\n' 'Check DirectAdmin separately for Python App / Python Selector and Node.js App.'
printf '%s\n' 'WSGI/Passenger or Node.js availability alone does not confirm FastAPI ASGI support.'

section 'Cron availability (existing schedule contents are suppressed)'
if cron_path=$(command_path crontab); then
    printf 'crontab: %s\n' "$cron_path"
    if limited "$cron_path" -l >/dev/null 2>&1; then
        printf '%s\n' 'Existing user crontab is readable; contents were not printed.'
    else
        cron_result=$?
        printf 'crontab read returned %s; no table, restriction or other failure remain possible.\n' "$cron_result"
    fi
else
    printf '%s\n' 'crontab: unavailable in PATH; DirectAdmin scheduler may still exist.'
fi
printf '%s\n' 'No cron entry created. Frequency and execution-time limits require panel/provider confirmation.'

section 'PHP / WP-CLI'
if php_path=$(command_path php); then
    printf 'php: %s\n' "$php_path"
    # -n bypasses php.ini and prevents loading configured application hooks.
    version_line "$php_path" -n -v || true
else
    printf '%s\n' 'php: unavailable in PATH'
fi
# Do not invoke wp: its project configuration can load user PHP code.
presence wp
printf '%s\n' 'WP-CLI was not executed; no WordPress project or credentials were opened.'

section 'Visible limits (not authoritative CloudLinux SH3 quotas)'
for limit_name in open_files processes virtual_memory_kib cpu_seconds file_size_blocks; do
    case "$limit_name" in
        open_files) limit_flag=-Sn ;;
        processes) limit_flag=-Su ;;
        virtual_memory_kib) limit_flag=-Sv ;;
        cpu_seconds) limit_flag=-St ;;
        file_size_blocks) limit_flag=-Sf ;;
    esac
    if limit_value=$(ulimit "$limit_flag" 2>/dev/null); then
        printf '%s: %s\n' "$limit_name" "$limit_value"
    else
        printf '%s: unavailable\n' "$limit_name"
    fi
done
if getconf_path=$(command_path getconf); then
    printf 'Visible online CPUs (may be host-wide): '
    limited "$getconf_path" _NPROCESSORS_ONLN 2>/dev/null || true
fi
if df_path=$(command_path df); then
    printf '%s\n' 'Filesystem capacity for current directory (may be shared, not the account quota):'
    limited "$df_path" -Pk . 2>/dev/null || true
fi
presence quota
printf '%s\n' 'Confirm account disk quota and CloudLinux PMEM/SPEED/IO/EP/NPROC in DirectAdmin.'

section 'Still requires verification'
printf '%s\n' \
    'Python package installation rights and supported application startup method.' \
    'ASGI routing, process lifetime/restarts, HTTPS callbacks and signed media access.' \
    'ffmpeg execution policy, RAM/CPU/time budgets and durable local SQLite storage.' \
    'Cron minimum interval and maximum execution time.' \
    'This report does not prove successful AO deployment or platform publishing.'
