#!/usr/bin/env bash
set -euo pipefail

# Lightweight SSH hardening helper (single-file bash)
# - Interactive SSH public key input (no hard-coded keys)
# - Enables public key auth, disables password auth
# - Changes SSH port to a high port (default: 54271)
# - Detects Debian/Ubuntu vs Alpine vs CentOS/RHEL families for service restart
#
# Must be run as root on Linux.

DEFAULT_PORT="54271"
SSHD_CONFIG_DEFAULT="/etc/ssh/sshd_config"
SSH_SELFTEST_TIMEOUT=5

die() {
  echo "ERROR: $*" >&2
  exit 1
}

maybe_warn() {
  echo "WARN: $*" >&2
}

run_restorecon() {
  # Best-effort SELinux context restore
  if command -v restorecon >/dev/null 2>&1; then
    restorecon "$@" 2>/dev/null || true
  fi
}

join_unique_ports() {
  # Usage: join_unique_ports new_port "p1 p2 ..."
  local new_port="$1"; shift
  local ports_str="$1"; shift || true
  local out=() seen
  seen=" $new_port "
  out+=("$new_port")
  for p in $ports_str; do
    [ -z "$p" ] && continue
    if [ "$p" = "$new_port" ]; then
      continue
    fi
    if echo "$seen" | grep -q " $p "; then
      continue
    fi
    seen="$seen$p "
    out+=("$p")
  done
  echo "${out[*]}"
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "Please run as root (e.g., via sudo)."
  fi
}

require_linux() {
  # Very small check: /etc is expected. (This script targets Linux servers.)
  [ -d /etc ] || die "This script must be run on a Linux system."
}

read_os_release_field() {
  # Usage: read_os_release_field ID
  local key="$1"
  [ -r /etc/os-release ] || return 0
  awk -F= -v k="$key" '
    $1==k {
      v=$2
      gsub(/^"/, "", v); gsub(/"$/, "", v)
      gsub(/^'\''/, "", v); gsub(/'\''$/, "", v)
      print v
      exit
    }
  ' /etc/os-release
}

detect_family() {
  local id id_like
  id="$(read_os_release_field ID | tr '[:upper:]' '[:lower:]')"
  id_like="$(read_os_release_field ID_LIKE | tr '[:upper:]' '[:lower:]')"

  if echo " $id $id_like " | grep -Eq ' (debian|ubuntu|linuxmint|raspbian) '; then
    echo "debian"
  elif echo " $id $id_like " | grep -Eq ' alpine '; then
    echo "alpine"
  elif echo " $id $id_like " | grep -Eq ' (rhel|centos|fedora|rocky|almalinux|ol) '; then
    echo "rhel"
  else
    echo "unknown"
  fi
}

user_home_dir() {
  # Usage: user_home_dir username
  local u="$1"
  if command -v getent >/dev/null 2>&1; then
    getent passwd "$u" | awk -F: '{print $6}'
  else
    awk -F: -v u="$u" '$1==u {print $6; exit}' /etc/passwd
  fi
}

choose_target_user() {
  local default username
  default="${SUDO_USER:-root}"
  if [ "$default" = "" ]; then default="root"; fi
  read -r -p "Target username [${default}]: " username || true
  username="${username:-$default}"
  validate_username "$username"
  echo "$username"
}

validate_username() {
  local username="$1"
  local home
  echo "$username" | grep -Eq '^[a-z_][a-z0-9_-]*$' || die "Invalid username format: $username"
  home="$(user_home_dir "$username")"
  [ -n "$home" ] || die "User not found or has no home directory: $username"
  [ -d "$home" ] || die "Home directory does not exist: $home"
}

ensure_ssh_paths() {
  # Usage: ensure_ssh_paths username
  local username="$1"
  local home ssh_dir key_file
  home="$(user_home_dir "$username")"
  [ -n "$home" ] || die "Could not determine home directory for user: $username"

  ssh_dir="$home/.ssh"
  key_file="$ssh_dir/authorized_keys"

  mkdir -p "$ssh_dir"
  chmod 700 "$ssh_dir"
  touch "$key_file"
  chmod 600 "$key_file"

  # Best effort ownership fix
  if command -v chown >/dev/null 2>&1; then
    if ! chown "$username":"$username" "$ssh_dir" "$key_file" 2>/dev/null; then
      maybe_warn "Failed to set ownership on $ssh_dir and $key_file"
    fi
  fi

  run_restorecon "$ssh_dir" "$key_file"
  echo "$key_file"
}

extract_ports() {
  # Usage: extract_ports /etc/ssh/sshd_config
  # Returns a space-separated list of active Port directives (defaults to 22 if none)
  local cfg="$1"
  local ports
  ports=$(awk '
    BEGIN { IGNORECASE=1 }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*Port[[:space:]]+/ { print $2 }
  ' "$cfg" | tr '\n' ' ')
  if [ -z "$ports" ]; then
    echo "22"
  else
    echo "$ports"
  fi
}

is_valid_key_line() {
  # Accept:
  # - empty lines
  # - comments
  # - "<keytype> <base64> [comment]"
  # - "<options> <keytype> <base64> [comment]"
  local line="$1"
  local s
  s="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  [ -z "$s" ] && return 0
  echo "$s" | grep -Eq '^[#]' && return 0

  echo "$s" | grep -Eq '^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+' && return 0
  echo "$s" | grep -Eq '^[^[:space:]]+[[:space:]]+(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)[[:space:]]+[A-Za-z0-9+/=]+' && return 0
  return 1
}

clean_authorized_keys() {
  # Usage: clean_authorized_keys /path/to/authorized_keys
  local key_file="$1"
  local backup
  backup="${key_file}.bak.$(date +%Y%m%d-%H%M%S)"
  cp "$key_file" "$backup"
  chmod 600 "$backup"

  # Use awk to preserve original newlines and comment out invalid lines.
  awk '
    function ltrim(s) { sub(/^[ \t\r\n]+/, "", s); return s }
    {
      line=$0
      trimmed=line
      gsub(/^[ \t]+/, "", trimmed)
      gsub(/[ \t]+$/, "", trimmed)
      if (trimmed=="" || trimmed ~ /^#/) { print line; next }
      # Accept common key types at field 1 or field 2 (after options token).
      if ($1 ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/) { print line; next }
      if ($2 ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/) { print line; next }
      print "# " line " # Invalid Key Format"
    }
  ' "$backup" > "$key_file"

  chmod 600 "$key_file"
  run_restorecon "$key_file"
  echo "Commented out invalid lines in authorized_keys (backup: $backup)."
}

add_key_if_missing() {
  # Usage: add_key_if_missing /path/to/authorized_keys "ssh-ed25519 AAAA... comment"
  local key_file="$1"
  local key="$2"
  if grep -qxF "$key" "$key_file"; then
    echo "Key already present: ${key:0:40}..."
  else
    echo "$key" >> "$key_file"
    echo "Added key: ${key:0:40}..."
  fi
}

read_keys_interactive() {
  echo "Paste SSH public keys, one per line. Press Enter on an empty line to finish."
  while true; do
    local line=""
    # shellcheck disable=SC2162
    read -r -p "> " line || true
    line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [ -z "$line" ]; then
      break
    fi
    if ! is_valid_key_line "$line"; then
      echo "That does not look like a valid SSH public key line. Try again." >&2
      continue
    fi
    echo "$line"
  done
}

make_backup() {
  # Usage: make_backup /etc/ssh/sshd_config
  local cfg="$1"
  local backup="${cfg}.bak.$(date +%Y%m%d-%H%M%S)"
  cp "$cfg" "$backup"
  chmod 600 "$backup"
  echo "$backup"
}

write_sshd_config() {
  # Usage: write_sshd_config mode cfg new_port "orig_ports"
  # mode: warmup | final
  local mode="$1"
  local cfg="$2"
  local new_port="$3"
  local orig_ports="$4"
  [ -w "$cfg" ] || die "Cannot write to $cfg. Please run as root."

  local tmp ports
  tmp="$(mktemp)"
  chmod 600 "$tmp"

  awk '
    BEGIN { IGNORECASE=1 }
    $0 ~ /^[[:space:]]*#?[[:space:]]*(PubkeyAuthentication|PasswordAuthentication|Port)[[:space:]]+/ { next }
    { print }
  ' "$cfg" > "$tmp"

  ports="$(join_unique_ports "$new_port" "$orig_ports")"

  {
    echo ""
    if [ "$mode" = "warmup" ]; then
      echo "# Managed by ssh-key helper (warmup stage)"
    else
      echo "# Managed by ssh-key helper"
    fi
    echo "PubkeyAuthentication yes"
    if [ "$mode" = "warmup" ]; then
      echo "PasswordAuthentication yes"
      for p in $ports; do
        echo "Port ${p}"
      done
    else
      echo "PasswordAuthentication no"
      echo "Port ${new_port}"
    fi
  } >> "$tmp"

  cat "$tmp" > "$cfg"
  rm -f "$tmp"
  run_restorecon "$cfg"
}

validate_sshd_config() {
  # Usage: validate_sshd_config /etc/ssh/sshd_config
  local cfg="$1"
  command -v sshd >/dev/null 2>&1 || die "sshd binary not found; cannot validate configuration."
  if sshd -t -f "$cfg" >/dev/null 2>&1; then
    echo "sshd config validation passed (sshd -t)."
    return 0
  else
    echo "sshd config validation failed (sshd -t)." >&2
    return 1
  fi
}

restart_ssh() {
  # Usage: restart_ssh family
  local family="$1"
  local services=()
  case "$family" in
    debian) services=(ssh sshd) ;;
    alpine|rhel) services=(sshd ssh) ;;
    *) services=(ssh sshd) ;;
  esac

  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    for svc in "${services[@]}"; do
      if systemctl restart "$svc" >/dev/null 2>&1; then
        echo "Restarted SSH service using systemd: systemctl restart $svc"
        return 0
      fi
    done
  fi

  if command -v service >/dev/null 2>&1; then
    for svc in "${services[@]}"; do
      if service "$svc" restart >/dev/null 2>&1; then
        echo "Restarted SSH service using service: service $svc restart"
        return 0
      fi
    done
  fi

  if command -v rc-service >/dev/null 2>&1; then
    for svc in "${services[@]}"; do
      if rc-service "$svc" restart >/dev/null 2>&1; then
        echo "Restarted SSH service using openrc: rc-service $svc restart"
        return 0
      fi
    done
  fi

  die "Failed to restart SSH service automatically. Please restart it manually."
}

ssh_self_test() {
  # Usage: ssh_self_test port username
  # Returns: 0 on success, 1 on failure
  # Outputs diagnostic info to stderr on failure
  local port="$1"
  local user="$2"
  local exit_code ssh_output

  if ! command -v ssh >/dev/null 2>&1; then
    maybe_warn "ssh client not found; skipping self-test on localhost port $port"
    return 0
  fi

  # Note: StrictHostKeyChecking=accept-new is safe here as we're testing localhost only.
  # This avoids interactive prompts while still protecting against MITM on first connect.
  ssh_output=$(ssh -o BatchMode=yes \
      -o NumberOfPasswordPrompts=0 \
      -o StrictHostKeyChecking=accept-new \
      -o ConnectTimeout="$SSH_SELFTEST_TIMEOUT" \
      -p "$port" "$user@localhost" true 2>&1)
  exit_code=$?

  if [ $exit_code -ne 0 ]; then
    maybe_warn "SSH self-test failed (exit code: $exit_code)"
    if echo "$ssh_output" | grep -qi "connection refused"; then
      maybe_warn "  Cause: Connection refused - SSH may not be listening on port $port"
    elif echo "$ssh_output" | grep -qi "connection timed out"; then
      maybe_warn "  Cause: Connection timed out - firewall may be blocking port $port"
    elif echo "$ssh_output" | grep -qi "permission denied"; then
      maybe_warn "  Cause: Permission denied - public key authentication failed"
    elif echo "$ssh_output" | grep -qi "no route to host"; then
      maybe_warn "  Cause: No route to host - network configuration issue"
    else
      maybe_warn "  Output: $ssh_output"
    fi
    return 1
  fi
  return 0
}

main() {
  require_linux
  require_root

  local port_input port cfg
  if [ "${1:-}" != "" ]; then
    port_input="$1"
  else
    read -r -p "SSH port [${DEFAULT_PORT}]: " port_input || true
    port_input="${port_input:-$DEFAULT_PORT}"
  fi
  port="$port_input"
  cfg="${2:-$SSHD_CONFIG_DEFAULT}"

  echo "$port" | grep -Eq '^[0-9]+$' || die "Port must be numeric."
  [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || die "Port must be between 1024 and 65535."

  local family username key_file keys_added any_key
  family="$(detect_family)"
  echo "Detected Linux family: $family"

  username="$(choose_target_user)"
  key_file="$(ensure_ssh_paths "$username")"
  clean_authorized_keys "$key_file"

  any_key="0"
  while IFS= read -r key; do
    [ -n "$key" ] || continue
    any_key="1"
    add_key_if_missing "$key_file" "$key"
  done < <(read_keys_interactive)

  [ "$any_key" = "1" ] || die "No keys provided. Nothing to do."

  echo ""
  echo "About to set SSH port to $port, enable public key auth, and disable password auth."
  echo "Ensure the firewall / security group allows TCP $port and you have a working key-based session."
  read -r -p "Proceed? [y/N]: " confirm
  confirm="$(echo "${confirm:-}" | tr '[:upper:]' '[:lower:]')"
  if [ "$confirm" != "y" ] && [ "$confirm" != "yes" ]; then
    die "Aborted by user."
  fi

  local orig_backup orig_ports
  orig_backup="$(make_backup "$cfg")"
  orig_ports="$(extract_ports "$cfg")"

  # Stage 1: warmup (keep old ports, keep password auth on), then self-test on new port
  write_sshd_config "warmup" "$cfg" "$port" "$orig_ports"
  if ! validate_sshd_config "$cfg"; then
    echo "Restoring previous sshd_config from backup: $orig_backup" >&2
    cp "$orig_backup" "$cfg"
    restart_ssh "$family" || true
    die "Aborted due to invalid sshd configuration (warmup)."
  fi
  restart_ssh "$family"

  if ! ssh_self_test "$port" "$username"; then
    echo "Self-test on localhost port $port failed. Restoring backup." >&2
    cp "$orig_backup" "$cfg"
    restart_ssh "$family" || true
    die "Aborted because SSH on new port could not be verified."
  fi

  # Stage 2: final (only new port, disable password auth)
  write_sshd_config "final" "$cfg" "$port" "$orig_ports"
  if ! validate_sshd_config "$cfg"; then
    echo "Restoring previous sshd_config from backup: $orig_backup" >&2
    cp "$orig_backup" "$cfg"
    restart_ssh "$family" || true
    die "Aborted due to invalid sshd configuration (final)."
  fi
  restart_ssh "$family"

  echo ""
  echo "Done. SSH should now listen on port $port with password auth disabled."
  echo "Example: ssh -p $port $username@<server-ip>"
}

main "$@"