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
LOCK_FILE="/var/run/ssh-key-hardening.lock"

# Regex matching SSH public key types (ERE, for grep -E)
SSH_KEY_TYPES_RE='(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)'

# Global state for signal trap rollback
_ROLLBACK_BACKUP=""
_ROLLBACK_CFG=""
_ROLLBACK_FAMILY=""
_TMP_FILES=()

cleanup_on_exit() {
  local exit_code=$?
  # Remove temp files
  for f in ${_TMP_FILES[@]+"${_TMP_FILES[@]}"}; do
    [ -f "$f" ] && rm -f "$f"
  done
  # Remove lock file
  [ -f "$LOCK_FILE" ] && rm -f "$LOCK_FILE"
  # Rollback if interrupted during two-stage apply
  if [ $exit_code -ne 0 ] && [ -n "$_ROLLBACK_BACKUP" ] && [ -n "$_ROLLBACK_CFG" ]; then
    echo "" >&2
    echo "WARN: Script interrupted. Restoring sshd_config from backup." >&2
    cp "$_ROLLBACK_BACKUP" "$_ROLLBACK_CFG"
    if [ -n "$_ROLLBACK_FAMILY" ]; then
      restart_ssh "$_ROLLBACK_FAMILY" 2>/dev/null || true
    fi
  fi
}
trap cleanup_on_exit EXIT

register_tmp_file() {
  _TMP_FILES+=("$1")
}

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
    if ! chown "${username}:" "$ssh_dir" "$key_file" 2>/dev/null; then
      maybe_warn "Failed to set ownership on $ssh_dir and $key_file"
    fi
  fi

  # StrictModes requires home dir not be group/world-writable
  local home_perms
  home_perms="$(stat -c '%a' "$home" 2>/dev/null || stat -f '%Lp' "$home" 2>/dev/null)"
  if [ -n "$home_perms" ]; then
    local group_write="${home_perms:1:1}"
    local other_write="${home_perms:2:1}"
    if [ "$group_write" -ge 2 ] 2>/dev/null || [ "$other_write" -ge 2 ] 2>/dev/null; then
      maybe_warn "Home directory $home has permissive permissions ($home_perms). StrictModes may reject key auth."
      chmod go-w "$home"
      echo "Fixed: removed group/other write from $home"
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
    /^[[:space:]]*#/ { next }
    { low = tolower($0) }
    low ~ /^[[:space:]]*port[[:space:]]+/ { print $2 }
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

  echo "$s" | grep -Eq "^${SSH_KEY_TYPES_RE}[[:space:]]+[A-Za-z0-9+/=]+" && return 0
  echo "$s" | grep -Eq "^[^[:space:]]+[[:space:]]+${SSH_KEY_TYPES_RE}[[:space:]]+[A-Za-z0-9+/=]+" && return 0
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
  if ! diff -q "$backup" "$key_file" >/dev/null 2>&1; then
    echo "Commented out invalid lines in authorized_keys (backup: $backup)."
  else
    echo "authorized_keys validated; no invalid lines found."
  fi
}

has_valid_keys() {
  # Usage: has_valid_keys /path/to/authorized_keys
  # Returns: 0 if file contains at least one valid key, 1 otherwise
  local key_file="$1"
  [ -f "$key_file" ] && [ -r "$key_file" ] || return 1

  # Single awk pass instead of per-line sed+grep subprocesses
  awk '
    /^[[:space:]]*$/ || /^[[:space:]]*#/ { next }
    $1 ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/ && $2 ~ /^[A-Za-z0-9+\/=]+/ { found=1; exit }
    $2 ~ /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)$/ && $3 ~ /^[A-Za-z0-9+\/=]+/ { found=1; exit }
    END { exit (found ? 0 : 1) }
  ' "$key_file"
}

warn_weak_key() {
  # Warn if key type is deprecated or weak
  local key="$1"
  local key_type
  key_type="$(echo "$key" | awk '{
    if ($1 ~ /^(ssh-|ecdsa-|sk-)/) print $1; else print $2
  }')"
  case "$key_type" in
    ssh-dss)
      maybe_warn "ssh-dss (DSA) keys are deprecated and insecure (fixed 1024-bit). Consider using ssh-ed25519."
      ;;
    ssh-rsa)
      maybe_warn "ssh-rsa uses SHA-1 signatures which are deprecated in OpenSSH 8.8+. Consider using ssh-ed25519."
      ;;
  esac
}

show_key_fingerprint() {
  # Display SSH key fingerprint for visual verification
  local key="$1"
  if command -v ssh-keygen >/dev/null 2>&1; then
    local fp
    fp="$(echo "$key" | ssh-keygen -l -f - 2>/dev/null)" || true
    if [ -n "$fp" ]; then
      echo "  Fingerprint: $fp"
    fi
  fi
}

add_key_if_missing() {
  # Usage: add_key_if_missing /path/to/authorized_keys "ssh-ed25519 AAAA... comment"
  local key_file="$1"
  local key="$2"
  warn_weak_key "$key"
  if grep -qxF "$key" "$key_file"; then
    echo "Key already present: ${key:0:40}..."
  else
    echo "$key" >> "$key_file"
    echo "Added key: ${key:0:40}..."
  fi
  show_key_fingerprint "$key"
}

read_keys_interactive() {
  echo "Paste SSH public keys, one per line. Press Enter on an empty line to finish." >&2
  while true; do
    local line=""
    # shellcheck disable=SC2162
    read -r -p "> " line || true
    line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [ -z "$line" ]; then
      break
    fi
    # Ignore accidental pastes of the prompt text itself
    if echo "$line" | grep -qi '^paste ssh public keys'; then
      maybe_warn "Ignored prompt text; please paste an actual SSH public key."
      continue
    fi
    if ! is_valid_key_line "$line"; then
      echo "That does not look like a valid SSH public key line. Try again." >&2
      continue
    fi
    echo "$line"
  done
}

choose_hardening_level() {
  # Interactive selection of SSH hardening level
  # Returns: basic | standard | strict
  local choice

  echo "" >&2
  echo "Select SSH hardening level:" >&2
  echo "" >&2
  echo "  1) basic    - Disable password auth, change port" >&2
  echo "  2) standard - Basic + disable root login, auth limits, timeouts (Recommended)" >&2
  echo "  3) strict   - Standard + disable forwarding, strong ciphers, verbose logging" >&2
  echo "" >&2

  while true; do
    read -r -p "Hardening level [1-3, default=2]: " choice || true
    choice="${choice:-2}"

    case "$choice" in
      1|basic)    echo "basic"; return 0 ;;
      2|standard) echo "standard"; return 0 ;;
      3|strict)   echo "strict"; return 0 ;;
      *) echo "Invalid choice. Please enter 1, 2, or 3." >&2 ;;
    esac
  done
}

get_hardening_configs() {
  # Usage: get_hardening_configs <level>
  # Returns: newline-separated list of sshd_config directives
  local level="$1"

  # Base configs (applied to all levels)
  local base_configs=(
    "PubkeyAuthentication yes"
    "PasswordAuthentication no"
    "KbdInteractiveAuthentication no"
    "ChallengeResponseAuthentication no"
    "HostbasedAuthentication no"
    "IgnoreRhosts yes"
    "StrictModes yes"
  )

  # Standard level additions (PermitRootLogin handled separately per level to avoid conflicts)
  local standard_configs=(
    "PermitEmptyPasswords no"
    "MaxAuthTries 3"
    "MaxSessions 5"
    "LoginGraceTime 30"
    "ClientAliveInterval 300"
    "ClientAliveCountMax 2"
    "MaxStartups 10:30:60"
    "UseDNS no"
    "PrintLastLog yes"
  )

  # Strict level additions
  local strict_configs=(
    "AllowTcpForwarding no"
    "AllowAgentForwarding no"
    "X11Forwarding no"
    "PermitTunnel no"
    "GatewayPorts no"
    "PermitUserEnvironment no"
    "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
    "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512"
    "HostKey /etc/ssh/ssh_host_ed25519_key"
    "HostKey /etc/ssh/ssh_host_rsa_key"
    "RekeyLimit 512M 1h"
    "LogLevel VERBOSE"
  )

  case "$level" in
    basic)
      printf '%s\n' "${base_configs[@]}"
      ;;
    standard)
      printf '%s\n' "${base_configs[@]}"
      echo "PermitRootLogin prohibit-password"
      printf '%s\n' "${standard_configs[@]}"
      ;;
    strict)
      printf '%s\n' "${base_configs[@]}"
      echo "PermitRootLogin no"
      printf '%s\n' "${standard_configs[@]}"
      printf '%s\n' "${strict_configs[@]}"
      ;;
    *)
      die "Unknown hardening level: $level"
      ;;
  esac
}

show_hardening_summary() {
  # Usage: show_hardening_summary <level>
  local level="$1"

  echo ""
  echo "Hardening level: $level"
  echo "Configuration to be applied:"
  echo "----------------------------------------"
  get_hardening_configs "$level" | while IFS= read -r line; do
    echo "  $line"
  done
  echo "----------------------------------------"
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
  # Usage: write_sshd_config mode cfg new_port "orig_ports" [hardening_level]
  # mode: warmup | final
  local mode="$1"
  local cfg="$2"
  local new_port="$3"
  local orig_ports="$4"
  local hardening_level="${5:-basic}"
  [ -w "$cfg" ] || die "Cannot write to $cfg. Please run as root."

  local tmp ports
  tmp="$(mktemp)"
  register_tmp_file "$tmp"
  chmod 600 "$tmp"

  # Filter patterns for all managed directives (lowercase for case-insensitive matching)
  local filter_pattern="pubkeyauthentication|passwordauthentication|port"
  filter_pattern="${filter_pattern}|kbdinteractiveauthentication|challengeresponseauthentication"
  filter_pattern="${filter_pattern}|hostbasedauthentication|ignorerhosts|strictmodes"
  filter_pattern="${filter_pattern}|permitrootlogin|permitemptypasswords|maxauthtries"
  filter_pattern="${filter_pattern}|maxsessions|logingracetime|clientaliveinterval"
  filter_pattern="${filter_pattern}|clientalivecountmax|maxstartups|allowtcpforwarding"
  filter_pattern="${filter_pattern}|allowagentforwarding|x11forwarding|permittunnel"
  filter_pattern="${filter_pattern}|gatewayports|permituserenvironment|ciphers|macs"
  filter_pattern="${filter_pattern}|kexalgorithms|loglevel|usedns|printlastlog|rekeylimit|hostkey"

  awk -v pattern="$filter_pattern" '
    { low = tolower($0) }
    low ~ "^[[:space:]]*#?[[:space:]]*(" pattern ")[[:space:]]+" { next }
    { print }
  ' "$cfg" > "$tmp"

  ports="$(join_unique_ports "$new_port" "$orig_ports")"

  {
    echo ""
    if [ "$mode" = "warmup" ]; then
      echo "# Managed by ssh-key helper (warmup stage)"
      echo "PubkeyAuthentication yes"
      echo "PasswordAuthentication yes"
      for p in $ports; do
        echo "Port ${p}"
      done
    else
      echo "# Managed by ssh-key helper (level: $hardening_level)"
      echo "Port ${new_port}"
      echo ""
      # Apply hardening configs based on level
      get_hardening_configs "$hardening_level"
    fi
  } >> "$tmp"

  cat "$tmp" > "$cfg"
  rm -f "$tmp"
  chmod 600 "$cfg"
  chown root:root "$cfg" 2>/dev/null || true
  run_restorecon "$cfg"
}

validate_sshd_config() {
  # Usage: validate_sshd_config /etc/ssh/sshd_config
  local cfg="$1"
  local err_output
  command -v sshd >/dev/null 2>&1 || die "sshd binary not found; cannot validate configuration."
  if err_output="$(sshd -t -f "$cfg" 2>&1)"; then
    echo "sshd config validation passed (sshd -t)."
    return 0
  else
    echo "sshd config validation failed (sshd -t)." >&2
    if [ -n "$err_output" ]; then
      echo "  $err_output" >&2
    fi
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

disable_weak_host_keys() {
  # Disable DSA host keys (insecure) by renaming them
  local key_dir="/etc/ssh"
  local changed=0
  for kf in "$key_dir"/ssh_host_dsa_key "$key_dir"/ssh_host_dsa_key.pub; do
    if [ -f "$kf" ]; then
      mv "$kf" "${kf}.disabled"
      echo "Disabled weak host key: $kf -> ${kf}.disabled"
      changed=1
    fi
  done
  if [ "$changed" = "0" ]; then
    echo "No weak DSA host keys found."
  fi
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

find_next_uid() {
  # Find the next available UID (starting from 1000 for regular users)
  local max_uid
  max_uid=$(awk -F: '($3 >= 1000 && $3 < 60000) { if ($3 > max) max=$3 } END { print (max=="" ? 999 : max) }' /etc/passwd)
  echo $((max_uid + 1))
}

write_sudoers_entry() {
  # Usage: write_sudoers_entry username
  # Creates /etc/sudoers.d/<username> with visudo validation
  local username="$1"
  mkdir -p /etc/sudoers.d
  echo "$username ALL=(ALL) ALL" > "/etc/sudoers.d/$username"
  chmod 440 "/etc/sudoers.d/$username"
  if command -v visudo >/dev/null 2>&1 && ! visudo -c -f "/etc/sudoers.d/$username" >/dev/null 2>&1; then
    maybe_warn "Sudoers syntax check failed. Removing entry for '$username'."
    rm -f "/etc/sudoers.d/$username"
    return 1
  fi
  echo "Created sudoers entry for '$username'."
}

create_new_user_interactive() {
  # Usage: create_new_user_interactive family [existing_key_file existing_username]
  # Interactively create a new system user after hardening is complete.
  local family="$1"
  local existing_key_file="${2:-}"
  local existing_username="${3:-}"

  echo ""
  read -r -p "Add a new system user? [y/N]: " create_user || true
  create_user="$(echo "${create_user:-}" | tr '[:upper:]' '[:lower:]')"
  if [ "$create_user" != "y" ] && [ "$create_user" != "yes" ]; then
    return 0
  fi

  # --- Username ---
  local new_username
  while true; do
    read -r -p "Enter new username: " new_username || true
    new_username="$(echo "${new_username:-}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    if [ -z "$new_username" ]; then
      echo "Username cannot be empty. Please try again." >&2
      continue
    fi
    if [ ${#new_username} -gt 32 ]; then
      echo "Username too long (max 32 characters)." >&2
      continue
    fi
    if ! echo "$new_username" | grep -Eq '^[a-z_][a-z0-9_-]*$'; then
      echo "Invalid format. Use lowercase letters, digits, underscores, or hyphens (must start with letter or underscore)." >&2
      continue
    fi
    if id "$new_username" >/dev/null 2>&1; then
      echo "User '$new_username' already exists. Please choose a different name." >&2
      continue
    fi
    break
  done

  # --- UID (auto-detect) ---
  local new_uid
  new_uid="$(find_next_uid)"
  echo "Auto-detected next available UID: $new_uid"

  # --- User group ---
  local group_name
  echo ""
  read -r -p "User group [${new_username}]: " group_name || true
  group_name="${group_name:-$new_username}"

  if ! echo "$group_name" | grep -Eq '^[a-z_][a-z0-9_-]*$'; then
    echo "Invalid group name format. Skipping user creation." >&2
    return 1
  fi

  # Create group if it doesn't exist
  if ! getent group "$group_name" >/dev/null 2>&1; then
    case "$family" in
      alpine)
        addgroup "$group_name"
        ;;
      *)
        groupadd "$group_name"
        ;;
    esac
    echo "Created group: $group_name"
  else
    echo "Group '$group_name' already exists."
  fi

  # --- Sudo privileges ---
  local grant_sudo
  echo ""
  echo "SECURITY WARNING: Granting sudo privileges allows this user to execute" >&2
  echo "  any command as root. This increases the attack surface if the account" >&2
  echo "  is compromised." >&2
  read -r -p "Grant sudo privileges to '$new_username'? [y/N]: " grant_sudo || true
  grant_sudo="$(echo "${grant_sudo:-}" | tr '[:upper:]' '[:lower:]')"

  # --- Create user ---
  local user_shell="/bin/bash"
  if [ "$family" = "alpine" ] && [ ! -x /bin/bash ]; then
    user_shell="/bin/ash"
  fi

  case "$family" in
    alpine)
      adduser -D -u "$new_uid" -G "$group_name" -s "$user_shell" "$new_username"
      ;;
    *)
      useradd -m -u "$new_uid" -g "$group_name" -s "$user_shell" "$new_username"
      ;;
  esac
  echo ""
  echo "Created user '$new_username' (UID: $new_uid, Group: $group_name, Shell: $user_shell)"

  # --- Set password ---
  echo ""
  echo "Set a password for '$new_username' (used for sudo and local login):"
  passwd "$new_username" || maybe_warn "Password not set. You can set it later with: passwd $new_username"

  # --- Apply sudo ---
  if [ "$grant_sudo" = "y" ] || [ "$grant_sudo" = "yes" ]; then
    local sudo_done=0
    case "$family" in
      debian)
        if getent group sudo >/dev/null 2>&1; then
          usermod -aG sudo "$new_username"
          echo "Added '$new_username' to sudo group."
          sudo_done=1
        fi
        ;;
      alpine)
        if command -v apk >/dev/null 2>&1; then
          apk add --no-cache sudo 2>/dev/null || true
        fi
        if getent group wheel >/dev/null 2>&1; then
          adduser "$new_username" wheel 2>/dev/null || usermod -aG wheel "$new_username" 2>/dev/null || true
          echo "Added '$new_username' to wheel group."
          sudo_done=1
        fi
        ;;
      rhel)
        if getent group wheel >/dev/null 2>&1; then
          usermod -aG wheel "$new_username"
          echo "Added '$new_username' to wheel group."
          sudo_done=1
        fi
        ;;
    esac
    # Fallback: create validated sudoers.d entry if no group method worked
    if [ "$sudo_done" = "0" ]; then
      write_sudoers_entry "$new_username"
    fi
  fi

  # --- SSH authorized_keys setup ---
  local new_key_file
  new_key_file="$(ensure_ssh_paths "$new_username")"

  local has_existing_keys=0
  if [ -n "$existing_key_file" ] && [ -f "$existing_key_file" ] && has_valid_keys "$existing_key_file"; then
    has_existing_keys=1
  fi

  echo ""
  echo "Set up SSH authorized_keys for '$new_username':" >&2
  echo "" >&2
  if [ "$has_existing_keys" = "1" ]; then
    echo "  1) Use the same SSH key(s) as '$existing_username' (Recommended)" >&2
    echo "  2) Add new SSH public key(s) manually" >&2
    echo "  3) Skip (no SSH key setup)" >&2
    echo "" >&2

    local key_choice
    while true; do
      read -r -p "SSH key setup [1-3, default=1]: " key_choice || true
      key_choice="${key_choice:-1}"
      case "$key_choice" in
        1) break ;;
        2) break ;;
        3) break ;;
        *) echo "Invalid choice. Please enter 1, 2, or 3." >&2 ;;
      esac
    done
  else
    echo "  1) Add new SSH public key(s) manually" >&2
    echo "  2) Skip (no SSH key setup)" >&2
    echo "" >&2

    local key_choice
    while true; do
      read -r -p "SSH key setup [1-2, default=1]: " key_choice || true
      key_choice="${key_choice:-1}"
      case "$key_choice" in
        1) key_choice="2"; break ;;  # Map to "add new" option
        2) key_choice="3"; break ;;  # Map to "skip" option
        *) echo "Invalid choice. Please enter 1 or 2." >&2 ;;
      esac
    done
  fi

  case "$key_choice" in
    1)
      # Copy existing keys
      cp "$existing_key_file" "$new_key_file"
      chmod 600 "$new_key_file"
      chown "$new_username":"$group_name" "$new_key_file" 2>/dev/null || true
      echo "Copied SSH authorized_keys from '$existing_username' to '$new_username'."
      ;;
    2)
      # Add new keys interactively
      local any_new_key=0
      while IFS= read -r key; do
        [ -n "$key" ] || continue
        any_new_key=1
        add_key_if_missing "$new_key_file" "$key"
      done < <(read_keys_interactive)
      if [ "$any_new_key" = "0" ]; then
        maybe_warn "No SSH keys added for '$new_username'."
        echo "  Password auth is disabled. This user cannot SSH in without keys." >&2
      else
        chmod 600 "$new_key_file"
        chown "$new_username":"$group_name" "$new_key_file" 2>/dev/null || true
      fi
      ;;
    3)
      maybe_warn "Skipped SSH key setup for '$new_username'."
      echo "  Password auth is disabled. This user cannot SSH in without keys." >&2
      echo "  Add keys later: ssh-copy-id -p <port> $new_username@<server-ip>" >&2
      ;;
  esac

  # --- Warn if AllowUsers/AllowGroups may block SSH access ---
  if grep -Eq '^[[:space:]]*AllowUsers[[:space:]]' "$SSHD_CONFIG_DEFAULT" 2>/dev/null; then
    echo ""
    maybe_warn "sshd_config contains an AllowUsers directive."
    echo "  You may need to add '$new_username' to AllowUsers for SSH access." >&2
  fi
  if grep -Eq '^[[:space:]]*AllowGroups[[:space:]]' "$SSHD_CONFIG_DEFAULT" 2>/dev/null; then
    maybe_warn "sshd_config contains an AllowGroups directive."
    echo "  You may need to add '$group_name' to AllowGroups for SSH access." >&2
  fi

  echo ""
  echo "User '$new_username' created successfully."
}

main() {
  require_linux
  require_root

  # Prevent concurrent execution
  if [ -f "$LOCK_FILE" ]; then
    local lock_pid
    lock_pid="$(cat "$LOCK_FILE" 2>/dev/null)"
    if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
      die "Another instance is running (PID: $lock_pid). If this is incorrect, remove $LOCK_FILE"
    else
      maybe_warn "Stale lock file found; removing."
      rm -f "$LOCK_FILE"
    fi
  fi
  echo $$ > "$LOCK_FILE"

  local port_input port cfg skip_self_test

  # Parse flags. Default: skip self-test (common when running on server without the private key).
  skip_self_test="1"
  local args=()
  for a in "$@"; do
    case "$a" in
      --skip-self-test) skip_self_test="1" ;; # default; kept for compatibility
      --self-test|--enable-self-test) skip_self_test="0" ;;
      *) args+=("$a") ;;
    esac
  done
  set -- ${args[@]+"${args[@]}"}

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

  local family username key_file any_key
  family="$(detect_family)"
  echo "Detected Linux family: $family"

  username="$(choose_target_user)"
  key_file="$(ensure_ssh_paths "$username")"
  clean_authorized_keys "$key_file"

  # Check for existing keys and allow user to skip key input
  local use_existing
  any_key="0"

  if has_valid_keys "$key_file"; then
    echo ""
    echo "Found existing valid keys in: $key_file"
    read -r -p "Use existing keys without adding new ones? [Y/n]: " use_existing || true
    use_existing="$(echo "${use_existing:-y}" | tr '[:upper:]' '[:lower:]')"

    if [ "$use_existing" = "y" ] || [ "$use_existing" = "yes" ]; then
      echo "Using existing keys."
      any_key="1"
    fi
  fi

  # If not using existing keys or no valid keys exist, prompt for new keys
  if [ "$any_key" = "0" ]; then
    if ! has_valid_keys "$key_file"; then
      echo ""
      maybe_warn "No valid keys found in $key_file. You must provide at least one SSH public key."
    fi

    while IFS= read -r key; do
      [ -n "$key" ] || continue
      any_key="1"
      add_key_if_missing "$key_file" "$key"
    done < <(read_keys_interactive)
  fi

  [ "$any_key" = "1" ] || die "No keys provided and no existing valid keys. Cannot proceed."

  # Choose hardening level
  local hardening_level
  hardening_level="$(choose_hardening_level)"
  show_hardening_summary "$hardening_level"

  echo ""
  echo "About to set SSH port to $port and apply '$hardening_level' hardening."
  echo "Ensure the firewall / security group allows TCP $port and you have a working key-based session."
  read -r -p "Proceed? [y/N]: " confirm || true
  confirm="$(echo "${confirm:-}" | tr '[:upper:]' '[:lower:]')"
  if [ "$confirm" != "y" ] && [ "$confirm" != "yes" ]; then
    die "Aborted by user."
  fi

  local orig_backup orig_ports
  orig_backup="$(make_backup "$cfg")"
  orig_ports="$(extract_ports "$cfg")"

  # Arm the rollback trap during two-stage apply
  _ROLLBACK_BACKUP="$orig_backup"
  _ROLLBACK_CFG="$cfg"
  _ROLLBACK_FAMILY="$family"

  # Stage 1: warmup (keep old ports, keep password auth on), then self-test on new port
  write_sshd_config "warmup" "$cfg" "$port" "$orig_ports"
  if ! validate_sshd_config "$cfg"; then
    echo "Restoring previous sshd_config from backup: $orig_backup" >&2
    cp "$orig_backup" "$cfg"
    restart_ssh "$family" || true
    die "Aborted due to invalid sshd configuration (warmup)."
  fi
  restart_ssh "$family"

  if [ "$skip_self_test" = "1" ]; then
    maybe_warn "Skipping SSH self-test (default). Add --self-test to enable localhost verification."
  else
    if ! ssh_self_test "$port" "$username"; then
      echo "Self-test on localhost port $port failed. Restoring backup." >&2
      cp "$orig_backup" "$cfg"
      restart_ssh "$family" || true
      die "Aborted because SSH on new port could not be verified."
    fi
  fi

  # Disable weak host keys in strict mode
  if [ "$hardening_level" = "strict" ]; then
    disable_weak_host_keys
  fi

  # Stage 2: final (only new port, apply hardening)
  write_sshd_config "final" "$cfg" "$port" "$orig_ports" "$hardening_level"
  if ! validate_sshd_config "$cfg"; then
    echo "Restoring previous sshd_config from backup: $orig_backup" >&2
    cp "$orig_backup" "$cfg"
    restart_ssh "$family" || true
    die "Aborted due to invalid sshd configuration (final)."
  fi
  restart_ssh "$family"

  if [ "$skip_self_test" = "0" ]; then
    if ! ssh_self_test "$port" "$username"; then
      maybe_warn "SSH self-test failed after final stage. Restoring backup."
      cp "$orig_backup" "$cfg"
      restart_ssh "$family" || true
      die "Aborted because SSH with final config could not be verified."
    fi
  fi

  # Disarm rollback trap — two-stage apply succeeded
  _ROLLBACK_BACKUP=""
  _ROLLBACK_CFG=""
  _ROLLBACK_FAMILY=""

  # Offer to create a new system user (after hardening is complete)
  create_new_user_interactive "$family" "$key_file" "$username"

  echo ""
  echo "Done. SSH hardening complete!"
  echo "  - Port: $port"
  echo "  - Hardening level: $hardening_level"
  echo "  - Password auth: disabled"
  echo ""
  echo "WARNING: Do NOT close this SSH session until you have verified"
  echo "  that you can connect with the new configuration from another terminal:"
  echo ""
  echo "  ssh -p $port $username@<server-ip>"
  echo ""
  echo "Firewall rules (if not already configured):"
  echo "  # UFW (Ubuntu/Debian)"
  echo "  ufw allow $port/tcp && ufw reload"
  echo ""
  echo "  # firewalld (CentOS/RHEL)"
  echo "  firewall-cmd --permanent --add-port=$port/tcp && firewall-cmd --reload"
  echo ""
  echo "  # iptables"
  echo "  iptables -A INPUT -p tcp --dport $port -j ACCEPT"
}

main "$@"