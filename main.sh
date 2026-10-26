#!/usr/bin/env bash
# shellcheck disable=SC2034
#
# ssh-hardening — SSH + baseline security hardening for VPS / dedicated servers.
#
#   * Public-key-only SSH login, custom port, three hardening levels
#   * Native support: Debian/Ubuntu, RHEL family (CentOS/Rocky/Alma/Oracle/Fedora/
#     Amazon Linux/openEuler/Anolis/Alibaba Cloud Linux/OpenCloudOS...), Alpine,
#     Arch, openSUSE/SLES, Gentoo; systemd / OpenRC / SysV / runit
#   * Lockout protection: staged apply, effective-config verification (sshd -T),
#     listening-port checks, SELinux port labelling, firewall opening, and a
#     dead-man timer that rolls everything back unless you confirm a new login
#   * Optional modules: fail2ban, automatic security updates, kernel/network
#     sysctl hardening, reboot check
#
# Run as root:  sudo bash main.sh [--help]

if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: this script requires bash (e.g. 'sudo bash main.sh'; on Alpine: 'apk add bash')." >&2
  exit 1
fi
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
  echo "ERROR: bash >= 4 is required (found $BASH_VERSION)." >&2
  exit 1
fi

set -euo pipefail
umask 077
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export LC_ALL=C

SCRIPT_VERSION="2.0.0"
DEFAULT_PORT="54271"
DEFAULT_CONFIRM_TIMEOUT=180
SSH_SELFTEST_TIMEOUT=5
STATE_DIR="/var/lib/ssh-hardening"
LOG_FILE="/var/log/ssh-hardening.log"
DROPIN_NAME="00-ssh-hardening.conf"
BLOCK_BEGIN="# BEGIN ssh-hardening managed block"
BLOCK_END="# END ssh-hardening managed block"
NEUTRAL_MARK="# [ssh-hardening]"
SYSCTL_FILE="/etc/sysctl.d/90-ssh-hardening.conf"
SYSCTL_PORT_FILE="/etc/sysctl.d/60-ssh-hardening-port.conf"
F2B_JAIL_FILE="/etc/fail2ban/jail.d/ssh-hardening.local"

# Key types sshd may accept (DSA is recognised only so that it can be rejected)
SSH_KEY_TYPES_RE='^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh[.]com|sk-ecdsa-sha2-nistp256@openssh[.]com)$'

# ----------------------------------------------------------------------------
# Options
# ----------------------------------------------------------------------------
MODE="apply"            # apply | audit | restore
OPT_PORT=""
OPT_LEVEL=""
OPT_USER=""
OPT_CFG=""
OPT_KEYS=()
OPT_KEY_FILES=()
OPT_NEW_USER=""
OPT_ROOT_LOGIN=""       # "" | no | prohibit-password
OPT_ALLOW_USERS=""      # "" (ask) | 0 | 1
OPT_FIREWALL=""         # "" | 0 | 1
OPT_FAIL2BAN=""
OPT_AUTOUPD=""
OPT_SYSCTL=""
OPT_REBOOT=""
OPT_RESTORE_DIR=""
ASSUME_YES=0
DRY_RUN=0
SELF_TEST=0
CONFIRM_TIMEOUT="$DEFAULT_CONFIRM_TIMEOUT"

# ----------------------------------------------------------------------------
# Runtime state
# ----------------------------------------------------------------------------
LOG_READY=0
TTY_FD=""
LOCKDIR_OWNED=""
_TMP_FILES=()
ROLLBACK_ARMED=0
BACKUP_DIR=""

OS_ID="" OS_LIKE="" OS_NAME="" OS_VER="" FAMILY="" PKG="" INIT="" VIRT="none" CONTAINER_KIND=""
SSHD_BIN="" SSH_VER="" SSH_VER_NUM=0
SSHD_CFG="" SSH_DIR="" SSHD_DROPIN_DIR="" MAIN_CFG_MISSING=0 VENDOR_CFG="" USE_DROPIN=0
SSHD_T_ARGS=()
SSH_SERVICE="" SSH_SOCKET="" SOCKET_GENERATOR=0
EFF=""
CUR_PORTS=""
FW=""

PORT=""
LEVEL=""
TARGET_USER="" TARGET_HOME="" TARGET_GROUP="" TARGET_KEY_FILE=""
TARGET_EXISTING_KEYS=0
TARGET_NEW_KEYS=()
NEW_USER="" NEW_USER_SUDO="" NEW_USER_KEYSRC="" NEW_USER_KEYS=()
ROOT_LOGIN=""
ALLOW_USERS=""
DO_FIREWALL=0 DO_FAIL2BAN=0 DO_AUTOUPD=0 DO_SYSCTL=0
STRICT_CRYPTO=1
CONFIRMED_LOGIN=0
SERVER_IP="" CLIENT_IP=""
APT_UPDATED=0
REBOOT_REASONS=()
SUMMARY=()

# ----------------------------------------------------------------------------
# Output helpers (all UI goes to stderr; stdout is reserved for data)
# ----------------------------------------------------------------------------
if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
  C_R=$'\033[31m' C_G=$'\033[32m' C_Y=$'\033[33m' C_B=$'\033[34m' C_BOLD=$'\033[1m' C_0=$'\033[0m'
else
  C_R="" C_G="" C_Y="" C_B="" C_BOLD="" C_0=""
fi

_log() {
  if [ "$LOG_READY" = 1 ]; then
    printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE" 2>/dev/null || true
  fi
}
say()     { printf '%s\n' "$*" >&2; _log "$*"; }
info()    { printf '%s[*]%s %s\n' "$C_B" "$C_0" "$*" >&2; _log "INFO  $*"; }
ok()      { printf '%s[+]%s %s\n' "$C_G" "$C_0" "$*" >&2; _log "OK    $*"; }
warn()    { printf '%s[!]%s %s\n' "$C_Y" "$C_0" "$*" >&2; _log "WARN  $*"; }
err()     { printf '%s[x]%s %s\n' "$C_R" "$C_0" "$*" >&2; _log "ERROR $*"; }
die()     { err "$*"; exit 1; }
section() { printf '\n%s== %s ==%s\n' "$C_BOLD" "$*" "$C_0" >&2; _log "== $*"; }
summary() { SUMMARY+=("$*"); }

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
trim()  { printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
have()  { command -v "$1" >/dev/null 2>&1; }

# new_tmp: creates a temp file (removed on exit) and stores its path in NEW_TMP.
# Not used via $(...) so that the cleanup list survives.
NEW_TMP=""
new_tmp() {
  NEW_TMP="$(mktemp)"
  _TMP_FILES+=("$NEW_TMP")
}

same_file() { [ "$(cksum <"$1")" = "$(cksum <"$2")" ]; }

run_restorecon() {
  if have restorecon; then restorecon "$@" 2>/dev/null || true; fi
}

# ----------------------------------------------------------------------------
# Interactive input (works with `curl ... | sudo bash` by reading /dev/tty)
# ----------------------------------------------------------------------------
setup_input() {
  if [ -t 0 ]; then
    TTY_FD=0
  elif { exec 3</dev/tty; } 2>/dev/null; then
    TTY_FD=3
  else
    TTY_FD=""
  fi
}

# read_tty VAR "prompt" [timeout]  -> returns 1 on EOF/timeout
read_tty() {
  local __var="$1" __prompt="$2" __t="${3:-}" __reply="" __rc=0
  if [ -z "$TTY_FD" ]; then printf -v "$__var" '%s' ""; return 1; fi
  printf '%s' "$__prompt" >&2
  if [ -n "$__t" ]; then
    IFS= read -r -t "$__t" -u "$TTY_FD" __reply || __rc=$?
  else
    IFS= read -r -u "$TTY_FD" __reply || __rc=$?
  fi
  printf -v "$__var" '%s' "$__reply"
  return "$__rc"
}

# ask VAR "Question" "default"
ask() {
  local __v="$1" __q="$2" __d="${3:-}" __a=""
  if [ "$ASSUME_YES" = 1 ] || [ -z "$TTY_FD" ]; then
    printf -v "$__v" '%s' "$__d"
    return 0
  fi
  if [ -n "$__d" ]; then __q="$__q [$__d]: "; else __q="$__q: "; fi
  read_tty __a "$__q" || true
  __a="$(trim "$__a")"
  printf -v "$__v" '%s' "${__a:-$__d}"
}

# ask_yn "Question" y|n   -> 0 = yes
ask_yn() {
  local q="$1" d="$2" a hint
  if [ "$d" = y ]; then hint="[Y/n]"; else hint="[y/N]"; fi
  if [ "$ASSUME_YES" = 1 ] || [ -z "$TTY_FD" ]; then
    [ "$d" = y ]
    return
  fi
  while true; do
    read_tty a "$q $hint: " || a=""
    a="$(lower "$(trim "$a")")"
    case "${a:-$d}" in
      y|yes) return 0 ;;
      n|no)  return 1 ;;
      *) say "Please answer y or n." ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Exit / signal handling
# ----------------------------------------------------------------------------
on_exit() {
  local rc=$?
  set +e
  local f
  for f in ${_TMP_FILES[@]+"${_TMP_FILES[@]}"}; do rm -f "$f"; done
  if [ -n "$LOCKDIR_OWNED" ]; then rm -rf "$LOCKDIR_OWNED"; fi
  if [ "$ROLLBACK_ARMED" = 1 ] && [ "$rc" -ne 0 ] && [ -n "$BACKUP_DIR" ] && [ -f "$BACKUP_DIR/restore.sh" ]; then
    ROLLBACK_ARMED=0
    printf '\n' >&2
    warn "Run did not complete (exit $rc). Restoring SSH configuration from $BACKUP_DIR ..."
    if sh "$BACKUP_DIR/restore.sh" >>"$LOG_FILE" 2>&1; then
      ok "SSH configuration restored."
    else
      err "Automatic restore reported an error. Check $LOG_FILE and run: sh $BACKUP_DIR/restore.sh"
    fi
  fi
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# mkdir-based lock: unlike flock, no file descriptor is inherited by the rollback
# timer or by daemons started through SysV/OpenRC scripts.
acquire_lock() {
  local d="$STATE_DIR/.lockdir" pid
  if ! mkdir "$d" 2>/dev/null; then
    pid="$(cat "$d/pid" 2>/dev/null || true)"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
      die "Another instance is running (PID $pid). Remove $d if this is wrong."
    fi
    warn "Removing stale lock."
    rm -rf "$d"
    mkdir "$d" || die "Cannot create lock $d"
  fi
  echo $$ >"$d/pid"
  LOCKDIR_OWNED="$d"
}

# ----------------------------------------------------------------------------
# Usage / argument parsing
# ----------------------------------------------------------------------------
usage() {
  cat <<EOF
ssh-hardening v$SCRIPT_VERSION — SSH & baseline server hardening

Usage: sudo bash main.sh [options] [port] [sshd_config]

Modes:
      --audit              Read-only security report; changes nothing
      --dry-run            Ask all questions, show the plan and generated config, change nothing
      --restore [DIR]      Restore SSH config from the latest (or given) backup

SSH options:
  -p, --port N             SSH port (default $DEFAULT_PORT; 22 or 1024-65535)
  -l, --level L            basic | standard | strict
  -u, --user NAME          Login user whose authorized_keys is managed
  -k, --key "PUBKEY"       Add a public key (repeatable). "gh:NAME" imports github.com/NAME.keys
      --key-file FILE      Add keys from a file (repeatable)
      --new-user NAME      Also create a new sudo user (gets the same keys)
      --root-login MODE    no | prohibit-password (standard level only)
      --allow-users / --no-allow-users
                           Restrict SSH logins to the managed users (AllowUsers)
  -c, --config PATH        sshd_config path (default /etc/ssh/sshd_config)

Safety:
      --confirm-timeout S  Seconds to confirm a new login before auto-rollback (default $DEFAULT_CONFIRM_TIMEOUT, 0 = off)
      --self-test          Also test 'ssh -p PORT user@localhost' (needs a private key on this host)
      --skip-self-test     Do not run the localhost self-test (default)

Extra hardening modules (default: asked; on for standard/strict):
      --firewall / --no-firewall         Open the new port in ufw/firewalld/iptables/nftables
      --fail2ban / --no-fail2ban         Install and configure fail2ban for sshd
      --auto-updates / --no-auto-updates Automatic security updates
      --sysctl / --no-sysctl             Kernel/network sysctl hardening
      --reboot / --no-reboot             Reboot at the end (asked for standard/strict)

General:
  -y, --yes                Non-interactive: accept defaults (needs a key source)
  -h, --help               Show this help
  -V, --version            Show version

Examples:
  sudo bash main.sh
  sudo bash main.sh --audit
  sudo bash main.sh -p 2222 -l standard -u deploy -k gh:octocat --yes
  curl -fsSL https://raw.githubusercontent.com/Banezzz/ssh-key/main/main.sh | sudo bash
EOF
}

parse_args() {
  local positional=() a v
  while [ $# -gt 0 ]; do
    a="$1"
    v=""
    case "$a" in
      --*=*) v="${a#*=}"; a="${a%%=*}" ;;
    esac
    case "$a" in
      -p|--port|-l|--level|-u|--user|-k|--key|--key-file|--new-user|--root-login|-c|--config|--confirm-timeout)
        if [ -z "$v" ]; then
          [ $# -ge 2 ] || die "Option $a requires a value."
          v="$2"; shift
        fi ;;
    esac
    case "$a" in
      -h|--help) usage; exit 0 ;;
      -V|--version) echo "$SCRIPT_VERSION"; exit 0 ;;
      --audit) MODE="audit" ;;
      --restore)
        MODE="restore"
        if [ -n "$v" ]; then OPT_RESTORE_DIR="$v"
        elif [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then OPT_RESTORE_DIR="$2"; shift; fi ;;
      --dry-run) DRY_RUN=1 ;;
      -p|--port) OPT_PORT="$v" ;;
      -l|--level) OPT_LEVEL="$(lower "$v")" ;;
      -u|--user) OPT_USER="$v" ;;
      -k|--key) OPT_KEYS+=("$v") ;;
      --key-file) OPT_KEY_FILES+=("$v") ;;
      --new-user) OPT_NEW_USER="$v" ;;
      --root-login) OPT_ROOT_LOGIN="$(lower "$v")" ;;
      --allow-users) OPT_ALLOW_USERS=1 ;;
      --no-allow-users) OPT_ALLOW_USERS=0 ;;
      -c|--config) OPT_CFG="$v" ;;
      --confirm-timeout) CONFIRM_TIMEOUT="$v" ;;
      --self-test|--enable-self-test) SELF_TEST=1 ;;
      --skip-self-test) SELF_TEST=0 ;;
      --firewall) OPT_FIREWALL=1 ;;      --no-firewall) OPT_FIREWALL=0 ;;
      --fail2ban) OPT_FAIL2BAN=1 ;;      --no-fail2ban) OPT_FAIL2BAN=0 ;;
      --auto-updates) OPT_AUTOUPD=1 ;;   --no-auto-updates) OPT_AUTOUPD=0 ;;
      --sysctl) OPT_SYSCTL=1 ;;          --no-sysctl) OPT_SYSCTL=0 ;;
      --reboot) OPT_REBOOT=1 ;;          --no-reboot) OPT_REBOOT=0 ;;
      -y|--yes) ASSUME_YES=1 ;;
      --) shift; positional+=("$@"); break ;;
      -*) die "Unknown option: $a (see --help)" ;;
      *) positional+=("$a") ;;
    esac
    shift
  done
  # Backwards compatible positional arguments: [port] [sshd_config]
  if [ ${#positional[@]} -ge 1 ] && [ -z "$OPT_PORT" ]; then OPT_PORT="${positional[0]}"; fi
  if [ ${#positional[@]} -ge 2 ] && [ -z "$OPT_CFG" ]; then OPT_CFG="${positional[1]}"; fi
  [ ${#positional[@]} -le 2 ] || die "Too many arguments (see --help)."

  case "$OPT_LEVEL" in ""|basic|standard|strict) ;; 1) OPT_LEVEL=basic ;; 2) OPT_LEVEL=standard ;; 3) OPT_LEVEL=strict ;;
    *) die "Invalid --level: $OPT_LEVEL" ;; esac
  case "$OPT_ROOT_LOGIN" in ""|no|prohibit-password) ;; without-password) OPT_ROOT_LOGIN=prohibit-password ;;
    *) die "Invalid --root-login: $OPT_ROOT_LOGIN (no | prohibit-password)" ;; esac
  [[ "$CONFIRM_TIMEOUT" =~ ^[0-9]+$ ]] || die "--confirm-timeout must be a number of seconds."
}

# ----------------------------------------------------------------------------
# Environment detection
# ----------------------------------------------------------------------------
os_field() {
  local f
  for f in /etc/os-release /usr/lib/os-release; do
    if [ -r "$f" ]; then
      awk -F= -v k="$1" '$1==k { v=substr($0, index($0,"=")+1); gsub(/^["'\'']|["'\'']$/, "", v); print v; exit }' "$f"
      return 0
    fi
  done
}

detect_os() {
  OS_ID="$(lower "$(os_field ID)")"
  OS_LIKE="$(lower "$(os_field ID_LIKE)")"
  OS_NAME="$(os_field PRETTY_NAME)"
  OS_VER="$(os_field VERSION_ID)"
  [ -n "$OS_NAME" ] || OS_NAME="$(uname -sr)"

  if have apt-get; then PKG=apt-get
  elif have dnf; then PKG=dnf
  elif have yum; then PKG=yum
  elif have apk; then PKG=apk
  elif have pacman; then PKG=pacman
  elif have zypper; then PKG=zypper
  elif have emerge; then PKG=emerge
  else PKG=""; fi

  local ids=" $OS_ID $OS_LIKE "
  case "$ids" in
    *" debian "*|*" ubuntu "*|*" linuxmint "*|*" raspbian "*|*" kali "*|*" deepin "*|*" uos "*|*" pop "*) FAMILY=debian ;;
    *" alpine "*) FAMILY=alpine ;;
    *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*|*" ol "*|*" amzn "*|*" openeuler "*|*" anolis "*|*" alinux "*|*" opencloudos "*|*" tencentos "*|*" kylin "*|*" euleros "*|*" circle "*|*" navylinux "*|*" eurolinux "*) FAMILY=rhel ;;
    *" arch "*|*" manjaro "*|*" endeavouros "*|*" artix "*) FAMILY=arch ;;
    *" suse "*|*" opensuse "*|*" sles "*|*" sled "*|*opensuse-*) FAMILY=suse ;;
    *" gentoo "*) FAMILY=gentoo ;;
    *)
      case "$PKG" in
        apt-get) FAMILY=debian ;; dnf|yum) FAMILY=rhel ;; apk) FAMILY=alpine ;;
        pacman) FAMILY=arch ;; zypper) FAMILY=suse ;; emerge) FAMILY=gentoo ;; *) FAMILY=unknown ;;
      esac ;;
  esac

  if [ -d /run/systemd/system ] && have systemctl; then INIT=systemd
  elif have rc-service && { [ -d /run/openrc ] || [ -x /sbin/openrc-run ] || [ -x /sbin/openrc ]; }; then INIT=openrc
  elif have sv && { [ -d /etc/runit ] || [ -d /var/service ]; }; then INIT=runit
  else INIT=sysv; fi
}

detect_virt() {
  local c="" v=""
  if have systemd-detect-virt; then
    c="$(systemd-detect-virt -c 2>/dev/null || true)"
    v="$(systemd-detect-virt -v 2>/dev/null || true)"
  fi
  if [ -z "$c" ] || [ "$c" = none ]; then
    if [ -f /.dockerenv ]; then c=docker
    elif [ -f /run/.containerenv ]; then c=podman
    elif [ -d /proc/vz ] && [ ! -d /proc/bc ]; then c=openvz
    elif tr '\0' '\n' </proc/1/environ 2>/dev/null | grep -qx 'container=lxc'; then c=lxc
    else c=none; fi
  fi
  case "$c" in
    none) CONTAINER_KIND=""; VIRT="${v:-none}" ;;
    docker|podman|wsl|rkt) CONTAINER_KIND=app; VIRT="$c" ;;
    *) CONTAINER_KIND=system; VIRT="$c" ;;
  esac
}

detect_sshd() {
  SSHD_BIN="$(command -v sshd 2>/dev/null || true)"
  [ -n "$SSHD_BIN" ] || { [ -x /usr/sbin/sshd ] && SSHD_BIN=/usr/sbin/sshd; } || true
  [ -n "$SSHD_BIN" ] || die "sshd not found. Install the OpenSSH server first (openssh-server / openssh)."

  local v
  v="$("$SSHD_BIN" -V 2>&1 || true)"
  case "$v" in *OpenSSH_*) ;; *) v="$(ssh -V 2>&1 || true)" ;; esac
  SSH_VER="$(printf '%s' "$v" | sed -n 's/.*OpenSSH_\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n1)"
  if [ -n "$SSH_VER" ]; then
    SSH_VER_NUM=$(( ${SSH_VER%%.*} * 100 + ${SSH_VER#*.} ))
  else
    SSH_VER="unknown"; SSH_VER_NUM=0
  fi
}

resolve_sshd_paths() {
  SSHD_CFG="${OPT_CFG:-/etc/ssh/sshd_config}"
  SSH_DIR="$(dirname "$SSHD_CFG")"
  SSHD_DROPIN_DIR="$SSH_DIR/sshd_config.d"
  SSHD_T_ARGS=()
  if [ -n "$OPT_CFG" ]; then SSHD_T_ARGS=(-f "$OPT_CFG"); fi

  if [ ! -f "$SSHD_CFG" ]; then
    if [ -z "$OPT_CFG" ] && [ -f /usr/etc/ssh/sshd_config ]; then
      # openSUSE Tumbleweed / Leap 16: vendor config in /usr/etc, admin drop-ins in /etc/ssh/sshd_config.d
      MAIN_CFG_MISSING=1
      VENDOR_CFG=/usr/etc/ssh/sshd_config
    else
      die "sshd config not found: $SSHD_CFG"
    fi
  fi

  USE_DROPIN=0
  if dropin_is_included; then USE_DROPIN=1; fi
  if [ "$MAIN_CFG_MISSING" = 1 ] && [ "$USE_DROPIN" = 0 ]; then
    die "$VENDOR_CFG does not include $SSHD_DROPIN_DIR/*.conf; cannot place configuration safely."
  fi
}

# True if an Include directive in the global section of the main config covers our drop-in file
dropin_is_included() {
  local file="$SSHD_CFG" target="$SSHD_DROPIN_DIR/$DROPIN_NAME" pat
  [ "$MAIN_CFG_MISSING" = 1 ] && file="$VENDOR_CFG"
  while IFS= read -r pat; do
    [ -n "$pat" ] || continue
    case "$pat" in /*) ;; *) pat="$SSH_DIR/$pat" ;; esac
    # shellcheck disable=SC2053
    if [[ "$target" == $pat ]]; then return 0; fi
  done < <(awk '
    { t=$0; sub(/^[ \t]+/, "", t); split(t, a, /[ \t=]+/); k=tolower(a[1]) }
    k=="match" { exit }
    k=="include" { n=split(t, f, /[ \t]+/); for (i=2; i<=n; i++) print f[i] }
  ' "$file")
  return 1
}

detect_ssh_service() {
  SSH_SERVICE="" SSH_SOCKET="" SOCKET_GENERATOR=0
  local s st
  case "$INIT" in
    systemd)
      for s in ssh sshd; do
        if systemctl cat "$s.service" >/dev/null 2>&1; then SSH_SERVICE="$s"; break; fi
      done
      for s in ssh.socket sshd.socket; do
        st="$(systemctl is-enabled "$s" 2>/dev/null || true)"
        if [ "$st" = enabled ] || [ "$st" = enabled-runtime ] || systemctl is-active --quiet "$s" 2>/dev/null; then
          SSH_SOCKET="$s"; break
        fi
      done
      if [ -x /usr/lib/systemd/system-generators/sshd-socket-generator ] || [ -x /lib/systemd/system-generators/sshd-socket-generator ]; then
        SOCKET_GENERATOR=1
      fi ;;
    openrc|sysv)
      for s in sshd ssh; do
        if [ -x "/etc/init.d/$s" ]; then SSH_SERVICE="$s"; break; fi
      done ;;
    runit)
      for s in sshd ssh; do
        if [ -d "/etc/sv/$s" ] || [ -d "/var/service/$s" ] || [ -d "/etc/service/$s" ]; then SSH_SERVICE="$s"; break; fi
      done ;;
  esac
  if [ -z "$SSH_SERVICE" ]; then
    case "$FAMILY" in debian) SSH_SERVICE=ssh ;; *) SSH_SERVICE=sshd ;; esac
  fi
}

detect_firewall() {
  FW="none"
  local out=""
  if have ufw; then
    out="$(ufw status 2>/dev/null || true)"
    case "$out" in *"Status: active"*) FW=ufw; return ;; esac
  fi
  if have firewall-cmd && [ "$(firewall-cmd --state 2>/dev/null || true)" = running ]; then FW=firewalld; return; fi
  local rules=""
  if have nft; then
    rules="$(nft list ruleset 2>/dev/null || true)"
    if printf '%s\n' "$rules" | grep -Eq 'hook input .*policy drop|hook input .*policy reject'; then FW=nftables; return; fi
  fi
  if have iptables; then
    rules="$(iptables -S INPUT 2>/dev/null || true)"
    if printf '%s\n' "$rules" | grep -Eq '^-P INPUT (DROP|REJECT)|-j (DROP|REJECT)'; then FW=iptables; return; fi
  fi
}

detect_ips() {
  local conn="${SSH_CONNECTION:-}" who_out=""
  if [ -n "$conn" ]; then
    CLIENT_IP="$(printf '%s' "$conn" | awk '{print $1}')"
    SERVER_IP="$(printf '%s' "$conn" | awk '{print $3}')"
  fi
  if [ -z "$CLIENT_IP" ] && have who; then
    who_out="$(who -m 2>/dev/null || true)"
    CLIENT_IP="$(printf '%s' "$who_out" | sed -n 's/.*(\([0-9a-fA-F.:]*\)).*/\1/p' | head -n1)"
  fi
  if [ -z "$SERVER_IP" ] && have ip; then
    SERVER_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)"
  fi
  [ -n "$SERVER_IP" ] || SERVER_IP="<server-ip>"
}

print_env() {
  section "Environment"
  say "  OS:          $OS_NAME (family: $FAMILY, pkg: ${PKG:-none}, init: $INIT)"
  say "  Virtual:     $VIRT${CONTAINER_KIND:+ ($CONTAINER_KIND container)}"
  say "  OpenSSH:     $SSH_VER ($SSHD_BIN)"
  say "  Config:      ${VENDOR_CFG:-$SSHD_CFG} ($( [ "$USE_DROPIN" = 1 ] && echo "drop-in: $SSHD_DROPIN_DIR/$DROPIN_NAME" || echo "managed block at top of file"))"
  say "  Service:     $SSH_SERVICE${SSH_SOCKET:+ (socket-activated via $SSH_SOCKET)}"
  say "  Firewall:    $FW"
  if have getenforce; then say "  SELinux:     $(getenforce 2>/dev/null || echo unknown)"; fi
}

# ----------------------------------------------------------------------------
# sshd helpers
# ----------------------------------------------------------------------------
SSHD_TEST_OUT=""
sshd_test() {
  local d
  SSHD_TEST_OUT="$("$SSHD_BIN" -t ${SSHD_T_ARGS[@]+"${SSHD_T_ARGS[@]}"} 2>&1)" && return 0
  # Debian/Ubuntu: privilege separation dir only exists while sshd runs
  for d in /run/sshd /var/run/sshd /var/empty/sshd /var/empty; do
    case "$SSHD_TEST_OUT" in *"privilege separation directory"*"$d"*)
      mkdir -p "$d"; chmod 755 "$d"
      SSHD_TEST_OUT="$("$SSHD_BIN" -t ${SSHD_T_ARGS[@]+"${SSHD_T_ARGS[@]}"} 2>&1)" && return 0 ;;
    esac
  done
  return 1
}

load_eff() {
  EFF="$("$SSHD_BIN" -T ${SSHD_T_ARGS[@]+"${SSHD_T_ARGS[@]}"} 2>/dev/null)" && return 0
  EFF="$("$SSHD_BIN" -T ${SSHD_T_ARGS[@]+"${SSHD_T_ARGS[@]}"} -C "user=${TARGET_USER:-root},host=localhost,addr=127.0.0.1" 2>/dev/null)" && return 0
  EFF=""
  return 1
}
eff()     { awk -v k="$1" '$1==k { sub(/^[^ ]+ /, ""); print; exit }' <<<"$EFF"; }
eff_all() { awk -v k="$1" '$1==k { sub(/^[^ ]+ /, ""); print }' <<<"$EFF"; }
eff_has() { awk -v k="$1" '$1==k { f=1; exit } END { exit !f }' <<<"$EFF"; }

port_listening() {
  local hex f files=()
  hex="$(printf ':%04X' "$1")"
  for f in /proc/net/tcp /proc/net/tcp6; do [ -r "$f" ] && files+=("$f"); done
  [ ${#files[@]} -gt 0 ] || return 1
  awk -v h="$hex" 'FNR>1 && $4=="0A" && substr($2, length($2)-4)==h { f=1 } END { exit !f }' "${files[@]}"
}

wait_listening() {
  local port="$1" i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if port_listening "$port"; then return 0; fi
    sleep 1
  done
  return 1
}

in_list() { # in_list item "a b c"
  local x
  for x in $2; do [ "$x" = "$1" ] && return 0; done
  return 1
}

# ----------------------------------------------------------------------------
# Service restart (systemd incl. socket activation, OpenRC, SysV, runit)
# ----------------------------------------------------------------------------
restart_ssh() {
  case "$INIT" in
    systemd)
      if [ -n "$SSH_SOCKET" ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        if systemctl restart "$SSH_SOCKET" >/dev/null 2>&1; then
          info "Restarted $SSH_SOCKET (socket activation)."
          return 0
        fi
        return 1
      fi
      if systemctl restart "$SSH_SERVICE" >/dev/null 2>&1; then
        sleep 1
        if systemctl is-active --quiet "$SSH_SERVICE"; then
          info "Restarted $SSH_SERVICE.service."
          return 0
        fi
      fi
      return 1 ;;
    openrc)
      rc-service "$SSH_SERVICE" restart >/dev/null 2>&1 && { info "Restarted $SSH_SERVICE (OpenRC)."; return 0; }
      return 1 ;;
    runit)
      sv restart "$SSH_SERVICE" >/dev/null 2>&1 && { info "Restarted $SSH_SERVICE (runit)."; return 0; }
      return 1 ;;
    *)
      if have service && service "$SSH_SERVICE" restart >/dev/null 2>&1; then info "Restarted $SSH_SERVICE (service)."; return 0; fi
      if [ -x "/etc/init.d/$SSH_SERVICE" ] && "/etc/init.d/$SSH_SERVICE" restart >/dev/null 2>&1; then info "Restarted $SSH_SERVICE (init.d)."; return 0; fi
      return 1 ;;
  esac
}

# A socket unit that ignores sshd_config ports is switched to the plain service.
convert_socket_to_service() {
  [ "$INIT" = systemd ] && [ -n "$SSH_SOCKET" ] || return 1
  local was
  was="$(systemctl is-enabled "$SSH_SERVICE" 2>/dev/null || true)"
  warn "$SSH_SOCKET does not follow the Port setting; switching to $SSH_SERVICE.service (no socket activation)."
  if [ "$was" = enabled ]; then echo "service-was-enabled" >"$BACKUP_DIR/socket_converted"
  else echo "service-was-disabled" >"$BACKUP_DIR/socket_converted"; fi
  echo "$SSH_SOCKET" >"$BACKUP_DIR/socket_unit"
  systemctl disable --now "$SSH_SOCKET" >/dev/null 2>&1 || true
  systemctl enable "$SSH_SERVICE" >/dev/null 2>&1 || true
  SSH_SOCKET=""
  restart_ssh
}

# Restart and make sure every expected port is actually listening.
restart_and_verify() {
  local ports="$1" p missing=""
  if ! restart_ssh; then
    if [ -n "$SSH_SOCKET" ] && convert_socket_to_service; then :; else
      err "Failed to restart the SSH service."
      return 1
    fi
  fi
  for p in $ports; do
    wait_listening "$p" || missing="$missing $p"
  done
  if [ -n "$missing" ] && [ -n "$SSH_SOCKET" ]; then
    convert_socket_to_service || true
    missing=""
    for p in $ports; do wait_listening "$p" || missing="$missing $p"; done
  fi
  if [ -n "$missing" ]; then
    err "SSH is not listening on port(s):$missing"
    return 1
  fi
  ok "SSH is listening on: $(trim "$ports")"
}

# ----------------------------------------------------------------------------
# Package management
# ----------------------------------------------------------------------------
pkg_install() {
  [ $# -gt 0 ] || return 0
  info "Installing package(s): $*"
  case "$PKG" in
    apt-get)
      if [ "$APT_UPDATED" = 0 ]; then apt-get update -qq >>"$LOG_FILE" 2>&1 || true; APT_UPDATED=1; fi
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" >>"$LOG_FILE" 2>&1 ;;
    dnf)    dnf install -y -q "$@" >>"$LOG_FILE" 2>&1 ;;
    yum)    yum install -y -q "$@" >>"$LOG_FILE" 2>&1 ;;
    apk)    apk add --no-cache -q "$@" >>"$LOG_FILE" 2>&1 ;;
    pacman) pacman -S --needed --noconfirm "$@" >>"$LOG_FILE" 2>&1 ;;
    zypper) zypper -n -q install "$@" >>"$LOG_FILE" 2>&1 ;;
    *) warn "Automatic package installation is not supported here (install manually: $*)."; return 1 ;;
  esac
}

svc_enable_start() { # svc_enable_start NAME
  case "$INIT" in
    systemd) systemctl enable "$1" >/dev/null 2>&1 || true; systemctl restart "$1" >/dev/null 2>&1 ;;
    openrc)  rc-update add "$1" default >/dev/null 2>&1 || true; rc-service "$1" restart >/dev/null 2>&1 ;;
    runit)   [ -d "/etc/sv/$1" ] && ln -sf "/etc/sv/$1" /var/service/ 2>/dev/null; sv restart "$1" >/dev/null 2>&1 ;;
    *)       service "$1" restart >/dev/null 2>&1 || "/etc/init.d/$1" restart >/dev/null 2>&1 ;;
  esac
}

# ----------------------------------------------------------------------------
# Users & keys
# ----------------------------------------------------------------------------
user_field() { # user_field NAME FIELDNO
  if have getent; then getent passwd "$1" | awk -F: -v n="$2" '{print $n; exit}'
  else awk -F: -v u="$1" -v n="$2" '$1==u {print $n; exit}' /etc/passwd; fi
}

shadow_pw() { awk -F: -v u="$1" '$1==u {print $2; exit}' /etc/shadow 2>/dev/null || true; }

user_has_sudo() {
  local u="$1" g
  [ "$u" = root ] && return 0
  if have sudo; then
    if sudo -n -l -U "$u" 2>/dev/null | grep -Eq '\(ALL( ?: ?ALL)?\)[[:space:]]+(NOPASSWD:[[:space:]]*)?ALL'; then return 0; fi
  fi
  for g in $(id -nG "$u" 2>/dev/null); do
    case "$g" in sudo|wheel|admin) have sudo && return 0 ;; esac
  done
  return 1
}

# KI_* are set by key_info
KI_TYPE="" KI_BITS="" KI_FP="" KI_BLOB="" KI_COMMENT="" KEY_SCRATCH=""
key_info() {
  local line="$1" out
  KI_TYPE="" KI_BITS="" KI_FP="" KI_BLOB="" KI_COMMENT=""
  # locate "<type> <blob> [comment]", optionally preceded by options
  read -r KI_TYPE KI_BLOB KI_COMMENT < <(awk -v re="$SSH_KEY_TYPES_RE" '{
      for (i=1; i<=NF; i++) if ($i ~ re) { c=""; for (j=i+2; j<=NF; j++) c = c (c=="" ? "" : " ") $j; print $i, $(i+1), c; exit }
    }' <<<"$line") || true
  [ -n "$KI_TYPE" ] && [ -n "$KI_BLOB" ] || return 1
  [[ "$KI_BLOB" =~ ^[A-Za-z0-9+/]+=*$ ]] || return 1
  if have ssh-keygen; then
    if [ -z "$KEY_SCRATCH" ]; then new_tmp; KEY_SCRATCH="$NEW_TMP"; fi
    printf '%s\n' "$line" >"$KEY_SCRATCH"
    out="$(ssh-keygen -l -f "$KEY_SCRATCH" 2>/dev/null)" || return 1
    KI_BITS="$(awk '{print $1; exit}' <<<"$out")"
    KI_FP="$(awk '{print $2; exit}' <<<"$out")"
  fi
  return 0
}

# key_usable: 0 = usable, 1 = rejected (prints reason)
key_usable() {
  case "$KI_TYPE" in
    ssh-dss)
      warn "Rejected ssh-dss (DSA) key: disabled by default since OpenSSH 7.0 and removed in 10.0 — it would lock you out."
      return 1 ;;
    ssh-rsa)
      if [ -n "$KI_BITS" ] && [ "$KI_BITS" -lt 2048 ]; then
        warn "Rejected RSA key with only $KI_BITS bits (minimum 2048)."
        return 1
      fi
      if [ -n "$KI_BITS" ] && [ "$KI_BITS" -lt 3072 ]; then
        warn "RSA $KI_BITS-bit key accepted, but ssh-ed25519 (or RSA >= 3072) is recommended."
      fi ;;
  esac
  return 0
}

describe_key() { printf '%s %s%s %s' "$KI_TYPE" "${KI_BITS:+$KI_BITS-bit }" "${KI_FP:-}" "${KI_COMMENT:-}"; }

# Report keys in an authorized_keys file (read-only). Sets TARGET_EXISTING_KEYS.
inspect_authorized_keys() {
  local file="$1" line n=0 bad=0 rejected=0
  TARGET_EXISTING_KEYS=0
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line="$(trim "$line")"
    case "$line" in ""|\#*) continue ;; esac
    if ! key_info "$line"; then bad=$((bad + 1)); continue; fi
    n=$((n + 1))
    if key_usable >/dev/null 2>&1; then
      TARGET_EXISTING_KEYS=$((TARGET_EXISTING_KEYS + 1))
      say "    - $(describe_key)"
    else
      rejected=$((rejected + 1))
      say "    - $(describe_key)  ${C_Y}(not usable: weak/deprecated)${C_0}"
    fi
  done <"$file"
  if [ "$bad" -gt 0 ]; then warn "$bad line(s) in $file are not valid public keys (sshd ignores them; file left unchanged)."; fi
  if [ "$rejected" -gt 0 ]; then warn "$rejected key(s) are DSA or RSA < 2048 bits and will not be counted as usable."; fi
}

blob_in_list() { # blob_in_list BLOB file_or_empty [array items...]
  local blob="$1" file="$2" k
  shift 2
  if [ -n "$file" ] && [ -f "$file" ] && grep -qF -- "$blob" "$file"; then return 0; fi
  for k in "$@"; do
    case "$k" in *"$blob"*) return 0 ;; esac
  done
  return 1
}

fetch_github_keys() {
  local u="$1"
  [[ "$u" =~ ^[A-Za-z0-9-]{1,39}$ ]] || { warn "Invalid GitHub username: $u"; return 1; }
  if have curl; then curl -fsSL --max-time 20 "https://github.com/$u.keys"
  elif have wget; then wget -qO- --timeout=20 "https://github.com/$u.keys"
  else warn "Neither curl nor wget is available to fetch GitHub keys."; return 1; fi
}

# Expand a key source ("gh:NAME" or a key line) into candidate lines on stdout
expand_key_source() {
  local src="$1" u
  case "$src" in
    gh:*|github:*)
      u="${src#*:}"
      info "Fetching public keys from https://github.com/$u.keys"
      fetch_github_keys "$u" || { warn "Could not fetch keys for GitHub user '$u'."; return 0; } ;;
    *) printf '%s\n' "$src" ;;
  esac
}

# collect_key_line ARRAYNAME EXISTING_FILE LINE  -> validates/dedupes and appends
collect_key_line() {
  local arr="$1" file="$2" line="$3" cur=()
  line="$(trim "$line")"
  [ -n "$line" ] || return 0
  case "$line" in \#*) return 0 ;; esac
  if ! key_info "$line"; then
    warn "Not a valid SSH public key: ${line:0:50}..."
    return 1
  fi
  key_usable || return 1
  eval "cur=(\${${arr}[@]+\"\${${arr}[@]}\"})"
  if blob_in_list "$KI_BLOB" "$file" ${cur[@]+"${cur[@]}"}; then
    info "Key already present: $(describe_key)"
    return 0
  fi
  eval "${arr}+=(\"\$line\")"
  ok "Key accepted: $(describe_key)"
}

read_keys_interactive() { # read_keys_interactive ARRAYNAME EXISTING_FILE
  local arr="$1" file="$2" line l
  say "Paste SSH public keys, one per line (or gh:<github-user> to import). Empty line to finish."
  while true; do
    read_tty line "> " || break
    line="$(trim "$line")"
    [ -n "$line" ] || break
    case "$line" in [Pp]aste\ *) continue ;; esac
    while IFS= read -r l; do
      collect_key_line "$arr" "$file" "$l" || true
    done < <(expand_key_source "$line")
  done
}

# Securely create ~/.ssh and authorized_keys. Echoes the key file path.
ensure_ssh_dir() {
  local user="$1" home group ssh_dir key_file perms owner
  home="$(user_field "$user" 6)"
  group="$(id -gn "$user")"
  [ -n "$home" ] && [ -d "$home" ] || die "Home directory of '$user' does not exist: ${home:-?}"
  ssh_dir="$home/.ssh"
  key_file="$ssh_dir/authorized_keys"
  if [ -L "$ssh_dir" ] || [ -L "$key_file" ]; then
    die "$ssh_dir or $key_file is a symlink; refusing to modify it (fix manually)."
  fi
  mkdir -p "$ssh_dir"
  [ -e "$key_file" ] || : >"$key_file"
  chown "$user:$group" "$ssh_dir" "$key_file"
  chmod 700 "$ssh_dir"
  chmod 600 "$key_file"

  # StrictModes rejects keys if $HOME is group/world-writable or owned by someone else
  perms="$(stat -c '%a' "$home" 2>/dev/null || echo 755)"
  if (( 8#$perms & 8#022 )); then
    chmod go-w "$home"
    warn "Removed group/other write permission from $home (was $perms) — required by StrictModes."
  fi
  owner="$(stat -c '%U' "$home" 2>/dev/null || echo "$user")"
  if [ "$owner" != "$user" ] && [ "$owner" != root ]; then
    warn "$home is owned by '$owner', not '$user'; StrictModes may reject key logins."
  fi
  run_restorecon -R "$ssh_dir"
  printf '%s' "$key_file"
}

append_keys() { # append_keys FILE USER key...
  local file="$1" user="$2" k
  shift 2
  [ $# -gt 0 ] || return 0
  if [ -s "$file" ] && [ -n "$(tail -c1 "$file")" ]; then echo >>"$file"; fi
  for k in "$@"; do printf '%s\n' "$k" >>"$file"; done
  chown "$user:$(id -gn "$user")" "$file"
  chmod 600 "$file"
  run_restorecon "$file"
  ok "Wrote $# key(s) to $file"
}

# sshd's AuthorizedKeysFile must cover ~/.ssh/authorized_keys, otherwise our keys are ignored
check_authorized_keys_file() {
  local akf tok p
  akf="$(eff authorizedkeysfile)"
  [ -n "$akf" ] || return 0
  for tok in $akf; do
    p="${tok//%h/$TARGET_HOME}"
    p="${p//%u/$TARGET_USER}"
    p="${p//%%/%}"
    case "$p" in /*) ;; *) p="$TARGET_HOME/$p" ;; esac
    if [ "$p" = "$TARGET_HOME/.ssh/authorized_keys" ]; then return 0; fi
  done
  warn "sshd reads keys from: AuthorizedKeysFile $akf"
  warn "This script manages $TARGET_HOME/.ssh/authorized_keys, which sshd will NOT read."
  if [ -n "$(eff authorizedkeyscommand)" ] && [ "$(eff authorizedkeyscommand)" != none ]; then
    warn "An AuthorizedKeysCommand is configured: $(eff authorizedkeyscommand)"
  fi
  ask_yn "Continue anyway (only if you know your keys are provided another way)?" n || die "Aborted: AuthorizedKeysFile mismatch."
}

check_account_usable() {
  local user="$1" shell pw
  shell="$(user_field "$user" 7)"
  case "$shell" in
    */nologin|*/false|"") warn "User '$user' has shell '${shell:-none}' and cannot open an interactive session."
      ask_yn "Continue with this user anyway?" n || die "Aborted." ;;
  esac
  # Without PAM, sshd refuses locked accounts even for key logins (typical on Alpine)
  pw="$(shadow_pw "$user")"
  if [ "$(eff usepam)" != yes ] && [ "${pw:0:1}" = "!" ]; then
    warn "Account '$user' is locked ('!' in /etc/shadow) and sshd runs without PAM: key login would be refused."
    if ask_yn "Unlock the account for key login (password stays unusable)?" y; then
      ACCOUNT_UNLOCK_USERS+=("$user")
    else
      die "Aborted: '$user' cannot log in while locked."
    fi
  fi
  # Existing AllowUsers/AllowGroups/DenyUsers may exclude the user
  local allow deny pat ok_user=1
  allow="$(eff_all allowusers | tr '\n' ' ')"
  if [ -n "$(trim "$allow")" ]; then
    ok_user=0
    for pat in $allow; do
      # shellcheck disable=SC2053
      if [[ "$user" == ${pat%%@*} ]]; then ok_user=1; break; fi
    done
  fi
  deny="$(eff_all denyusers | tr '\n' ' ')"
  for pat in $deny; do
    # shellcheck disable=SC2053
    if [[ "$user" == ${pat%%@*} ]]; then ok_user=0; fi
  done
  if [ "$ok_user" = 0 ]; then
    warn "Current AllowUsers/DenyUsers settings do not permit '$user' to log in via SSH."
    warn "  AllowUsers: ${allow:-<none>}   DenyUsers: ${deny:-<none>}"
    ask_yn "Continue anyway (you can enable the AllowUsers option later in this run)?" n || die "Aborted."
  fi
  if [ -n "$(eff_all allowgroups | tr -d '[:space:]')" ]; then
    warn "AllowGroups is set ($(eff_all allowgroups | tr '\n' ' ')); make sure '$user' is in one of these groups."
  fi
}
ACCOUNT_UNLOCK_USERS=()

unlock_account() {
  local user="$1" pw
  pw="$(shadow_pw "$user")"
  case "$pw" in
    "!"*'$'*)
      if passwd -u "$user" >/dev/null 2>&1 || usermod -U "$user" >/dev/null 2>&1; then ok "Unlocked account '$user'."; return 0; fi ;;
  esac
  if have usermod && usermod -p '*' "$user" >/dev/null 2>&1; then ok "Account '$user' set to key-only (no password)."; return 0; fi
  if have chpasswd && printf '%s:*\n' "$user" | chpasswd -e >/dev/null 2>&1; then ok "Account '$user' set to key-only (no password)."; return 0; fi
  warn "Could not unlock '$user'; run: usermod -p '*' $user"
}

# ----------------------------------------------------------------------------
# New user creation
# ----------------------------------------------------------------------------
valid_new_username() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }

plan_new_user() {
  local need_admin="$1" name def_create=n choice
  if [ -n "$OPT_NEW_USER" ]; then
    name="$OPT_NEW_USER"
  else
    [ "$need_admin" = 1 ] && def_create=y
    if [ "$need_admin" = 1 ]; then
      say ""
      say "A non-root sudo user is recommended: root SSH login can then be disabled entirely."
    fi
    ask_yn "Create a new sudo user for SSH login?" "$def_create" || return 0
    while true; do
      ask name "New username" ""
      if [ -z "$name" ]; then [ "$ASSUME_YES" = 1 ] && return 0; continue; fi
      if ! valid_new_username "$name"; then warn "Invalid name (lowercase letters, digits, _ and -, max 32 chars)."; continue; fi
      if id "$name" >/dev/null 2>&1; then warn "User '$name' already exists."; continue; fi
      break
    done
  fi
  valid_new_username "$name" || die "Invalid username: $name"
  id "$name" >/dev/null 2>&1 && die "User '$name' already exists."
  NEW_USER="$name"

  NEW_USER_SUDO="password"
  say ""
  say "Sudo for '$NEW_USER':"
  say "  1) sudo with password (recommended: a stolen key alone does not give root)"
  say "  2) sudo without password (NOPASSWD)"
  say "  3) no sudo"
  # A password cannot be set non-interactively, so --yes defaults to NOPASSWD sudo
  if [ "$ASSUME_YES" = 1 ]; then ask choice "Choice [1-3]" "2"; else ask choice "Choice [1-3]" "1"; fi
  case "$choice" in 2) NEW_USER_SUDO="nopasswd" ;; 3) NEW_USER_SUDO="none" ;; *) NEW_USER_SUDO="password" ;; esac

  local have_target_keys=$(( TARGET_EXISTING_KEYS + ${#TARGET_NEW_KEYS[@]} ))
  if [ "$have_target_keys" -gt 0 ]; then
    say ""
    say "SSH keys for '$NEW_USER':"
    say "  1) Same key(s) as '$TARGET_USER' (recommended)"
    say "  2) Paste different key(s)"
    ask choice "Choice [1-2]" "1"
  else
    choice=2
  fi
  if [ "$choice" = 2 ]; then
    NEW_USER_KEYSRC="new"
    read_keys_interactive NEW_USER_KEYS ""
    [ ${#NEW_USER_KEYS[@]} -gt 0 ] || die "No usable key provided for '$NEW_USER'."
  else
    NEW_USER_KEYSRC="copy"
  fi
}

ensure_sudo_installed() {
  have sudo && return 0
  pkg_install sudo || { warn "sudo could not be installed."; return 1; }
  have sudo
}

grant_sudo() {
  local user="$1" mode="$2" f="/etc/sudoers.d/90-ssh-hardening-$1" sudoers_bak=""
  ensure_sudo_installed || return 1
  mkdir -p /etc/sudoers.d
  chmod 750 /etc/sudoers.d
  if ! grep -Eq '^[#@]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers 2>/dev/null; then
    new_tmp; sudoers_bak="$NEW_TMP"
    cp -p /etc/sudoers "$sudoers_bak"
    printf '\n#includedir /etc/sudoers.d\n' >>/etc/sudoers
  fi
  {
    echo "# Created by ssh-hardening on $(date '+%F %T')"
    if grep -Eq '^Defaults[[:space:]]+targetpw' /etc/sudoers 2>/dev/null; then
      echo "Defaults:$user !targetpw"
    fi
    if [ "$mode" = nopasswd ]; then echo "$user ALL=(ALL:ALL) NOPASSWD: ALL"
    else echo "$user ALL=(ALL:ALL) ALL"; fi
  } >"$f"
  chmod 440 "$f"
  if have visudo && ! visudo -c >/dev/null 2>&1; then
    rm -f "$f"
    [ -n "$sudoers_bak" ] && cp -p "$sudoers_bak" /etc/sudoers
    warn "sudoers validation failed; sudo was not granted to '$user'."
    return 1
  fi
  ok "Granted sudo to '$user' ($f${mode:+, $mode})."
}

create_new_user() {
  [ -n "$NEW_USER" ] || return 0
  section "Creating user '$NEW_USER'"
  local shell=/bin/sh pw tries
  [ -x /bin/bash ] && shell=/bin/bash
  if have useradd; then
    useradd -m -U -s "$shell" "$NEW_USER" 2>/dev/null || useradd -m -s "$shell" "$NEW_USER"
  elif have adduser; then
    adduser -D -s "$shell" "$NEW_USER"
  else
    die "Neither useradd nor adduser is available."
  fi
  ok "Created user '$NEW_USER' (shell $shell)."

  if [ "$NEW_USER_SUDO" = password ] && [ -n "$TTY_FD" ] && [ "$ASSUME_YES" = 0 ]; then
    say "Set a password for '$NEW_USER' (used for sudo and console login, never for SSH):"
    for tries in 1 2 3; do
      if passwd "$NEW_USER" <&"$TTY_FD"; then break; fi
      warn "Password not set (attempt $tries/3)."
    done
  fi
  pw="$(shadow_pw "$NEW_USER")"
  case "$pw" in
    '!'|'!!'|'*'|'!*'|'')
      unlock_account "$NEW_USER"
      if [ "$NEW_USER_SUDO" = password ]; then
        warn "'$NEW_USER' has no password, so password-sudo would be unusable."
        if [ "$ASSUME_YES" = 0 ] && ask_yn "Use NOPASSWD sudo instead?" n; then NEW_USER_SUDO=nopasswd
        else warn "Set it later with: passwd $NEW_USER"; fi
      fi ;;
  esac
  if [ "$NEW_USER_SUDO" != none ]; then grant_sudo "$NEW_USER" "$NEW_USER_SUDO" || true; fi

  local kf
  kf="$(ensure_ssh_dir "$NEW_USER")"
  if [ "$NEW_USER_KEYSRC" = copy ]; then
    local lines=()
    while IFS= read -r l || [ -n "$l" ]; do
      l="$(trim "$l")"
      case "$l" in ""|\#*) continue ;; esac
      lines+=("$l")
    done <"$TARGET_KEY_FILE"
    append_keys "$kf" "$NEW_USER" ${lines[@]+"${lines[@]}"}
  else
    append_keys "$kf" "$NEW_USER" "${NEW_USER_KEYS[@]}"
  fi
  summary "Created user $NEW_USER (sudo: $NEW_USER_SUDO)"
}

# ----------------------------------------------------------------------------
# Plan: port, user, keys, level, options
# ----------------------------------------------------------------------------
select_port() {
  local p="$OPT_PORT" range lo hi
  [ -n "$p" ] || ask p "SSH port" "$DEFAULT_PORT"
  [[ "$p" =~ ^[0-9]+$ ]] || die "Port must be numeric."
  p=$((10#$p))
  if [ "$p" -ne 22 ] && { [ "$p" -lt 1024 ] || [ "$p" -gt 65535 ]; }; then
    die "Port must be 22 or between 1024 and 65535."
  fi
  if port_listening "$p" && ! in_list "$p" "$CUR_PORTS"; then
    die "Port $p is already used by another service (check: ss -ltnp | grep :$p)."
  fi
  if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
    read -r lo hi </proc/sys/net/ipv4/ip_local_port_range || true
    if [ -n "${lo:-}" ] && [ "$p" -ge "$lo" ] && [ "$p" -le "$hi" ]; then
      PORT_IN_EPHEMERAL=1
      info "Port $p is inside the ephemeral range ($lo-$hi); it will be reserved so outgoing connections cannot occupy it."
    fi
  fi
  PORT="$p"
}
PORT_IN_EPHEMERAL=0

select_target_user() {
  local u="$OPT_USER" def="${SUDO_USER:-root}"
  [ -n "$u" ] || ask u "SSH login user (keys are installed for this account)" "$def"
  id "$u" >/dev/null 2>&1 || die "User not found: $u"
  TARGET_USER="$u"
  TARGET_HOME="$(user_field "$u" 6)"
  TARGET_GROUP="$(id -gn "$u")"
  [ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME" ] || die "Home directory of '$u' does not exist: ${TARGET_HOME:-?}"
  TARGET_KEY_FILE="$TARGET_HOME/.ssh/authorized_keys"
}

collect_target_keys() {
  section "SSH keys for '$TARGET_USER'"
  if [ -f "$TARGET_KEY_FILE" ]; then
    say "  Existing keys in $TARGET_KEY_FILE:"
    inspect_authorized_keys "$TARGET_KEY_FILE"
  else
    say "  $TARGET_KEY_FILE does not exist yet."
  fi

  local src f l
  for src in ${OPT_KEYS[@]+"${OPT_KEYS[@]}"}; do
    while IFS= read -r l; do collect_key_line TARGET_NEW_KEYS "$TARGET_KEY_FILE" "$l" || true; done < <(expand_key_source "$src")
  done
  for f in ${OPT_KEY_FILES[@]+"${OPT_KEY_FILES[@]}"}; do
    [ -r "$f" ] || die "Cannot read key file: $f"
    while IFS= read -r l || [ -n "$l" ]; do collect_key_line TARGET_NEW_KEYS "$TARGET_KEY_FILE" "$l" || true; done <"$f"
  done

  if [ ${#OPT_KEYS[@]} -eq 0 ] && [ ${#OPT_KEY_FILES[@]} -eq 0 ]; then
    if [ "$TARGET_EXISTING_KEYS" -gt 0 ]; then
      if ! ask_yn "Use the existing key(s) without adding new ones?" y; then
        read_keys_interactive TARGET_NEW_KEYS "$TARGET_KEY_FILE"
      fi
    else
      warn "No usable key found for '$TARGET_USER'. You must add at least one."
      read_keys_interactive TARGET_NEW_KEYS "$TARGET_KEY_FILE"
    fi
  fi
  [ $(( TARGET_EXISTING_KEYS + ${#TARGET_NEW_KEYS[@]} )) -gt 0 ] || die "No usable SSH key for '$TARGET_USER'. Cannot continue."
}

select_level() {
  if [ -n "$OPT_LEVEL" ]; then LEVEL="$OPT_LEVEL"; return; fi
  local c
  section "Hardening level"
  say "  1) basic    - key-only login, custom port, no password/keyboard-interactive auth"
  say "  2) standard - basic + root login restricted, auth/session limits, X11 off, VERBOSE"
  say "                logging; offers fail2ban, auto security updates, sysctl (recommended)"
  say "  3) strict   - standard + no root login, no forwarding/tunnels, modern crypto only,"
  say "                Ed25519/RSA host keys only. NOTE: breaks VS Code Remote-SSH and ssh -L/-D tunnels"
  while true; do
    ask c "Level [1-3]" "2"
    case "$(lower "$c")" in
      1|basic) LEVEL=basic; return ;;
      2|standard) LEVEL=standard; return ;;
      3|strict) LEVEL=strict; return ;;
      *) warn "Please enter 1, 2 or 3." ;;
    esac
  done
}

# Who can still administer the box over SSH once root login is disabled?
nonroot_admin() {
  if [ -n "$NEW_USER" ] && [ "$NEW_USER_SUDO" != none ]; then echo "$NEW_USER"; return 0; fi
  if [ "$TARGET_USER" != root ] && user_has_sudo "$TARGET_USER"; then echo "$TARGET_USER"; return 0; fi
  return 1
}

decide_root_login() {
  local admin=""
  admin="$(nonroot_admin || true)"
  case "$LEVEL" in
    basic) ROOT_LOGIN="" ;;
    strict)
      ROOT_LOGIN="no"
      if [ -z "$admin" ]; then
        if [ "$TARGET_USER" = root ] && [ -z "$NEW_USER" ]; then
          die "Strict level disables root SSH login, but root is the only SSH user. Create a sudo user (--new-user) or choose standard."
        fi
        warn "Strict disables root SSH login and no SSH user with sudo rights was found."
        warn "You would need 'su' with the root password to administer the server."
        ask_yn "Continue anyway?" n || die "Aborted."
      fi ;;
    standard)
      if [ -n "$OPT_ROOT_LOGIN" ]; then ROOT_LOGIN="$OPT_ROOT_LOGIN"
      elif [ "$ASSUME_YES" = 1 ]; then ROOT_LOGIN=prohibit-password
      elif [ -n "$admin" ]; then
        if ask_yn "Disable root SSH login completely (admin via '$admin' + sudo)?" y; then ROOT_LOGIN=no; else ROOT_LOGIN=prohibit-password; fi
      else
        ROOT_LOGIN=prohibit-password
      fi
      if [ "$ROOT_LOGIN" = no ] && [ -z "$admin" ]; then
        [ "$TARGET_USER" = root ] && die "--root-login no would lock out root, the only SSH user."
        warn "Root login disabled but no sudo-capable SSH user was found."
      fi ;;
  esac
  [ "$SSH_VER_NUM" -gt 0 ] && [ "$SSH_VER_NUM" -lt 700 ] && [ "$ROOT_LOGIN" = prohibit-password ] && ROOT_LOGIN=without-password
  return 0
}

users_with_keys() {
  local u home shell
  while IFS=: read -r u _ uid _ _ home shell; do
    case "$shell" in */nologin|*/false) continue ;; esac
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } || continue
    if [ -s "$home/.ssh/authorized_keys" ]; then printf '%s ' "$u"; fi
  done </etc/passwd
  return 0
}

decide_allow_users() {
  ALLOW_USERS=""
  [ "$LEVEL" != basic ] || return 0
  local list="" others="" u def=n
  # root is pointless in AllowUsers when root login is disabled anyway
  if [ "$TARGET_USER" != root ] || [ "$ROOT_LOGIN" != no ]; then list="$TARGET_USER"; fi
  [ -n "$NEW_USER" ] && list="${list:+$list }$NEW_USER"
  [ -n "$list" ] || return 0
  for u in $(users_with_keys); do in_list "$u" "$list" || others="$others $u"; done
  if [ "$OPT_ALLOW_USERS" = 0 ]; then return 0; fi
  if [ "$OPT_ALLOW_USERS" != 1 ]; then
    say ""
    say "AllowUsers restricts SSH logins to an explicit list: $list"
    [ -n "$others" ] && warn "These users also have keys and would LOSE SSH access:$others"
    ask_yn "Enable AllowUsers?" "$def" || return 0
    local extra=""
    ask extra "Additional users to allow (space separated, empty for none)" ""
    for u in $extra; do id "$u" >/dev/null 2>&1 && list="$list $u" || warn "Skipping unknown user: $u"; done
  fi
  ALLOW_USERS="$list"
}

select_modules() {
  local def=n
  [ "$LEVEL" != basic ] && def=y
  section "Additional hardening"
  # Firewall opening is a safety measure, on by default whenever a firewall is active
  if [ -n "$OPT_FIREWALL" ]; then DO_FIREWALL="$OPT_FIREWALL"
  elif [ "$FW" != none ]; then
    if ask_yn "Open TCP $PORT in the active firewall ($FW)?" y; then DO_FIREWALL=1; fi
  else
    info "No active host firewall detected — remember your provider's security group / cloud firewall."
  fi
  if [ "$CONTAINER_KIND" = app ]; then
    info "Running inside a $VIRT container: skipping fail2ban, auto-updates and sysctl modules."
    return 0
  fi
  if [ -n "$OPT_FAIL2BAN" ]; then DO_FAIL2BAN="$OPT_FAIL2BAN"
  elif ask_yn "Install fail2ban (ban IPs with repeated SSH failures)?" "$def"; then DO_FAIL2BAN=1; fi
  if [ -n "$OPT_AUTOUPD" ]; then DO_AUTOUPD="$OPT_AUTOUPD"
  elif ask_yn "Enable automatic security updates?" "$def"; then DO_AUTOUPD=1; fi
  if [ "$CONTAINER_KIND" = system ]; then
    info "System container ($VIRT): kernel sysctl hardening is usually not permitted; skipping."
  elif [ -n "$OPT_SYSCTL" ]; then DO_SYSCTL="$OPT_SYSCTL"
  elif ask_yn "Apply kernel/network sysctl hardening?" "$def"; then DO_SYSCTL=1; fi
}

# ----------------------------------------------------------------------------
# sshd configuration generation
# ----------------------------------------------------------------------------
pick_algos() { # pick_algos kex|cipher|mac "pref1 pref2..." -> comma list of supported
  local type="$1" prefs="$2" supported out="" a
  have ssh || return 0
  supported="$(ssh -Q "$type" 2>/dev/null | tr '\n' ' ')"
  [ -n "$supported" ] || return 0
  for a in $prefs; do
    in_list "$a" "$supported" && out="${out:+$out,}$a"
  done
  printf '%s' "$out"
}

gen_hardening() {
  echo "PubkeyAuthentication yes"
  echo "PasswordAuthentication no"
  echo "KbdInteractiveAuthentication no"
  if [ "$SSH_VER_NUM" -gt 0 ] && [ "$SSH_VER_NUM" -lt 807 ]; then echo "ChallengeResponseAuthentication no"; fi
  echo "PermitEmptyPasswords no"
  echo "HostbasedAuthentication no"
  echo "IgnoreRhosts yes"
  echo "StrictModes yes"
  [ -n "$ROOT_LOGIN" ] && echo "PermitRootLogin $ROOT_LOGIN"
  [ "$LEVEL" = basic ] && return 0

  if [ "$LEVEL" = strict ]; then echo "MaxAuthTries 3"; echo "LoginGraceTime 20"
  else echo "MaxAuthTries 4"; echo "LoginGraceTime 30"; fi
  echo "MaxSessions 10"
  echo "MaxStartups 10:30:60"
  echo "ClientAliveInterval 300"
  echo "ClientAliveCountMax 2"
  echo "UseDNS no"
  echo "X11Forwarding no"
  echo "PermitUserEnvironment no"
  echo "LogLevel VERBOSE"
  # Drop SHA-1 / 64-bit-tag MACs from the defaults ("-" prefix needs OpenSSH 7.5+); strict sets an explicit list
  if [ "$LEVEL" = standard ] && [ "$SSH_VER_NUM" -ge 705 ]; then echo "MACs -hmac-md5*,hmac-sha1*,umac-64*"; fi
  if eff_has debianbanner; then echo "DebianBanner no"; fi
  [ -n "$ALLOW_USERS" ] && echo "AllowUsers $ALLOW_USERS"
  [ "$LEVEL" = strict ] || return 0

  echo "AllowTcpForwarding no"
  echo "AllowAgentForwarding no"
  if [ "$SSH_VER_NUM" -ge 700 ] || [ "$SSH_VER_NUM" -eq 0 ]; then echo "AllowStreamLocalForwarding no"; fi
  echo "PermitTunnel no"
  echo "GatewayPorts no"
  echo "RekeyLimit 512M 1h"
  echo "HostKey $SSH_DIR/ssh_host_ed25519_key"
  echo "HostKey $SSH_DIR/ssh_host_rsa_key"
  if [ "$STRICT_CRYPTO" = 1 ]; then
    local kex ciphers macs
    kex="$(pick_algos kex "mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com curve25519-sha256 curve25519-sha256@libssh.org diffie-hellman-group18-sha512 diffie-hellman-group16-sha512 diffie-hellman-group-exchange-sha256")"
    ciphers="$(pick_algos cipher "chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr")"
    macs="$(pick_algos mac "hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com")"
    [ -n "$kex" ] && echo "KexAlgorithms $kex"
    [ -n "$ciphers" ] && echo "Ciphers $ciphers"
    [ -n "$macs" ] && echo "MACs $macs"
  fi
  return 0
}

gen_config() { # gen_config warmup|final
  if [ "$1" = warmup ]; then
    local p
    echo "# Stage 1 (warmup): listen on old and new ports"
    for p in $PORT $CUR_PORTS; do echo "Port $p"; done | awk '!seen[$0]++'
  else
    echo "# Level: $LEVEL"
    echo "Port $PORT"
    gen_hardening
  fi
}

# Comment out directives (global section only) whose keyword is in KEYS (regex alternation)
neutralize_file() { # neutralize_file FILE KEYS
  local file="$1" keys="$2" tmp
  [ -f "$file" ] || return 0
  new_tmp; tmp="$NEW_TMP"
  awk -v keys="$keys" -v mark="$NEUTRAL_MARK" -v b="$BLOCK_BEGIN" -v e="$BLOCK_END" '
    $0 == b { skip=1; next }
    $0 == e { skip=0; after=1; next }
    skip { next }
    after && $0 == "" { after=0; next }
    { after=0 }
    /^# Managed by ssh-key helper/ { next }
    { t=$0; sub(/^[ \t]+/, "", t); split(t, a, /[ \t=]+/); k=tolower(a[1]) }
    k == "match" { inmatch=1 }
    !inmatch && t !~ /^#/ && k ~ ("^(" keys ")$") { print mark " " $0; next }
    { print }
  ' "$file" >"$tmp"
  if ! same_file "$tmp" "$file"; then cat "$tmp" >"$file"; fi
}

config_files() { # main config and all other drop-ins
  [ "$MAIN_CFG_MISSING" = 1 ] || echo "$SSHD_CFG"
  local f
  if [ -d "$SSHD_DROPIN_DIR" ]; then
    for f in "$SSHD_DROPIN_DIR"/*.conf; do
      [ -f "$f" ] && [ "$(basename "$f")" != "$DROPIN_NAME" ] && echo "$f"
    done
  fi
  return 0
}

write_sshd_config() { # write_sshd_config warmup|final
  local stage="$1" content keys f tmp
  content="$(gen_config "$stage")"
  keys="$(awk '!/^#/ && NF { print tolower($1) }' <<<"$content" | sort -u | paste -sd'|' -)"
  while IFS= read -r f; do neutralize_file "$f" "$keys"; done < <(config_files)

  local header
  header="# Generated by ssh-hardening v$SCRIPT_VERSION on $(date '+%F %T'). Restore: sh $BACKUP_DIR/restore.sh"
  if [ "$USE_DROPIN" = 1 ]; then
    mkdir -p "$SSHD_DROPIN_DIR"
    { echo "$header"; echo "$content"; } >"$SSHD_DROPIN_DIR/$DROPIN_NAME"
    chmod 600 "$SSHD_DROPIN_DIR/$DROPIN_NAME"
    run_restorecon "$SSHD_DROPIN_DIR/$DROPIN_NAME"
  else
    # First value wins in sshd_config, so the managed block goes to the very top
    new_tmp; tmp="$NEW_TMP"
    { echo "$BLOCK_BEGIN"; echo "$header"; echo "$content"; echo "$BLOCK_END"; echo; cat "$SSHD_CFG"; } >"$tmp"
    cat "$tmp" >"$SSHD_CFG"
  fi
  if [ "$MAIN_CFG_MISSING" = 0 ]; then chmod 600 "$SSHD_CFG"; run_restorecon "$SSHD_CFG"; fi
}

# Verify the effective configuration really is what we wrote (catches overrides)
verify_effective() {
  load_eff || { err "sshd -T failed."; return 1; }
  local bad=0 v ports
  ports="$(eff_all port | sort -u | tr '\n' ' ')"
  if [ "$(trim "$ports")" != "$PORT" ]; then err "Effective ports are '$ports', expected '$PORT'."; bad=1; fi
  local la
  for la in $(eff_all listenaddress); do
    case "$la" in *:"$PORT") ;; *) err "ListenAddress $la does not use port $PORT."; bad=1 ;; esac
  done
  check_kv() {
    v="$(lower "$(eff "$1")")"
    if [ -n "$v" ] && [ "$v" != "$2" ]; then err "Effective $1 is '$v', expected '$2'."; bad=1; fi
  }
  check_kv passwordauthentication no
  check_kv pubkeyauthentication yes
  check_kv kbdinteractiveauthentication no
  check_kv permitemptypasswords no
  case "$ROOT_LOGIN" in
    no) check_kv permitrootlogin no ;;
    prohibit-password|without-password) check_kv permitrootlogin without-password ;;
  esac
  if [ "$bad" = 1 ]; then
    err "Another configuration source overrides the hardening. Files mentioning these settings:"
    grep -rniE '^[[:space:]]*(port|passwordauthentication|permitrootlogin|kbdinteractiveauthentication|listenaddress)[[:space:]]' \
      ${VENDOR_CFG:+"$VENDOR_CFG"} "$SSH_DIR"/sshd_config "$SSHD_DROPIN_DIR" 2>/dev/null | sed 's/^/    /' >&2 || true
    return 1
  fi
  ok "Effective configuration verified (sshd -T)."
}

warn_match_overrides() {
  local f hits
  while IFS= read -r f; do
    hits="$(awk '
      { t=$0; sub(/^[ \t]+/, "", t); split(t, a, /[ \t=]+/); k=tolower(a[1]); v=tolower(a[2]) }
      k=="match" { m=1; hdr=t; next }
      m && t !~ /^#/ && ((k=="passwordauthentication" && v=="yes") || (k=="permitrootlogin" && v=="yes") || (k=="kbdinteractiveauthentication" && v=="yes")) { print "    " FILENAME ": [" hdr "] " t }
    ' "$f")"
    if [ -n "$hits" ]; then
      warn "Match blocks re-enable weaker authentication for some connections:"
      say "$hits"
    fi
  done < <(config_files; [ -f "$SSHD_DROPIN_DIR/$DROPIN_NAME" ] && echo "$SSHD_DROPIN_DIR/$DROPIN_NAME")
  return 0
}

# ----------------------------------------------------------------------------
# Backup & restore
# ----------------------------------------------------------------------------
create_backup() {
  local base n=1
  base="$STATE_DIR/backup-$(date +%Y%m%d-%H%M%S)"
  BACKUP_DIR="$base"
  # Never reuse a directory (two runs in the same second); "-N" suffixes still sort after the base name
  while ! mkdir "$BACKUP_DIR" 2>/dev/null; do n=$((n + 1)); BACKUP_DIR="$base-$n"; done
  chmod 700 "$BACKUP_DIR"
  if [ "$MAIN_CFG_MISSING" = 1 ]; then : >"$BACKUP_DIR/no_main_cfg"; else cp -p "$SSHD_CFG" "$BACKUP_DIR/sshd_config"; fi
  if [ -d "$SSHD_DROPIN_DIR" ]; then cp -a "$SSHD_DROPIN_DIR" "$BACKUP_DIR/sshd_config.d"; else : >"$BACKUP_DIR/no_dropin_dir"; fi
  [ -f "$SSH_DIR/moduli" ] && cp -p "$SSH_DIR/moduli" "$BACKUP_DIR/moduli"
  {
    echo "date=$(date '+%F %T')"
    echo "version=$SCRIPT_VERSION"
    echo "old_ports=$CUR_PORTS"
    echo "new_port=$PORT"
    echo "level=$LEVEL"
  } >"$BACKUP_DIR/meta"
  write_restore_script
  ok "Backup: $BACKUP_DIR"
}

write_restore_script() {
  cat >"$BACKUP_DIR/restore.sh" <<EOF
#!/bin/sh
# Generated by ssh-hardening v$SCRIPT_VERSION on $(date '+%F %T').
# Restores the SSH server configuration to the state before that run.
B='$BACKUP_DIR'
CFG='$SSHD_CFG'
DROPIN_DIR='$SSHD_DROPIN_DIR'
DROPIN='$SSHD_DROPIN_DIR/$DROPIN_NAME'
SSH_DIR='$SSH_DIR'
SVC='$SSH_SERVICE'
SOCK='$SSH_SOCKET'
echo "[restore] Restoring SSH configuration from \$B"
if [ -f "\$B/sshd_config" ]; then cp -p "\$B/sshd_config" "\$CFG"; fi
rm -f "\$DROPIN"
if [ -d "\$B/sshd_config.d" ]; then
  mkdir -p "\$DROPIN_DIR" && cp -a "\$B/sshd_config.d/." "\$DROPIN_DIR/"
elif [ -f "\$B/no_dropin_dir" ]; then
  rmdir "\$DROPIN_DIR" 2>/dev/null || true
fi
if [ -f "\$B/moduli" ]; then cp -p "\$B/moduli" "\$SSH_DIR/moduli"; fi
if [ -f "\$B/disabled_hostkeys" ]; then
  while IFS= read -r f; do [ -f "\$f.disabled" ] && mv "\$f.disabled" "\$f"; done < "\$B/disabled_hostkeys"
fi
command -v restorecon >/dev/null 2>&1 && restorecon -R "\$SSH_DIR" 2>/dev/null
rc=0
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload 2>/dev/null
  if [ -f "\$B/socket_converted" ]; then
    SOCK=\$(cat "\$B/socket_unit")
    systemctl stop "\$SVC" 2>/dev/null
    [ "\$(cat "\$B/socket_converted")" = service-was-disabled ] && systemctl disable "\$SVC" 2>/dev/null
    systemctl enable --now "\$SOCK" || rc=1
  elif [ -n "\$SOCK" ]; then
    systemctl restart "\$SOCK" || rc=1
  else
    systemctl restart "\$SVC" || rc=1
  fi
elif command -v rc-service >/dev/null 2>&1; then
  rc-service "\$SVC" restart || rc=1
elif command -v sv >/dev/null 2>&1 && [ -e "/var/service/\$SVC" ]; then
  sv restart "\$SVC" || rc=1
elif command -v service >/dev/null 2>&1; then
  service "\$SVC" restart || rc=1
else
  "/etc/init.d/\$SVC" restart || rc=1
fi
: > "\$B/restored"
echo "[restore] Done (restart status: \$rc). Firewall rules, SELinux port labels and created users are left in place."
exit \$rc
EOF
  chmod 700 "$BACKUP_DIR/restore.sh"
}

run_restore() {
  local dir="$OPT_RESTORE_DIR"
  if [ -z "$dir" ]; then
    dir="$(ls -1d "$STATE_DIR"/backup-* 2>/dev/null | sort | tail -n1 || true)"
  fi
  [ -n "$dir" ] && [ -f "$dir/restore.sh" ] || die "No backup found${dir:+ in $dir} (backups live in $STATE_DIR)."
  section "Restore"
  say "  Backup: $dir"
  [ -f "$dir/meta" ] && sed 's/^/    /' "$dir/meta" >&2
  ask_yn "Restore this SSH configuration now?" y || die "Aborted."
  if sh "$dir/restore.sh" >&2; then ok "Restored. Verify you can log in on the old port before closing this session."
  else die "Restore script reported an error."; fi
}

# ----------------------------------------------------------------------------
# Pre-apply system changes: SELinux, firewall, reserved port, host keys
# ----------------------------------------------------------------------------
selinux_allow_port() {
  have getenforce || return 0
  local mode
  mode="$(getenforce 2>/dev/null || echo Disabled)"
  [ "$mode" != Disabled ] || return 0
  [ "$PORT" != 22 ] || return 0
  if ! have semanage; then
    case "$PKG" in
      dnf) pkg_install policycoreutils-python-utils || true ;;
      yum) pkg_install policycoreutils-python || pkg_install policycoreutils-python-utils || true ;;
      zypper) pkg_install policycoreutils-python-utils || true ;;
      apt-get) pkg_install policycoreutils-python-utils || true ;;
    esac
  fi
  if ! have semanage; then
    if [ "$mode" = Enforcing ]; then die "SELinux is enforcing and 'semanage' is unavailable: sshd could not bind port $PORT."; fi
    warn "semanage unavailable; SELinux is $mode, continuing."
    return 0
  fi
  local labelled
  labelled="$(semanage port -l 2>/dev/null | awk '$1=="ssh_port_t" { $1=""; $2=""; gsub(/ /, ""); print }')"
  if in_list "$PORT" "${labelled//,/ }"; then
    info "SELinux already allows sshd on port $PORT."
    return 0
  fi
  if semanage port -a -t ssh_port_t -p tcp "$PORT" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$PORT" 2>/dev/null; then
    ok "SELinux: labelled tcp/$PORT as ssh_port_t."
    summary "SELinux: tcp/$PORT labelled ssh_port_t"
  else
    die "Failed to label port $PORT for SELinux (semanage port -a -t ssh_port_t -p tcp $PORT)."
  fi
}

firewall_open_port() {
  [ "$DO_FIREWALL" = 1 ] || return 0
  case "$FW" in
    ufw)
      ufw allow "$PORT/tcp" comment 'ssh-hardening' >/dev/null 2>&1 || ufw allow "$PORT/tcp" >/dev/null 2>&1 \
        || { warn "ufw: failed to allow $PORT/tcp"; return 1; }
      ok "ufw: allowed $PORT/tcp" ;;
    firewalld)
      firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null 2>&1 && firewall-cmd --add-port="$PORT/tcp" >/dev/null 2>&1 \
        || { warn "firewalld: failed to open $PORT/tcp"; return 1; }
      ok "firewalld: opened $PORT/tcp (runtime + permanent, default zone)" ;;
    iptables)
      local t
      for t in iptables ip6tables; do
        have "$t" || continue
        "$t" -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || "$t" -I INPUT 1 -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
      done
      ok "iptables: inserted ACCEPT rule for tcp/$PORT"
      if have netfilter-persistent; then netfilter-persistent save >/dev/null 2>&1 && ok "Rules saved (netfilter-persistent)."
      elif [ "$FAMILY" = rhel ] && have service && service iptables save >/dev/null 2>&1; then ok "Rules saved (service iptables save)."
      elif [ "$INIT" = openrc ] && rc-service iptables save >/dev/null 2>&1; then ok "Rules saved (rc-service iptables save)."
      else warn "iptables rule is NOT persistent across reboots. Save it with your distro's tool (e.g. iptables-save > /etc/iptables/rules.v4)."; fi ;;
    nftables)
      local fam tbl
      for fam_tbl in "inet filter" "ip filter"; do
        fam="${fam_tbl% *}"; tbl="${fam_tbl#* }"
        if nft list chain "$fam" "$tbl" input >/dev/null 2>&1; then
          nft insert rule "$fam" "$tbl" input tcp dport "$PORT" accept && ok "nftables: inserted accept rule for tcp/$PORT ($fam $tbl input)"
          warn "Add 'tcp dport $PORT accept' to /etc/nftables.conf as well, or the rule is lost on reboot."
          return 0
        fi
      done
      warn "nftables input chain not found automatically — add 'tcp dport $PORT accept' manually BEFORE continuing."
      ask_yn "Have you opened TCP $PORT yourself?" n || die "Aborted: port not opened." ;;
  esac
  summary "Firewall ($FW): TCP $PORT opened"
}

reserve_port() {
  [ "$PORT_IN_EPHEMERAL" = 1 ] || return 0
  [ "$CONTAINER_KIND" != app ] || return 0
  local f=/proc/sys/net/ipv4/ip_local_reserved_ports cur item lo hi new
  [ -w "$f" ] || return 0
  cur="$(cat "$f")"
  for item in ${cur//,/ }; do
    lo="${item%-*}"; hi="${item#*-}"
    if [ "$PORT" -ge "$lo" ] && [ "$PORT" -le "$hi" ]; then return 0; fi
  done
  new="${cur:+$cur,}$PORT"
  if echo "$new" >"$f" 2>/dev/null; then
    mkdir -p /etc/sysctl.d
    printf '# ssh-hardening: keep the SSH port out of the ephemeral port pool\nnet.ipv4.ip_local_reserved_ports = %s\n' "$new" >"$SYSCTL_PORT_FILE"
    chmod 644 "$SYSCTL_PORT_FILE"
    ok "Reserved port $PORT (net.ipv4.ip_local_reserved_ports)."
  fi
}

prepare_host_keys() {
  local t bits
  [ "$LEVEL" = strict ] || return 0
  # Strict pins HostKey to Ed25519 + RSA: generate them if missing (never DSA)
  if [ ! -f "$SSH_DIR/ssh_host_ed25519_key" ]; then ssh-keygen -q -t ed25519 -N '' -f "$SSH_DIR/ssh_host_ed25519_key" && ok "Generated Ed25519 host key."; fi
  if [ ! -f "$SSH_DIR/ssh_host_rsa_key" ]; then ssh-keygen -q -t rsa -b 4096 -N '' -f "$SSH_DIR/ssh_host_rsa_key" && ok "Generated RSA-4096 host key."; fi
  for t in "$SSH_DIR/ssh_host_dsa_key" "$SSH_DIR/ssh_host_dsa_key.pub"; do
    if [ -f "$t" ]; then mv "$t" "$t.disabled"; echo "$t" >>"$BACKUP_DIR/disabled_hostkeys"; ok "Disabled DSA host key: $t"; fi
  done
  bits="$(ssh-keygen -l -f "$SSH_DIR/ssh_host_rsa_key.pub" 2>/dev/null | awk '{print $1}' || true)"
  if [ -n "$bits" ] && [ "$bits" -lt 3072 ]; then
    warn "RSA host key is only $bits bits. Regenerating changes the host fingerprint, so it is left alone:"
    warn "  ssh-keygen -f $SSH_DIR/ssh_host_rsa_key -t rsa -b 4096 -N '' (then update clients' known_hosts)"
  fi
  # Drop Diffie-Hellman group-exchange moduli smaller than 3072 bits
  if [ -f "$SSH_DIR/moduli" ]; then
    local tmp
    new_tmp; tmp="$NEW_TMP"
    awk '/^#/ || $5 >= 3071' "$SSH_DIR/moduli" >"$tmp"
    if [ "$(grep -vc '^#' "$tmp" || true)" -gt 0 ] && ! same_file "$tmp" "$SSH_DIR/moduli"; then
      cat "$tmp" >"$SSH_DIR/moduli"
      ok "Removed DH moduli < 3072 bits from $SSH_DIR/moduli."
    fi
  fi
  if [ -d /etc/crypto-policies ]; then
    warn "This system uses crypto-policies. On RHEL 8 they are passed to sshd on the command line and override"
    warn "the Ciphers/MACs/KexAlgorithms set here; consider: update-crypto-policies --set FUTURE"
  fi
}

# ----------------------------------------------------------------------------
# Apply, verify, confirm
# ----------------------------------------------------------------------------
apply_stage() { # apply_stage warmup|final "ports to verify"
  local stage="$1" ports="$2"
  write_sshd_config "$stage"
  if ! sshd_test; then
    if [ "$stage" = final ] && [ "$LEVEL" = strict ] && [ "$STRICT_CRYPTO" = 1 ]; then
      warn "sshd rejected the algorithm lists ($SSHD_TEST_OUT); retrying with the distro's default crypto."
      STRICT_CRYPTO=0
      write_sshd_config "$stage"
      sshd_test || { err "sshd -t: $SSHD_TEST_OUT"; return 1; }
    else
      err "sshd -t: $SSHD_TEST_OUT"
      return 1
    fi
  fi
  ok "Configuration syntax OK (sshd -t)."
  if [ "$stage" = final ]; then verify_effective || return 1; fi
  restart_and_verify "$ports"
}

ssh_self_test() {
  local out rc=0
  have ssh || { warn "ssh client not found; skipping self-test."; return 0; }
  out="$(ssh -o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout="$SSH_SELFTEST_TIMEOUT" \
        -p "$PORT" "$TARGET_USER@127.0.0.1" true 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    warn "Self-test failed (exit $rc): $(printf '%s' "$out" | tail -n1)"
    return 1
  fi
  ok "Self-test: key login to $TARGET_USER@127.0.0.1:$PORT works."
}

# The account to test with: root is useless once root login is disabled
login_user() {
  if [ "$TARGET_USER" = root ] && [ "$ROOT_LOGIN" = no ] && [ -n "$NEW_USER" ]; then echo "$NEW_USER"; else echo "$TARGET_USER"; fi
}

# Dead-man switch: roll back automatically unless a new login is confirmed in time
confirm_new_login() {
  if [ "$CONFIRM_TIMEOUT" -eq 0 ] || [ -z "$TTY_FD" ] || [ "$ASSUME_YES" = 1 ]; then
    warn "Login confirmation skipped (non-interactive or --confirm-timeout 0)."
    warn "Keep this session open and test: ssh -p $PORT $(login_user)@$SERVER_IP"
    return 0
  fi
  local deadman="$BACKUP_DIR/deadman.sh" pid start left ans
  cat >"$deadman" <<EOF
#!/bin/sh
sleep $CONFIRM_TIMEOUT
[ -e '$BACKUP_DIR/confirmed' ] && exit 0
[ -e '$BACKUP_DIR/restored' ] && exit 0
sh '$BACKUP_DIR/restore.sh' >> '$BACKUP_DIR/deadman.log' 2>&1
EOF
  chmod 700 "$deadman"
  if have setsid; then nohup setsid sh "$deadman" </dev/null >/dev/null 2>&1 3<&- &
  else nohup sh "$deadman" </dev/null >/dev/null 2>&1 3<&- & fi
  pid=$!

  section "Confirm your new login (auto-rollback in ${CONFIRM_TIMEOUT}s)"
  say "  1. Keep THIS session open."
  say "  2. In a NEW terminal run:   ${C_BOLD}ssh -p $PORT $(login_user)@$SERVER_IP${C_0}"
  say "     (also allow TCP $PORT in your cloud provider's security group / firewall)"
  say "  3. If the login works, type 'yes' here. Type 'rollback' to revert now."
  say "  If nothing is confirmed in time, or this session drops, the old configuration is restored."
  start=$SECONDS
  while true; do
    left=$(( CONFIRM_TIMEOUT - (SECONDS - start) ))
    if [ "$left" -le 0 ]; then ans=""; break; fi
    if ! read_tty ans "Login works? (yes/rollback, ${left}s left): " "$left"; then
      [ -n "$ans" ] || { ans=""; break; }
    fi
    ans="$(lower "$(trim "$ans")")"
    case "$ans" in
      yes|y) : >"$BACKUP_DIR/confirmed"; kill "$pid" 2>/dev/null || true; CONFIRMED_LOGIN=1; ok "Confirmed. Rollback timer cancelled."; return 0 ;;
      rollback|no|n) break ;;
      *) say "Please type 'yes' or 'rollback'." ;;
    esac
  done
  say ""
  : >"$BACKUP_DIR/confirmed"
  kill "$pid" 2>/dev/null || true
  ROLLBACK_ARMED=0
  warn "Not confirmed — restoring the previous SSH configuration."
  sh "$BACKUP_DIR/restore.sh" >&2 || err "Restore reported an error; see output above."
  die "Rolled back. Nothing else was changed. Check firewall/security group and keys, then re-run."
}

# ----------------------------------------------------------------------------
# Optional modules
# ----------------------------------------------------------------------------
setup_auto_updates() {
  section "Automatic security updates"
  case "$FAMILY" in
    debian)
      pkg_install unattended-upgrades || { warn "Could not install unattended-upgrades."; return 1; }
      [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && cp -p /etc/apt/apt.conf.d/20auto-upgrades "$BACKUP_DIR/" 2>/dev/null
      cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
      chmod 644 /etc/apt/apt.conf.d/20auto-upgrades
      if [ "$INIT" = systemd ]; then systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true; fi
      ok "unattended-upgrades enabled (security origins only; automatic reboot stays off)."
      summary "Auto updates: unattended-upgrades" ;;
    rhel)
      if [ "$PKG" = dnf ]; then
        pkg_install dnf-automatic || pkg_install dnf5-plugin-automatic || { warn "Could not install dnf-automatic."; return 1; }
        local conf=/etc/dnf/automatic.conf type=security
        [ "$OS_ID" = centos ] && type=default   # CentOS Stream publishes no security errata
        if [ -f "$conf" ]; then
          cp -p "$conf" "$BACKUP_DIR/" 2>/dev/null || true
          sed -i -E "s/^#?[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = $type/; s/^#?[[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/" "$conf"
          grep -q '^upgrade_type' "$conf" || sed -i "/^\[commands\]/a upgrade_type = $type" "$conf"
          grep -q '^apply_updates' "$conf" || sed -i "/^\[commands\]/a apply_updates = yes" "$conf"
        else
          printf '[commands]\nupgrade_type = %s\napply_updates = yes\n' "$type" >"$conf"
        fi
        local t done_t=""
        for t in dnf-automatic.timer dnf5-automatic.timer dnf-automatic-install.timer; do
          if systemctl enable --now "$t" >/dev/null 2>&1; then done_t="$t"; break; fi
        done
        [ -n "$done_t" ] || { warn "Could not enable a dnf-automatic timer."; return 1; }
        ok "dnf-automatic enabled ($done_t, upgrade_type=$type)."
        summary "Auto updates: dnf-automatic ($type)"
      else
        pkg_install yum-cron || { warn "Could not install yum-cron."; return 1; }
        sed -i -E 's/^update_cmd[[:space:]]*=.*/update_cmd = security/; s/^apply_updates[[:space:]]*=.*/apply_updates = yes/' /etc/yum/yum-cron.conf
        svc_enable_start yum-cron || true
        ok "yum-cron enabled (security updates)."
        summary "Auto updates: yum-cron"
      fi ;;
    suse)
      [ "$INIT" = systemd ] || { warn "Automatic updates on SUSE require systemd here; skipped."; return 1; }
      cat >/etc/systemd/system/ssh-hardening-security-patch.service <<'EOF'
[Unit]
Description=Install security patches (ssh-hardening)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper --non-interactive patch --category security --auto-agree-with-licenses
EOF
      cat >/etc/systemd/system/ssh-hardening-security-patch.timer <<'EOF'
[Unit]
Description=Daily security patches (ssh-hardening)

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
      systemctl daemon-reload && systemctl enable --now ssh-hardening-security-patch.timer >/dev/null 2>&1 \
        || { warn "Could not enable the zypper patch timer."; return 1; }
      ok "Daily 'zypper patch --category security' timer enabled."
      summary "Auto updates: zypper security patch timer" ;;
    alpine)
      warn "Alpine has no official unattended-upgrade mechanism; schedule 'apk -U upgrade' yourself if desired."; return 1 ;;
    arch)
      warn "Unattended upgrades are not recommended on Arch (rolling release); skipped."; return 1 ;;
    *)
      warn "Automatic updates are not supported for this distribution; skipped."; return 1 ;;
  esac
}

pick_f2b_banaction() {
  local d=/etc/fail2ban/action.d
  if [ "$FW" = firewalld ] && [ -f "$d/firewallcmd-rich-rules.conf" ]; then echo firewallcmd-rich-rules
  elif [ "$FW" = ufw ] && [ -f "$d/ufw.conf" ]; then echo ufw
  elif have nft && { ! have iptables || [ "$FW" = nftables ]; } && [ -f "$d/nftables-multiport.conf" ]; then echo nftables-multiport
  elif have iptables && [ -f "$d/iptables-multiport.conf" ]; then echo iptables-multiport
  elif have nft && [ -f "$d/nftables-multiport.conf" ]; then echo nftables-multiport
  fi
}

setup_fail2ban() {
  section "fail2ban"
  if ! have fail2ban-client; then
    local extra=()
    [ "$FAMILY" = debian ] && [ "$INIT" = systemd ] && extra=(python3-systemd)
    if ! pkg_install fail2ban ${extra[@]+"${extra[@]}"}; then
      if [ "$FAMILY" = rhel ] && [ "$PKG" != yum ] && ask_yn "fail2ban requires the EPEL repository. Enable EPEL?" y; then
        case "$OS_ID" in
          ol) pkg_install "oracle-epel-release-el${OS_VER%%.*}" || true ;;
          *) pkg_install epel-release || true ;;
        esac
        pkg_install fail2ban || true
      fi
    fi
  fi
  have fail2ban-client || { warn "fail2ban is not available; skipped."; return 1; }

  local backend=auto banaction ignore="127.0.0.1/8 ::1"
  if [ ! -f /var/log/auth.log ] && [ ! -f /var/log/secure ] && [ ! -f /var/log/messages ]; then
    # Debian 12+/Ubuntu 24.04 minimal images log only to the journal
    if [ "$INIT" = systemd ] && have journalctl; then backend=systemd
    else warn "No SSH log file (auth.log/secure/messages) and no systemd journal: install a syslog daemon first."; return 1; fi
  fi
  banaction="$(pick_f2b_banaction)"
  [ -n "$CLIENT_IP" ] && ignore="$ignore $CLIENT_IP"
  mkdir -p /etc/fail2ban/jail.d
  {
    echo "# Generated by ssh-hardening v$SCRIPT_VERSION"
    echo "[sshd]"
    echo "enabled = true"
    echo "port = $PORT"
    echo "backend = $backend"
    echo "maxretry = 5"
    echo "findtime = 10m"
    echo "bantime = 1h"
    echo "bantime.increment = true"
    echo "bantime.maxtime = 1w"
    echo "ignoreip = $ignore"
    [ -n "$banaction" ] && echo "banaction = $banaction"
  } >"$F2B_JAIL_FILE"
  chmod 644 "$F2B_JAIL_FILE"
  if ! fail2ban-client -t >/dev/null 2>&1 && ! fail2ban-client --test >/dev/null 2>&1; then
    warn "fail2ban rejected the configuration; removing $F2B_JAIL_FILE."
    rm -f "$F2B_JAIL_FILE"
    return 1
  fi
  svc_enable_start fail2ban || true
  sleep 2
  if fail2ban-client status sshd >/dev/null 2>&1; then
    ok "fail2ban active: sshd jail on port $PORT (backend=$backend${banaction:+, $banaction}${CLIENT_IP:+, whitelisted $CLIENT_IP})."
    summary "fail2ban: sshd jail enabled"
  else
    warn "fail2ban did not report the sshd jail yet; check: fail2ban-client status sshd"
  fi
}

setup_sysctl() {
  section "Kernel / network sysctl hardening"
  local entries=(
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv6.conf.all.accept_source_route=0"
    "net.ipv6.conf.default.accept_source_route=0"
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"
    "kernel.kptr_restrict=1"
    "kernel.dmesg_restrict=1"
    "kernel.yama.ptrace_scope=1"
    "fs.protected_hardlinks=1"
    "fs.protected_symlinks=1"
    "fs.suid_dumpable=0"
  )
  if [ "$LEVEL" = strict ]; then
    entries+=(
      "net.ipv4.conf.all.log_martians=1"
      "net.ipv4.conf.default.log_martians=1"
      "kernel.unprivileged_bpf_disabled=1"
      "net.core.bpf_jit_harden=2"
      "fs.protected_fifos=2"
      "fs.protected_regular=2"
    )
  fi
  local e k v path applied=0 skipped=0 tmp
  new_tmp; tmp="$NEW_TMP"
  echo "# Generated by ssh-hardening v$SCRIPT_VERSION ($LEVEL). Remove this file and reboot to revert." >"$tmp"
  for e in "${entries[@]}"; do
    k="${e%%=*}"; v="${e#*=}"
    path="/proc/sys/${k//.//}"
    if [ ! -e "$path" ]; then skipped=$((skipped + 1)); continue; fi
    if echo "$v" >"$path" 2>/dev/null; then
      echo "$k = $v" >>"$tmp"
      applied=$((applied + 1))
    else
      skipped=$((skipped + 1))
    fi
  done
  mkdir -p /etc/sysctl.d
  [ -f "$SYSCTL_FILE" ] && cp -p "$SYSCTL_FILE" "$BACKUP_DIR/" 2>/dev/null
  cat "$tmp" >"$SYSCTL_FILE"
  chmod 644 "$SYSCTL_FILE"
  ok "Applied $applied sysctl setting(s) live and persisted them in $SYSCTL_FILE ($skipped not supported/permitted)."
  info "IP forwarding and rp_filter are deliberately untouched (Docker/VPN/router hosts depend on them)."
  summary "sysctl: $applied settings in $SYSCTL_FILE"
}

check_reboot_required() {
  REBOOT_REASONS=()
  [ "$CONTAINER_KIND" = "" ] || return 0
  if [ -f /var/run/reboot-required ]; then
    REBOOT_REASONS+=("system reports /var/run/reboot-required$( [ -f /var/run/reboot-required.pkgs ] && printf ' (%s)' "$(tr '\n' ' ' </var/run/reboot-required.pkgs | sed 's/ $//')")")
  fi
  if have needs-restarting; then
    needs-restarting -r >/dev/null 2>&1 || [ $? -ne 1 ] || REBOOT_REASONS+=("needs-restarting: core libraries or kernel updated")
  elif [ "$PKG" = dnf ] && dnf needs-restarting --help >/dev/null 2>&1; then
    dnf needs-restarting -r >/dev/null 2>&1 || [ $? -ne 1 ] || REBOOT_REASONS+=("dnf needs-restarting: core libraries or kernel updated")
  fi
  if [ "$PKG" = zypper ]; then
    zypper needs-rebooting >/dev/null 2>&1 || [ $? -ne 102 ] || REBOOT_REASONS+=("zypper needs-rebooting")
  fi
  if [ -d /lib/modules ] && [ ! -d "/lib/modules/$(uname -r)" ] && [ -n "$(ls /lib/modules 2>/dev/null)" ]; then
    REBOOT_REASONS+=("running kernel $(uname -r) is no longer installed (kernel was upgraded)")
  fi
  return 0
}

reboot_prompt() {
  [ "$CONTAINER_KIND" != app ] || return 0
  check_reboot_required
  if [ "$LEVEL" = basic ] && [ ${#REBOOT_REASONS[@]} -eq 0 ] && [ "$OPT_REBOOT" != 1 ]; then
    info "No reboot required (SSH changes are live)."
    return 0
  fi
  section "Reboot"
  local r
  if [ ${#REBOOT_REASONS[@]} -gt 0 ]; then
    warn "A reboot is REQUIRED to finish applying updates:"
    for r in "${REBOOT_REASONS[@]}"; do say "    - $r"; done
  else
    say "  Not strictly required: SSH, firewall and sysctl changes are already live."
    say "  Recommended once, while you still have console access: a reboot proves that sshd,"
    say "  the firewall rule and the sysctl settings all come back correctly on port $PORT."
  fi
  if [ "$CONFIRMED_LOGIN" != 1 ] && [ "$OPT_REBOOT" != 1 ]; then
    warn "Verify a NEW login on port $PORT before rebooting: ssh -p $PORT $(login_user)@$SERVER_IP"
  fi
  local do_reboot=0
  if [ "$OPT_REBOOT" = 1 ]; then do_reboot=1
  elif [ "$OPT_REBOOT" = 0 ]; then do_reboot=0
  elif ask_yn "Reboot now?" n; then do_reboot=1; fi
  if [ "$do_reboot" = 0 ]; then
    [ ${#REBOOT_REASONS[@]} -gt 0 ] && warn "Remember to reboot soon (sudo reboot)."
    return 0
  fi
  local i
  for i in 10 9 8 7 6 5 4 3 2 1; do printf '\rRebooting in %2ds (Ctrl+C to cancel)... ' "$i" >&2; sleep 1; done
  printf '\n' >&2
  _log "Rebooting"
  sync
  if have systemctl && [ "$INIT" = systemd ]; then systemctl reboot; else reboot; fi
}

# ----------------------------------------------------------------------------
# Audit (read-only)
# ----------------------------------------------------------------------------
audit_line() { # audit_line PASS|WARN|FAIL|INFO "text"
  local c
  case "$1" in PASS) c="$C_G" ;; WARN) c="$C_Y" ;; FAIL) c="$C_R" ;; *) c="$C_B" ;; esac
  printf '  %s%-4s%s %s\n' "$c" "$1" "$C_0" "$2" >&2
}

run_audit() {
  section "SSH server (effective configuration)"
  if ! sshd_test; then audit_line FAIL "sshd -t: $SSHD_TEST_OUT"; fi
  load_eff || { audit_line FAIL "sshd -T failed; cannot read effective configuration"; return 0; }
  local v p
  p="$(eff_all port | tr '\n' ' ')"
  p="$(trim "$p")"
  if in_list 22 "$p"; then audit_line WARN "Port: $p (default port 22 attracts constant scanning)"; else audit_line PASS "Port: $p"; fi
  v="$(eff passwordauthentication)"; [ "$v" = no ] && audit_line PASS "PasswordAuthentication no" || audit_line FAIL "PasswordAuthentication $v"
  v="$(eff kbdinteractiveauthentication)"
  if [ -n "$v" ]; then [ "$v" = no ] && audit_line PASS "KbdInteractiveAuthentication no" || audit_line WARN "KbdInteractiveAuthentication $v (may allow password prompts via PAM)"; fi
  v="$(eff permitrootlogin)"
  case "$v" in no) audit_line PASS "PermitRootLogin no" ;; without-password|prohibit-password) audit_line PASS "PermitRootLogin $v (key only)" ;; *) audit_line FAIL "PermitRootLogin $v" ;; esac
  v="$(eff permitemptypasswords)"; [ "$v" = no ] && audit_line PASS "PermitEmptyPasswords no" || audit_line FAIL "PermitEmptyPasswords $v"
  v="$(eff maxauthtries)"; [ "${v:-6}" -le 4 ] && audit_line PASS "MaxAuthTries $v" || audit_line WARN "MaxAuthTries $v (recommend <= 4)"
  v="$(eff x11forwarding)"; [ "$v" = no ] && audit_line PASS "X11Forwarding no" || audit_line WARN "X11Forwarding $v"
  v="$(eff loglevel)"; audit_line INFO "LogLevel $v"
  v="$(eff allowusers | tr '\n' ' ')"; [ -n "$v" ] && audit_line INFO "AllowUsers $v"
  local weak=""
  weak="$( { eff ciphers; eff macs; eff kexalgorithms; } | tr ',' '\n' | grep -E -- '-cbc$|^3des|arcfour|hmac-md5|hmac-sha1|umac-64|diffie-hellman-group1-|diffie-hellman-group14-sha1|group-exchange-sha1' | tr '\n' ' ' || true)"
  if [ -n "$weak" ]; then audit_line WARN "Weak algorithms enabled: $weak"; else audit_line PASS "No legacy ciphers/MACs/KEX enabled"; fi
  if [ -f "$SSH_DIR/ssh_host_dsa_key" ]; then audit_line WARN "DSA host key present"; fi
  if [ -d "$SSHD_DROPIN_DIR" ]; then
    local hits
    hits="$(grep -liE '^[[:space:]]*passwordauthentication[[:space:]]+yes' "$SSHD_DROPIN_DIR"/*.conf 2>/dev/null | tr '\n' ' ' || true)"
    [ -n "$hits" ] && audit_line WARN "Drop-ins enabling password auth: $hits"
  fi

  section "Accounts with SSH keys"
  local u home line n weakk
  while IFS=: read -r u _ uid _ _ home shell; do
    { [ "$uid" -eq 0 ] || [ "$uid" -ge 1000 ]; } || continue
    [ -f "$home/.ssh/authorized_keys" ] || continue
    n=0; weakk=0
    while IFS= read -r line || [ -n "$line" ]; do
      line="$(trim "$line")"; case "$line" in ""|\#*) continue ;; esac
      key_info "$line" || continue
      n=$((n + 1))
      key_usable >/dev/null 2>&1 || weakk=$((weakk + 1))
      if [ "$KI_TYPE" = ssh-rsa ] && [ -n "$KI_BITS" ] && [ "$KI_BITS" -lt 3072 ]; then weakk=$((weakk + 1)); fi
    done <"$home/.ssh/authorized_keys"
    if [ "$weakk" -gt 0 ]; then audit_line WARN "$u: $n key(s), $weakk weak (DSA / RSA < 3072)"
    else audit_line PASS "$u: $n key(s)"; fi
  done </etc/passwd

  section "System"
  case "$FW" in none) audit_line WARN "No active host firewall detected (cloud firewall may still apply)" ;; *) audit_line PASS "Firewall: $FW" ;; esac
  if have fail2ban-client && fail2ban-client status sshd >/dev/null 2>&1; then audit_line PASS "fail2ban sshd jail active"
  else audit_line INFO "fail2ban sshd jail not active"; fi
  local au="none"
  if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades; then au="unattended-upgrades"
  elif [ "$INIT" = systemd ] && { systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || systemctl is-enabled dnf5-automatic.timer >/dev/null 2>&1 || systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1; }; then au="dnf-automatic"
  elif [ "$INIT" = systemd ] && systemctl is-enabled ssh-hardening-security-patch.timer >/dev/null 2>&1; then au="zypper patch timer"
  elif have yum-cron && [ -f /etc/yum/yum-cron.conf ]; then au="yum-cron (installed)"; fi
  [ "$au" = none ] && audit_line WARN "Automatic security updates: not configured" || audit_line PASS "Automatic security updates: $au"
  if have getenforce; then audit_line INFO "SELinux: $(getenforce 2>/dev/null || echo unknown)"; fi
  [ -f "$SYSCTL_FILE" ] && audit_line PASS "sysctl hardening file present ($SYSCTL_FILE)" || audit_line INFO "sysctl hardening: not applied by this tool"
  check_reboot_required
  if [ ${#REBOOT_REASONS[@]} -gt 0 ]; then for v in "${REBOOT_REASONS[@]}"; do audit_line WARN "Reboot required: $v"; done
  else audit_line PASS "No pending reboot detected"; fi
}

# ----------------------------------------------------------------------------
# Plan display & final report
# ----------------------------------------------------------------------------
show_plan() {
  section "Plan"
  say "  SSH port:        ${CUR_PORTS% } -> $PORT"
  say "  Level:           $LEVEL"
  say "  Login user:      $TARGET_USER ($TARGET_EXISTING_KEYS existing key(s), ${#TARGET_NEW_KEYS[@]} new)"
  [ -n "$NEW_USER" ] && say "  New user:        $NEW_USER (sudo: $NEW_USER_SUDO, keys: $NEW_USER_KEYSRC)"
  say "  Root login:      ${ROOT_LOGIN:-unchanged ($(eff permitrootlogin)); passwords disabled}"
  [ -n "$ALLOW_USERS" ] && say "  AllowUsers:      $ALLOW_USERS"
  say "  Firewall:        $( [ "$DO_FIREWALL" = 1 ] && echo "open TCP $PORT in $FW" || echo "no change")"
  say "  fail2ban:        $( [ "$DO_FAIL2BAN" = 1 ] && echo yes || echo no)"
  say "  Auto-updates:    $( [ "$DO_AUTOUPD" = 1 ] && echo yes || echo no)"
  say "  sysctl:          $( [ "$DO_SYSCTL" = 1 ] && echo yes || echo no)"
  say "  Rollback timer:  $( [ "$CONFIRM_TIMEOUT" -gt 0 ] && [ "$ASSUME_YES" = 0 ] && echo "${CONFIRM_TIMEOUT}s" || echo off)"
  say ""
  say "  sshd settings ($( [ "$USE_DROPIN" = 1 ] && echo "$SSHD_DROPIN_DIR/$DROPIN_NAME" || echo "top of $SSHD_CFG")):"
  gen_config final | grep -v '^#' | sed 's/^/    /' >&2
}

final_report() {
  load_eff || true
  section "Done"
  ok "SSH hardening complete (level: $LEVEL)."
  say "  Port:            $(trim "$(eff_all port | tr '\n' ' ')")"
  say "  Password auth:   $(eff passwordauthentication)"
  say "  Root login:      $(eff permitrootlogin)"
  local s
  for s in ${SUMMARY[@]+"${SUMMARY[@]}"}; do say "  - $s"; done
  say ""
  say "  Connect:         ssh -p $PORT $(login_user)@$SERVER_IP"
  say "  Backup/restore:  sudo sh $BACKUP_DIR/restore.sh   (or: main.sh --restore)"
  say "  Audit later:     sudo bash main.sh --audit"
  say "  Log:             $LOG_FILE"
  if [ "$CONFIRMED_LOGIN" != 1 ]; then
    say ""
    warn "Do NOT close this session until a new login on port $PORT has worked."
  fi
  say ""
  say "  Client tip: if you have many keys in ssh-agent, use 'IdentitiesOnly yes' + IdentityFile"
  say "  in ~/.ssh/config, otherwise MaxAuthTries may be exhausted before the right key is tried."
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
  parse_args "$@"
  [ "$(uname -s)" = Linux ] || die "This script supports Linux only."
  [ "${EUID:-$(id -u)}" -eq 0 ] || die "Please run as root (e.g. sudo bash main.sh)."

  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  touch "$LOG_FILE" && chmod 600 "$LOG_FILE" && LOG_READY=1
  _log "---- ssh-hardening v$SCRIPT_VERSION start (mode=$MODE dry_run=$DRY_RUN) ----"
  setup_input
  acquire_lock

  detect_os
  detect_virt
  detect_sshd
  resolve_sshd_paths
  detect_ssh_service
  detect_firewall
  detect_ips
  print_env

  case "$MODE" in
    audit) run_audit; exit 0 ;;
    restore) run_restore; exit 0 ;;
  esac

  if [ -z "$TTY_FD" ] && [ "$ASSUME_YES" = 0 ]; then
    die "No terminal available for questions. Run interactively, or use --yes with --key/--key-file (see --help)."
  fi

  if ! sshd_test; then
    if printf '%s' "$SSHD_TEST_OUT" | grep -qi 'no hostkeys available'; then
      ssh-keygen -A >/dev/null 2>&1 && ok "Generated missing host keys."
      sshd_test || die "Current sshd configuration is invalid: $SSHD_TEST_OUT"
    else
      die "Current sshd configuration is invalid; fix it first: $SSHD_TEST_OUT"
    fi
  fi
  load_eff || die "Could not read the effective sshd configuration (sshd -T)."
  CUR_PORTS="$(eff_all port | sort -un | tr '\n' ' ')"
  CUR_PORTS="$(trim "$CUR_PORTS")"
  [ -n "$CUR_PORTS" ] || CUR_PORTS=22

  section "SSH port"
  select_port
  select_target_user
  load_eff || true   # re-evaluate with the target user (Match blocks)
  collect_target_keys
  check_authorized_keys_file
  check_account_usable "$TARGET_USER"
  select_level

  local need_admin=0
  if [ "$LEVEL" != basic ] && { [ "$TARGET_USER" = root ] || ! user_has_sudo "$TARGET_USER"; }; then need_admin=1; fi
  if [ -n "$OPT_NEW_USER" ] || [ "$ASSUME_YES" = 0 ]; then plan_new_user "$need_admin"; fi
  decide_root_login
  decide_allow_users
  select_modules
  show_plan

  if [ "$DRY_RUN" = 1 ]; then
    section "Dry run"
    ok "No changes were made."
    exit 0
  fi
  say ""
  ask_yn "Apply these changes now?" y || die "Aborted by user. Nothing was changed."

  # --- 1. Accounts & keys (no SSH changes yet) ---
  section "Accounts & keys"
  TARGET_KEY_FILE="$(ensure_ssh_dir "$TARGET_USER")"
  append_keys "$TARGET_KEY_FILE" "$TARGET_USER" ${TARGET_NEW_KEYS[@]+"${TARGET_NEW_KEYS[@]}"}
  local u
  for u in ${ACCOUNT_UNLOCK_USERS[@]+"${ACCOUNT_UNLOCK_USERS[@]}"}; do unlock_account "$u"; done
  create_new_user

  # --- 2. Backup and pre-requisites ---
  section "Preparing"
  create_backup
  ROLLBACK_ARMED=1
  selinux_allow_port
  firewall_open_port || { ask_yn "Firewall could not be updated. Continue anyway?" n || die "Aborted."; }
  reserve_port
  prepare_host_keys

  # --- 3. Stage 1: listen on old + new port ---
  section "Stage 1/2: enabling port $PORT alongside ${CUR_PORTS}"
  local warm_ports
  # shellcheck disable=SC2086  # CUR_PORTS is a space separated list
  warm_ports="$(printf '%s\n' "$PORT" $CUR_PORTS | awk '!seen[$0]++' | tr '\n' ' ')"
  apply_stage warmup "$warm_ports" || die "Stage 1 failed; previous configuration will be restored."

  # --- 4. Stage 2: final hardening ---
  section "Stage 2/2: applying '$LEVEL' hardening"
  apply_stage final "$PORT" || die "Stage 2 failed; previous configuration will be restored."
  warn_match_overrides
  if [ "$SELF_TEST" = 1 ]; then
    ssh_self_test || die "Self-test failed; previous configuration will be restored."
  fi
  summary "sshd: port $PORT, level $LEVEL"

  # --- 5. Dead-man confirmation ---
  confirm_new_login
  ROLLBACK_ARMED=0

  # --- 6. Optional modules (failures are reported, never fatal) ---
  if [ "$DO_AUTOUPD" = 1 ]; then setup_auto_updates || warn "Automatic updates were not configured."; fi
  if [ "$DO_FAIL2BAN" = 1 ]; then setup_fail2ban || warn "fail2ban was not configured."; fi
  if [ "$DO_SYSCTL" = 1 ]; then setup_sysctl || warn "sysctl hardening was not applied."; fi

  final_report
  reboot_prompt
  _log "---- finished ----"
}

main "$@"
