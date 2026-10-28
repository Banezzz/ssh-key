#!/usr/bin/env bash
# shellcheck disable=SC2034
#
# ssh-hardening — SSH & baseline security toolkit for VPS / dedicated servers.
#
#   * Interactive menu: hardening wizard, security score, key / user / fail2ban
#     management, login history, login alerts, backups
#   * Public-key-only SSH, custom port, three hardening levels
#   * Debian/Ubuntu, RHEL family, Alpine, Arch, openSUSE/SLES, Gentoo;
#     systemd (incl. ssh.socket) / OpenRC / SysV / runit
#   * Lockout protection: staged apply, sshd -T verification, listening-port
#     checks, SELinux labelling, firewall opening, dead-man rollback timer
#   * Chinese / English UI (--lang zh|en)
#
# Run as root:  sudo bash main.sh [--help]

if [ -z "${BASH_VERSION:-}" ]; then
  echo "ERROR: this script requires bash (e.g. 'sudo bash main.sh'; on Alpine: 'apk add bash')." >&2
  echo "错误：需要 bash 运行（例如 'sudo bash main.sh'；Alpine 请先 'apk add bash'）。" >&2
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

SCRIPT_VERSION="3.0.0"
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
NOTIFY_DIR="/etc/ssh-hardening"
NOTIFY_CONF="$NOTIFY_DIR/notify.conf"
NOTIFY_BIN="/usr/local/sbin/ssh-hardening-notify"
PAM_SSHD="/etc/pam.d/sshd"
PAM_NOTIFY_LINE="session optional pam_exec.so quiet $NOTIFY_BIN"

# Key types sshd may accept (DSA is recognised only so that it can be rejected)
SSH_KEY_TYPES_RE='^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh[.]com|sk-ecdsa-sha2-nistp256@openssh[.]com)$'

# ----------------------------------------------------------------------------
# Options
# ----------------------------------------------------------------------------
MODE=""                 # menu | wizard | audit | restore | keys | users | logins | f2b | notify | backups
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
OPT_LANG=""
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
SERVER_IP="" CLIENT_IP="" CLIENT_PORT=""
APT_UPDATED=0

# ----------------------------------------------------------------------------
# UI: language, colours, glyphs, layout helpers
# All UI goes to stderr; stdout is reserved for data returned by functions.
# ----------------------------------------------------------------------------
UI_LANG="zh"
COLOR=0 FANCY=0
C_R="" C_G="" C_Y="" C_B="" C_M="" C_C="" C_DIM="" C_BOLD="" C_0=""
G_OK="[+]" G_ERR="[x]" G_WARN="[!]" G_INFO="[*]" G_ARROW="->" G_STEP=">" G_BULLET="-"
B_TL="+" B_V="|" B_BL="+" B_H="-" B_TR="+" B_BR="+" BAR_ON="#" BAR_OFF="."

ui_init() {
  if [ -t 2 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then COLOR=1; fi
  if [ "$COLOR" = 1 ] && [ "${TERM:-}" != linux ] && [ "${SSH_HARDEN_ASCII:-0}" != 1 ]; then FANCY=1; fi
  if [ "$COLOR" = 1 ]; then
    C_R=$'\033[31m' C_G=$'\033[32m' C_Y=$'\033[33m' C_B=$'\033[34m' C_M=$'\033[35m' C_C=$'\033[36m'
    C_DIM=$'\033[2m' C_BOLD=$'\033[1m' C_0=$'\033[0m'
  fi
  if [ "$FANCY" = 1 ]; then
    G_OK="✓" G_ERR="✗" G_WARN="!" G_INFO="•" G_ARROW="→" G_STEP="❯" G_BULLET="·"
    B_TL="┌" B_V="│" B_BL="└" B_H="─" B_TR="╮" B_BR="╯" BAR_ON="█" BAR_OFF="░"
  fi
}

# Language: --lang > $SSH_HARDEN_LANG > saved choice > zh (en on the Linux VT console, which has no CJK font)
ui_lang_init() {
  local saved=""
  [ -r "$STATE_DIR/lang" ] && saved="$(cat "$STATE_DIR/lang" 2>/dev/null || true)"
  UI_LANG="${OPT_LANG:-${SSH_HARDEN_LANG:-$saved}}"
  if [ -z "$UI_LANG" ]; then
    if [ "${TERM:-}" = linux ]; then UI_LANG=en; else UI_LANG=zh; fi
  fi
  case "$UI_LANG" in zh*|cn) UI_LANG=zh ;; *) UI_LANG=en ;; esac
}

# L "english" "中文"  -> text in the UI language
L() { if [ "$UI_LANG" = zh ] && [ $# -ge 2 ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

_log() {
  if [ "$LOG_READY" = 1 ]; then
    printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG_FILE" 2>/dev/null || true
  fi
}
# Message helpers take ("english" ["中文"])
say()  { local m; m="$(L "$@")"; printf '%s\n' "$m" >&2; _log "$m"; }
info() { local m; m="$(L "$@")"; printf '  %s%s%s %s\n' "$C_B" "$G_INFO" "$C_0" "$m" >&2; _log "INFO  $m"; }
ok()   { local m; m="$(L "$@")"; printf '  %s%s%s %s\n' "$C_G" "$G_OK" "$C_0" "$m" >&2; _log "OK    $m"; }
warn() { local m; m="$(L "$@")"; printf '  %s%s%s %s\n' "$C_Y$C_BOLD" "$G_WARN" "$C_0" "$m" >&2; _log "WARN  $m"; }
err()  { local m; m="$(L "$@")"; printf '  %s%s%s %s\n' "$C_R$C_BOLD" "$G_ERR" "$C_0" "$m" >&2; _log "ERROR $m"; }
die()  { err "$@"; exit 1; }
hint() { local m; m="$(L "$@")"; printf '    %s%s%s\n' "$C_DIM" "$m" "$C_0" >&2; _log "      $m"; }

# Display width of a string (ASCII = 1 column, 3-byte UTF-8 CJK = 2 columns)
dwidth() {
  local s="$1" a
  a="$(printf '%s' "$s" | tr -d '\200-\377')"
  echo $(( ${#a} + (${#s} - ${#a}) * 2 / 3 ))
}
pad() { # pad "text" WIDTH -> text padded with spaces to WIDTH display columns
  local w n
  w="$(dwidth "$1")"
  n=$(( $2 - w ))
  [ "$n" -gt 0 ] || n=0
  printf '%s%*s' "$1" "$n" ''
}
rep() { # rep CHAR COUNT
  local i out=""
  for (( i = 0; i < $2; i++ )); do out="$out$1"; done
  printf '%s' "$out"
}

section() {
  local t
  t="$(L "$@")"
  printf '\n  %s%s %s%s\n' "$C_BOLD$C_C" "$G_STEP" "$t" "$C_0" >&2
  printf '  %s%s%s\n' "$C_DIM" "$(rep "$B_H" $(( $(dwidth "$t") + 2 )))" "$C_0" >&2
  _log "== $t"
}

WSTEP_TOTAL=6
wstep() { # wstep N "english" "中文"
  local n="$1" t
  shift
  t="$(L "$@")"
  printf '\n  %s[%s/%s]%s %s%s%s\n' "$C_C$C_BOLD" "$n" "$WSTEP_TOTAL" "$C_0" "$C_BOLD" "$t" "$C_0" >&2
  printf '  %s%s%s\n' "$C_DIM" "$(rep "$B_H" $(( $(dwidth "$t") + 6 )))" "$C_0" >&2
  _log "== [$n/$WSTEP_TOTAL] $t"
}

kv() { # kv "label" "value"
  printf '    %s%s%s %s\n' "$C_DIM" "$(pad "$1" 16)" "$C_0" "$2" >&2
  _log "  $1 $2"
}

# Left-bar card: card_open "title"; card_line "text"; card_close ["footer"]
card_open()  { printf '\n  %s%s%s %s%s%s\n' "$C_C" "$B_TL$B_H" "$C_0" "$C_BOLD" "$1" "$C_0" >&2; _log "-- $1"; }
card_line()  { printf '  %s%s%s %s\n' "$C_C" "$B_V" "$C_0" "$1" >&2; _log "   $1"; }
card_kv()    { card_line "$C_DIM$(pad "$1" 16)$C_0 $2"; }
card_close() { printf '  %s%s%s %s%s%s\n' "$C_C" "$B_BL$B_H" "$C_0" "$C_DIM" "${1:-}" "$C_0" >&2; }

badge() { # badge PASS|WARN|FAIL|INFO -> coloured symbol
  case "$1" in
    PASS) printf '%s%s%s' "$C_G" "$G_OK" "$C_0" ;;
    WARN) printf '%s%s%s' "$C_Y$C_BOLD" "$G_WARN" "$C_0" ;;
    FAIL) printf '%s%s%s' "$C_R$C_BOLD" "$G_ERR" "$C_0" ;;
    *)    printf '%s%s%s' "$C_B" "$G_INFO" "$C_0" ;;
  esac
}

bar() { # bar PERCENT WIDTH -> coloured progress bar
  local pct="$1" w="$2" on c
  on=$(( pct * w / 100 ))
  if [ "$pct" -ge 80 ]; then c="$C_G"; elif [ "$pct" -ge 60 ]; then c="$C_Y"; else c="$C_R"; fi
  printf '%s%s%s%s%s' "$c" "$(rep "$BAR_ON" "$on")" "$C_DIM" "$(rep "$BAR_OFF" $(( w - on )))" "$C_0"
}

onoff() { # onoff 0|1 -> coloured on/off word
  if [ "$1" = 1 ]; then printf '%s%s%s' "$C_G" "$(L on 开启)" "$C_0"; else printf '%s%s%s' "$C_DIM" "$(L off 关闭)" "$C_0"; fi
}

clear_screen() { if [ "$FANCY" = 1 ] && [ -t 2 ]; then printf '\033[H\033[2J\033[3J' >&2; fi; }

pause() {
  [ -n "$TTY_FD" ] && [ "$ASSUME_YES" = 0 ] || return 0
  local _x
  printf '\n  %s%s%s' "$C_DIM" "$(L "Press Enter to return to the menu..." "按回车键返回菜单...")" "$C_0" >&2
  read_tty _x "" || true
}

# spin "english" "中文" -- cmd args...   (runs cmd with a spinner; output goes to the log)
spin() {
  local en="$1" zh="$2" msg rc=0 pid i=0 frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  shift 2
  [ "${1:-}" = "--" ] && shift
  msg="$(L "$en" "$zh")"
  _log "RUN   $* ($msg)"
  if [ "$FANCY" != 1 ] || [ ! -t 2 ]; then
    "$@" >>"$LOG_FILE" 2>&1 || rc=$?
  else
    "$@" >>"$LOG_FILE" 2>&1 &
    pid=$!
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r  %s%s%s %s' "$C_C" "${frames:$(( i % 10 * 3 )):3}" "$C_0" "$msg" >&2
      i=$((i + 1))
      sleep 0.1
    done
    wait "$pid" || rc=$?
    printf '\r\033[K' >&2
  fi
  if [ "$rc" -eq 0 ]; then ok "$msg"; else err "$msg ($(L "failed, see" "失败，详见") $LOG_FILE)"; fi
  return "$rc"
}

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

in_list() { # in_list item "a b c"
  local x
  for x in $2; do [ "$x" = "$1" ] && return 0; done
  return 1
}

valid_ip() {
  [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || [[ "$1" =~ ^[0-9a-fA-F:]+:[0-9a-fA-F:]*(/[0-9]{1,3})?$ ]]
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

prompt_fmt() { # prompt_fmt "question" "default" -> styled prompt string
  if [ -n "$2" ]; then printf '  %s?%s %s %s[%s]%s: ' "$C_C$C_BOLD" "$C_0" "$1" "$C_DIM" "$2" "$C_0"
  else printf '  %s?%s %s: ' "$C_C$C_BOLD" "$C_0" "$1"; fi
}

# ask VAR "Question" "default"
ask() {
  local __v="$1" __q="$2" __d="${3:-}" __a=""
  if [ "$ASSUME_YES" = 1 ] || [ -z "$TTY_FD" ]; then
    printf -v "$__v" '%s' "$__d"
    return 0
  fi
  read_tty __a "$(prompt_fmt "$__q" "$__d")" || true
  __a="$(trim "$__a")"
  _log "ASK   $__q -> ${__a:-$__d}"
  printf -v "$__v" '%s' "${__a:-$__d}"
}

# ask_yn "Question" y|n   -> 0 = yes
ask_yn() {
  local q="$1" d="$2" a hint
  if [ "$d" = y ]; then hint="Y/n"; else hint="y/N"; fi
  if [ "$ASSUME_YES" = 1 ] || [ -z "$TTY_FD" ]; then
    [ "$d" = y ]
    return
  fi
  while true; do
    read_tty a "$(prompt_fmt "$q" "$hint")" || a=""
    a="$(lower "$(trim "$a")")"
    _log "ASK   $q -> ${a:-$d}"
    case "${a:-$d}" in
      y|yes|是) return 0 ;;
      n|no|否)  return 1 ;;
      *) say "  $(L "Please answer y or n." "请输入 y 或 n。")" ;;
    esac
  done
}

# menu_item KEY "english" "中文" ["description"]
menu_item() {
  local key="$1" label desc=""
  label="$(L "$2" "$3")"
  [ $# -ge 4 ] && desc="$4"
  printf '   %s%2s%s  %s %s%s%s\n' "$C_C$C_BOLD" "$key" "$C_0" "$(pad "$label" 20)" "$C_DIM" "$desc" "$C_0" >&2
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
    warn "Run did not complete (exit $rc). Restoring SSH configuration from $BACKUP_DIR ..." \
         "运行未完成（退出码 $rc），正在从 $BACKUP_DIR 恢复 SSH 配置……"
    if sh "$BACKUP_DIR/restore.sh" >>"$LOG_FILE" 2>&1; then
      ok "SSH configuration restored." "SSH 配置已恢复。"
    else
      err "Automatic restore reported an error. Check $LOG_FILE and run: sh $BACKUP_DIR/restore.sh" \
          "自动恢复出错，请查看 $LOG_FILE 并手动执行：sh $BACKUP_DIR/restore.sh"
    fi
  fi
  [ "$COLOR" = 1 ] && printf '%s' "$C_0" >&2
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
      die "Another instance is running (PID $pid). Remove $d if this is wrong." \
          "已有另一个实例在运行（PID $pid）。如判断有误，请删除 $d"
    fi
    rm -rf "$d"
    mkdir "$d" || die "Cannot create lock $d" "无法创建锁 $d"
  fi
  echo $$ >"$d/pid"
  LOCKDIR_OWNED="$d"
}

# ----------------------------------------------------------------------------
# Usage / argument parsing
# ----------------------------------------------------------------------------
usage() {
  if [ "$UI_LANG" = zh ]; then
    cat <<EOF
ssh-hardening v$SCRIPT_VERSION — VPS / 独立服务器 SSH 安全加固工具

用法：sudo bash main.sh [选项] [端口] [sshd_config]
      不带参数运行时进入交互式主菜单。

功能模式
      --wizard             直接进入一键加固向导
      --audit              安全体检与评分（只读）
      --keys               SSH 公钥管理
      --users              用户管理
      --logins             登录记录与失败来源统计
      --fail2ban-status    fail2ban 管理（查看 / 解封 / 封禁）
      --notify             登录提醒（Telegram / 企业微信 / 钉钉 / 飞书 / Webhook）
      --backups            备份管理
      --restore [DIR]      从最近一次（或指定）备份恢复 SSH 配置
      --dry-run            走完向导并显示计划，不做任何修改

加固选项（指定任一项即进入向导）
  -p, --port N             SSH 端口（默认 $DEFAULT_PORT；22 或 1024-65535）
  -l, --level L            basic | standard | strict
  -u, --user NAME          登录用户（管理其 authorized_keys）
  -k, --key "PUBKEY"       添加公钥（可重复）；"gh:NAME" 导入 github.com/NAME.keys
      --key-file FILE      从文件添加公钥（可重复）
      --new-user NAME      同时创建 sudo 用户（复制相同公钥）
      --root-login MODE    no | prohibit-password（standard 等级）
      --allow-users / --no-allow-users   是否启用 AllowUsers 白名单
  -c, --config PATH        sshd_config 路径（默认 /etc/ssh/sshd_config）

安全
      --confirm-timeout S  新登录确认时限，超时自动回滚（默认 ${DEFAULT_CONFIRM_TIMEOUT}，0 关闭）
      --self-test          额外执行 ssh -p PORT user@localhost 自测（需本机有私钥）

附加模块（不指定则询问；standard/strict 默认开启）
      --firewall / --no-firewall
      --fail2ban / --no-fail2ban
      --auto-updates / --no-auto-updates
      --sysctl / --no-sysctl
      --reboot / --no-reboot

通用
      --lang zh|en         界面语言（默认中文；Linux 控制台自动使用英文）
  -y, --yes                非交互：全部使用默认值（需要提供公钥来源）
  -h, --help               显示帮助
  -V, --version            显示版本
EOF
  else
    cat <<EOF
ssh-hardening v$SCRIPT_VERSION — SSH & baseline security toolkit for VPS / dedicated servers

Usage: sudo bash main.sh [options] [port] [sshd_config]
       Without arguments an interactive menu is shown.

Tools
      --wizard             Go straight to the hardening wizard
      --audit              Security check with score (read-only)
      --keys               Manage SSH public keys
      --users              Manage users
      --logins             Login history and failed-login sources
      --fail2ban-status    fail2ban status / unban / ban
      --notify             Login alerts (Telegram / WeCom / DingTalk / Feishu / webhook)
      --backups            Manage backups
      --restore [DIR]      Restore SSH config from the latest (or given) backup
      --dry-run            Run the wizard and show the plan, change nothing

Hardening options (any of these starts the wizard)
  -p, --port N             SSH port (default $DEFAULT_PORT; 22 or 1024-65535)
  -l, --level L            basic | standard | strict
  -u, --user NAME          Login user whose authorized_keys is managed
  -k, --key "PUBKEY"       Add a public key (repeatable). "gh:NAME" imports github.com/NAME.keys
      --key-file FILE      Add keys from a file (repeatable)
      --new-user NAME      Also create a new sudo user (gets the same keys)
      --root-login MODE    no | prohibit-password (standard level)
      --allow-users / --no-allow-users
  -c, --config PATH        sshd_config path (default /etc/ssh/sshd_config)

Safety
      --confirm-timeout S  Seconds to confirm a new login before auto-rollback (default $DEFAULT_CONFIRM_TIMEOUT, 0 = off)
      --self-test          Also test 'ssh -p PORT user@localhost' (needs a private key on this host)

Extra modules (default: asked; on for standard/strict)
      --firewall / --no-firewall
      --fail2ban / --no-fail2ban
      --auto-updates / --no-auto-updates
      --sysctl / --no-sysctl
      --reboot / --no-reboot

General
      --lang zh|en         UI language (default Chinese; English on the Linux console)
  -y, --yes                Non-interactive: accept defaults (needs a key source)
  -h, --help               Show this help
  -V, --version            Show version
EOF
  fi
}

parse_args() {
  local positional=() a v wizard_opt=0
  while [ $# -gt 0 ]; do
    a="$1"
    v=""
    case "$a" in
      --*=*) v="${a#*=}"; a="${a%%=*}" ;;
    esac
    case "$a" in
      -p|--port|-l|--level|-u|--user|-k|--key|--key-file|--new-user|--root-login|-c|--config|--confirm-timeout|--lang)
        if [ -z "$v" ]; then
          [ $# -ge 2 ] || die "Option $a requires a value." "选项 $a 需要一个值。"
          v="$2"; shift
        fi ;;
    esac
    case "$a" in
      -h|--help) MODE=help ;;
      -V|--version) echo "$SCRIPT_VERSION"; exit 0 ;;
      --menu) MODE=menu ;;
      --wizard|--harden) MODE=wizard ;;
      --audit) MODE=audit ;;
      --keys) MODE=keys ;;
      --users) MODE=users ;;
      --logins) MODE=logins ;;
      --fail2ban-status|--f2b) MODE=f2b ;;
      --notify) MODE=notify ;;
      --backups) MODE=backups ;;
      --restore)
        MODE=restore
        if [ -n "$v" ]; then OPT_RESTORE_DIR="$v"
        elif [ $# -ge 2 ] && [ "${2#-}" = "$2" ]; then OPT_RESTORE_DIR="$2"; shift; fi ;;
      --dry-run) DRY_RUN=1; wizard_opt=1 ;;
      --lang) OPT_LANG="$(lower "$v")" ;;
      -p|--port) OPT_PORT="$v"; wizard_opt=1 ;;
      -l|--level) OPT_LEVEL="$(lower "$v")"; wizard_opt=1 ;;
      -u|--user) OPT_USER="$v"; wizard_opt=1 ;;
      -k|--key) OPT_KEYS+=("$v"); wizard_opt=1 ;;
      --key-file) OPT_KEY_FILES+=("$v"); wizard_opt=1 ;;
      --new-user) OPT_NEW_USER="$v"; wizard_opt=1 ;;
      --root-login) OPT_ROOT_LOGIN="$(lower "$v")"; wizard_opt=1 ;;
      --allow-users) OPT_ALLOW_USERS=1; wizard_opt=1 ;;
      --no-allow-users) OPT_ALLOW_USERS=0; wizard_opt=1 ;;
      -c|--config) OPT_CFG="$v" ;;
      --confirm-timeout) CONFIRM_TIMEOUT="$v" ;;
      --self-test|--enable-self-test) SELF_TEST=1 ;;
      --skip-self-test) SELF_TEST=0 ;;
      --firewall) OPT_FIREWALL=1 ;;      --no-firewall) OPT_FIREWALL=0 ;;
      --fail2ban) OPT_FAIL2BAN=1 ;;      --no-fail2ban) OPT_FAIL2BAN=0 ;;
      --auto-updates) OPT_AUTOUPD=1 ;;   --no-auto-updates) OPT_AUTOUPD=0 ;;
      --sysctl) OPT_SYSCTL=1 ;;          --no-sysctl) OPT_SYSCTL=0 ;;
      --reboot) OPT_REBOOT=1 ;;          --no-reboot) OPT_REBOOT=0 ;;
      -y|--yes) ASSUME_YES=1; wizard_opt=1 ;;
      --) shift; positional+=("$@"); break ;;
      -*) die "Unknown option: $a (see --help)" "未知选项：$a（参见 --help）" ;;
      *) positional+=("$a") ;;
    esac
    shift
  done
  # Backwards compatible positional arguments: [port] [sshd_config]
  if [ ${#positional[@]} -ge 1 ] && [ -z "$OPT_PORT" ]; then OPT_PORT="${positional[0]}"; wizard_opt=1; fi
  if [ ${#positional[@]} -ge 2 ] && [ -z "$OPT_CFG" ]; then OPT_CFG="${positional[1]}"; fi
  [ ${#positional[@]} -le 2 ] || die "Too many arguments (see --help)." "参数过多（参见 --help）。"
  if [ -z "$MODE" ]; then
    if [ "$wizard_opt" = 1 ]; then MODE=wizard; else MODE=menu; fi
  fi

  case "$OPT_LEVEL" in ""|basic|standard|strict) ;; 1) OPT_LEVEL=basic ;; 2) OPT_LEVEL=standard ;; 3) OPT_LEVEL=strict ;;
    *) die "Invalid --level: $OPT_LEVEL" "无效的 --level：$OPT_LEVEL" ;; esac
  case "$OPT_ROOT_LOGIN" in ""|no|prohibit-password) ;; without-password) OPT_ROOT_LOGIN=prohibit-password ;;
    *) die "Invalid --root-login: $OPT_ROOT_LOGIN (no | prohibit-password)" "无效的 --root-login：$OPT_ROOT_LOGIN（no | prohibit-password）" ;; esac
  [[ "$CONFIRM_TIMEOUT" =~ ^[0-9]+$ ]] || die "--confirm-timeout must be a number of seconds." "--confirm-timeout 必须是秒数。"
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
  [ -n "$SSHD_BIN" ] || die "sshd not found. Install the OpenSSH server first (openssh-server / openssh)." \
                            "未找到 sshd，请先安装 OpenSSH 服务端（openssh-server / openssh）。"
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
      die "sshd config not found: $SSHD_CFG" "找不到 sshd 配置文件：$SSHD_CFG"
    fi
  fi

  USE_DROPIN=0
  if dropin_is_included; then USE_DROPIN=1; fi
  if [ "$MAIN_CFG_MISSING" = 1 ] && [ "$USE_DROPIN" = 0 ]; then
    die "$VENDOR_CFG does not include $SSHD_DROPIN_DIR/*.conf; cannot place configuration safely." \
        "$VENDOR_CFG 没有 Include $SSHD_DROPIN_DIR/*.conf，无法安全写入配置。"
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

# Read VAR from the environment of an ancestor process (sudo strips SSH_CONNECTION)
ancestor_env() {
  local var="$1" pid=$$ stat rest i v
  for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
    stat="$(cat "/proc/$pid/stat" 2>/dev/null)" || return 1
    rest="${stat##*) }"
    # shellcheck disable=SC2086
    set -- $rest
    pid="${2:-0}"
    [ "$pid" -gt 1 ] 2>/dev/null || return 1
    v="$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null | sed -n "s/^$var=//p" | head -n1)"
    if [ -n "$v" ]; then printf '%s' "$v"; return 0; fi
  done
  return 1
}

detect_ips() {
  local conn="${SSH_CONNECTION:-}" who_out=""
  [ -n "$conn" ] || conn="$(ancestor_env SSH_CONNECTION || true)"
  if [ -n "$conn" ]; then
    CLIENT_IP="$(printf '%s' "$conn" | awk '{print $1}')"
    CLIENT_PORT="$(printf '%s' "$conn" | awk '{print $2}')"
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

refresh_cur_ports() {
  CUR_PORTS="$(trim "$(eff_all port | sort -un | tr '\n' ' ')")"
  [ -n "$CUR_PORTS" ] || CUR_PORTS=22
}

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

# ----------------------------------------------------------------------------
# Service restart (systemd incl. socket activation, OpenRC, SysV, runit)
# ----------------------------------------------------------------------------
restart_ssh() {
  case "$INIT" in
    systemd)
      if [ -n "$SSH_SOCKET" ]; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        if systemctl restart "$SSH_SOCKET" >/dev/null 2>&1; then
          info "Restarted $SSH_SOCKET (socket activation)." "已重启 $SSH_SOCKET（套接字激活）。"
          return 0
        fi
        return 1
      fi
      if systemctl restart "$SSH_SERVICE" >/dev/null 2>&1; then
        sleep 1
        if systemctl is-active --quiet "$SSH_SERVICE"; then
          info "Restarted $SSH_SERVICE.service." "已重启 $SSH_SERVICE.service。"
          return 0
        fi
      fi
      return 1 ;;
    openrc)
      rc-service "$SSH_SERVICE" restart >/dev/null 2>&1 && { info "Restarted $SSH_SERVICE (OpenRC)." "已重启 $SSH_SERVICE（OpenRC）。"; return 0; }
      return 1 ;;
    runit)
      sv restart "$SSH_SERVICE" >/dev/null 2>&1 && { info "Restarted $SSH_SERVICE (runit)." "已重启 $SSH_SERVICE（runit）。"; return 0; }
      return 1 ;;
    *)
      if have service && service "$SSH_SERVICE" restart >/dev/null 2>&1; then info "Restarted $SSH_SERVICE (service)." "已重启 $SSH_SERVICE（service）。"; return 0; fi
      if [ -x "/etc/init.d/$SSH_SERVICE" ] && "/etc/init.d/$SSH_SERVICE" restart >/dev/null 2>&1; then info "Restarted $SSH_SERVICE (init.d)." "已重启 $SSH_SERVICE（init.d）。"; return 0; fi
      return 1 ;;
  esac
}

# A socket unit that ignores sshd_config ports is switched to the plain service.
convert_socket_to_service() {
  [ "$INIT" = systemd ] && [ -n "$SSH_SOCKET" ] || return 1
  local was
  was="$(systemctl is-enabled "$SSH_SERVICE" 2>/dev/null || true)"
  warn "$SSH_SOCKET does not follow the Port setting; switching to $SSH_SERVICE.service (no socket activation)." \
       "$SSH_SOCKET 不跟随 Port 设置，改用 $SSH_SERVICE.service（关闭套接字激活）。"
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
      err "Failed to restart the SSH service." "SSH 服务重启失败。"
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
    err "SSH is not listening on port(s):$missing" "SSH 未在以下端口监听：$missing"
    return 1
  fi
  ok "SSH is listening on: $(trim "$ports")" "SSH 正在监听：$(trim "$ports")"
}

# ----------------------------------------------------------------------------
# Package management
# ----------------------------------------------------------------------------
pkg_install() {
  [ $# -gt 0 ] || return 0
  case "$PKG" in
    apt-get)
      if [ "$APT_UPDATED" = 0 ]; then
        spin "Updating package index" "更新软件包索引" -- apt-get update -qq || true
        APT_UPDATED=1
      fi
      spin "Installing $*" "安装 $*" -- env DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@" ;;
    dnf)    spin "Installing $*" "安装 $*" -- dnf install -y -q "$@" ;;
    yum)    spin "Installing $*" "安装 $*" -- yum install -y -q "$@" ;;
    apk)    spin "Installing $*" "安装 $*" -- apk add --no-cache -q "$@" ;;
    pacman) spin "Installing $*" "安装 $*" -- pacman -S --needed --noconfirm "$@" ;;
    zypper) spin "Installing $*" "安装 $*" -- zypper -n -q install "$@" ;;
    *) warn "Automatic package installation is not supported here (install manually: $*)." \
            "当前系统不支持自动安装软件包，请手动安装：$*"; return 1 ;;
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

# Login-capable accounts: root and UID >= 1000 with a real shell
login_users() {
  local u uid home shell
  while IFS=: read -r u _ uid _ _ home shell; do
    case "$shell" in */nologin|*/false|"") continue ;; esac
    { [ "$uid" -eq 0 ] || { [ "$uid" -ge 1000 ] && [ "$uid" -lt 65534 ]; }; } 2>/dev/null || continue
    printf '%s\n' "$u"
  done </etc/passwd
  return 0
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
      warn "Rejected ssh-dss (DSA) key: disabled since OpenSSH 7.0 and removed in 10.0 — it would lock you out." \
           "已拒绝 ssh-dss（DSA）公钥：OpenSSH 7.0 起默认禁用、10.0 已移除，会导致无法登录。"
      return 1 ;;
    ssh-rsa)
      if [ -n "$KI_BITS" ] && [ "$KI_BITS" -lt 2048 ]; then
        warn "Rejected RSA key with only $KI_BITS bits (minimum 2048)." "已拒绝仅 $KI_BITS 位的 RSA 公钥（最低 2048 位）。"
        return 1
      fi
      if [ -n "$KI_BITS" ] && [ "$KI_BITS" -lt 3072 ]; then
        warn "RSA $KI_BITS-bit key accepted; ssh-ed25519 (or RSA >= 3072) is recommended." \
             "已接受 RSA $KI_BITS 位公钥；建议改用 ssh-ed25519（或 ≥3072 位 RSA）。"
      fi ;;
  esac
  return 0
}

key_is_weak() { # after key_info: DSA or RSA < 3072
  [ "$KI_TYPE" = ssh-dss ] && return 0
  [ "$KI_TYPE" = ssh-rsa ] && [ -n "$KI_BITS" ] && [ "$KI_BITS" -lt 3072 ] && return 0
  return 1
}

short_type() {
  case "$KI_TYPE" in
    ssh-ed25519) echo ED25519 ;; ssh-rsa) echo RSA ;; ssh-dss) echo DSA ;;
    ecdsa-sha2-*) echo ECDSA ;; sk-ssh-ed25519*) echo ED25519-SK ;; sk-ecdsa*) echo ECDSA-SK ;; *) echo "$KI_TYPE" ;;
  esac
}

describe_key() { printf '%s %s%s %s' "$(short_type)" "${KI_BITS:+$KI_BITS-bit }" "${KI_FP:-}" "${KI_COMMENT:-}"; }

# Report keys in an authorized_keys file (read-only). Sets TARGET_EXISTING_KEYS.
inspect_authorized_keys() {
  local file="$1" line bad=0 rejected=0
  TARGET_EXISTING_KEYS=0
  [ -f "$file" ] || return 0
  while IFS= read -r line || [ -n "$line" ]; do
    line="$(trim "$line")"
    case "$line" in ""|\#*) continue ;; esac
    if ! key_info "$line"; then bad=$((bad + 1)); continue; fi
    if key_usable >/dev/null 2>&1; then
      TARGET_EXISTING_KEYS=$((TARGET_EXISTING_KEYS + 1))
      say "    $(badge PASS) $(describe_key)"
    else
      rejected=$((rejected + 1))
      say "    $(badge FAIL) $(describe_key)  $C_Y$(L "(not usable: weak/deprecated)" "（不可用：过弱/已废弃）")$C_0"
    fi
  done <"$file"
  if [ "$bad" -gt 0 ]; then
    warn "$bad line(s) in $file are not valid public keys (sshd ignores them; file left unchanged)." \
         "$file 中有 $bad 行不是有效公钥（sshd 会忽略，文件保持不变）。"
  fi
  if [ "$rejected" -gt 0 ]; then
    warn "$rejected key(s) are DSA or RSA < 2048 bits and are not counted as usable." \
         "$rejected 把公钥为 DSA 或 <2048 位 RSA，不计为可用公钥。"
  fi
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
  [[ "$u" =~ ^[A-Za-z0-9-]{1,39}$ ]] || { warn "Invalid GitHub username: $u" "无效的 GitHub 用户名：$u"; return 1; }
  if have curl; then curl -fsSL --max-time 20 "https://github.com/$u.keys"
  elif have wget; then wget -qO- --timeout=20 "https://github.com/$u.keys"
  else warn "Neither curl nor wget is available to fetch GitHub keys." "没有 curl 或 wget，无法获取 GitHub 公钥。"; return 1; fi
}

# Expand a key source ("gh:NAME" or a key line) into candidate lines on stdout
expand_key_source() {
  local src="$1" u
  case "$src" in
    gh:*|github:*)
      u="${src#*:}"
      info "Fetching public keys from https://github.com/$u.keys" "正在获取 https://github.com/$u.keys"
      fetch_github_keys "$u" || { warn "Could not fetch keys for GitHub user '$u'." "无法获取 GitHub 用户 '$u' 的公钥。"; return 0; } ;;
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
    warn "Not a valid SSH public key: ${line:0:50}..." "不是有效的 SSH 公钥：${line:0:50}..."
    return 1
  fi
  key_usable || return 1
  eval "cur=(\${${arr}[@]+\"\${${arr}[@]}\"})"
  if blob_in_list "$KI_BLOB" "$file" ${cur[@]+"${cur[@]}"}; then
    info "Key already present: $(describe_key)" "公钥已存在：$(describe_key)"
    return 0
  fi
  eval "${arr}+=(\"\$line\")"
  ok "Key accepted: $(describe_key)" "已接受公钥：$(describe_key)"
}

read_keys_interactive() { # read_keys_interactive ARRAYNAME EXISTING_FILE
  local arr="$1" file="$2" line l
  hint "Paste public keys one per line (contents of ~/.ssh/id_ed25519.pub), or gh:<github-user>. Empty line to finish." \
       "每行粘贴一把公钥（即 ~/.ssh/id_ed25519.pub 的内容），或输入 gh:<GitHub用户名> 导入；空行结束。"
  while true; do
    read_tty line "  $C_C$G_STEP$C_0 " || break
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
  [ -n "$home" ] && [ -d "$home" ] || die "Home directory of '$user' does not exist: ${home:-?}" "用户 '$user' 的家目录不存在：${home:-?}"
  ssh_dir="$home/.ssh"
  key_file="$ssh_dir/authorized_keys"
  if [ -L "$ssh_dir" ] || [ -L "$key_file" ]; then
    die "$ssh_dir or $key_file is a symlink; refusing to modify it (fix manually)." \
        "$ssh_dir 或 $key_file 是符号链接，拒绝修改（请手动处理）。"
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
    warn "Removed group/other write permission from $home (was $perms) — required by StrictModes." \
         "已移除 $home 的组/其他用户写权限（原为 $perms），StrictModes 要求如此。"
  fi
  owner="$(stat -c '%U' "$home" 2>/dev/null || echo "$user")"
  if [ "$owner" != "$user" ] && [ "$owner" != root ]; then
    warn "$home is owned by '$owner', not '$user'; StrictModes may reject key logins." \
         "$home 的属主是 '$owner' 而不是 '$user'，StrictModes 可能拒绝密钥登录。"
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
  ok "Wrote $# key(s) to $file" "已写入 $# 把公钥到 $file"
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
  warn "sshd reads keys from: AuthorizedKeysFile $akf" "sshd 从以下位置读取公钥：AuthorizedKeysFile $akf"
  warn "This script manages $TARGET_HOME/.ssh/authorized_keys, which sshd will NOT read." \
       "本脚本管理的是 $TARGET_HOME/.ssh/authorized_keys，sshd 不会读取它。"
  if [ -n "$(eff authorizedkeyscommand)" ] && [ "$(eff authorizedkeyscommand)" != none ]; then
    warn "An AuthorizedKeysCommand is configured: $(eff authorizedkeyscommand)" "已配置 AuthorizedKeysCommand：$(eff authorizedkeyscommand)"
  fi
  ask_yn "$(L "Continue anyway (only if your keys are provided another way)?" "仍然继续？（仅当你确认公钥由其他方式提供）")" n \
    || die "Aborted: AuthorizedKeysFile mismatch." "已中止：AuthorizedKeysFile 不匹配。"
}

ACCOUNT_UNLOCK_USERS=()
check_account_usable() {
  local user="$1" shell pw
  shell="$(user_field "$user" 7)"
  case "$shell" in
    */nologin|*/false|"")
      warn "User '$user' has shell '${shell:-none}' and cannot open an interactive session." \
           "用户 '$user' 的 shell 为 '${shell:-无}'，无法打开交互式会话。"
      ask_yn "$(L "Continue with this user anyway?" "仍然使用该用户？")" n || die "Aborted." "已中止。" ;;
  esac
  # Without PAM, sshd refuses locked accounts even for key logins (typical on Alpine)
  pw="$(shadow_pw "$user")"
  if [ "$(eff usepam)" != yes ] && [ "${pw:0:1}" = "!" ]; then
    warn "Account '$user' is locked ('!' in /etc/shadow) and sshd runs without PAM: key login would be refused." \
         "账户 '$user' 已锁定（/etc/shadow 中为 '!'），且 sshd 未启用 PAM：密钥登录也会被拒绝。"
    if ask_yn "$(L "Unlock the account for key login (password stays unusable)?" "解锁该账户以允许密钥登录（密码仍不可用）？")" y; then
      ACCOUNT_UNLOCK_USERS+=("$user")
    else
      die "Aborted: '$user' cannot log in while locked." "已中止：'$user' 锁定状态下无法登录。"
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
    warn "Current AllowUsers/DenyUsers settings do not permit '$user' to log in via SSH." \
         "当前 AllowUsers/DenyUsers 设置不允许 '$user' 通过 SSH 登录。"
    hint "AllowUsers: ${allow:-<none>}   DenyUsers: ${deny:-<none>}"
    ask_yn "$(L "Continue anyway (you can enable AllowUsers later in this wizard)?" "仍然继续？（稍后可在向导中启用 AllowUsers）")" n || die "Aborted." "已中止。"
  fi
  if [ -n "$(eff_all allowgroups | tr -d '[:space:]')" ]; then
    warn "AllowGroups is set ($(eff_all allowgroups | tr '\n' ' ')); make sure '$user' is in one of these groups." \
         "已设置 AllowGroups（$(eff_all allowgroups | tr '\n' ' ')），请确认 '$user' 属于其中某个组。"
  fi
}

unlock_account() {
  local user="$1" pw
  pw="$(shadow_pw "$user")"
  case "$pw" in
    "!"*'$'*)
      if passwd -u "$user" >/dev/null 2>&1 || usermod -U "$user" >/dev/null 2>&1; then ok "Unlocked account '$user'." "已解锁账户 '$user'。"; return 0; fi ;;
  esac
  if have usermod && usermod -p '*' "$user" >/dev/null 2>&1; then ok "Account '$user' set to key-only (no password)." "账户 '$user' 已设为仅密钥登录（无密码）。"; return 0; fi
  if have chpasswd && printf '%s:*\n' "$user" | chpasswd -e >/dev/null 2>&1; then ok "Account '$user' set to key-only (no password)." "账户 '$user' 已设为仅密钥登录（无密码）。"; return 0; fi
  warn "Could not unlock '$user'; run: usermod -p '*' $user" "无法解锁 '$user'，请执行：usermod -p '*' $user"
}

# ----------------------------------------------------------------------------
# New user creation
# ----------------------------------------------------------------------------
valid_new_username() { [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; }

ask_new_username() { # ask_new_username VAR
  local __n
  while true; do
    ask __n "$(L "New username" "新用户名")" ""
    if [ -z "$__n" ]; then printf -v "$1" '%s' ""; return 1; fi
    if ! valid_new_username "$__n"; then warn "Invalid name (lowercase letters, digits, _ and -, max 32 chars)." "用户名无效（小写字母、数字、_ 和 -，最长 32 位）。"; continue; fi
    if id "$__n" >/dev/null 2>&1; then warn "User '$__n' already exists." "用户 '$__n' 已存在。"; continue; fi
    printf -v "$1" '%s' "$__n"
    return 0
  done
}

ask_sudo_mode() { # ask_sudo_mode VAR USER
  local __c __def=1
  # A password cannot be set non-interactively, so --yes defaults to NOPASSWD sudo
  [ "$ASSUME_YES" = 1 ] && __def=2
  say ""
  say "  $(L "Sudo for '$2':" "'$2' 的 sudo 权限：")"
  say "   $C_C$C_BOLD 1$C_0  $(L "sudo with password (recommended: a stolen key alone does not give root)" "需要密码的 sudo（推荐：仅私钥泄露拿不到 root）")"
  say "   $C_C$C_BOLD 2$C_0  $(L "sudo without password (NOPASSWD)" "免密 sudo（NOPASSWD）")"
  say "   $C_C$C_BOLD 3$C_0  $(L "no sudo" "不授予 sudo")"
  ask __c "$(L "Choice" "请选择") [1-3]" "$__def"
  case "$__c" in 2) printf -v "$1" nopasswd ;; 3) printf -v "$1" none ;; *) printf -v "$1" password ;; esac
}

plan_new_user() {
  local need_admin="$1" name def_create=n choice
  if [ -n "$OPT_NEW_USER" ]; then
    name="$OPT_NEW_USER"
  else
    [ "$need_admin" = 1 ] && def_create=y
    if [ "$need_admin" = 1 ]; then
      hint "A non-root sudo user is recommended: root SSH login can then be disabled entirely." \
           "建议创建一个非 root 的 sudo 用户，这样可以完全禁止 root 通过 SSH 登录。"
    fi
    ask_yn "$(L "Create a new sudo user for SSH login?" "创建一个新的 sudo 用户用于 SSH 登录？")" "$def_create" || return 0
    ask_new_username name || return 0
  fi
  valid_new_username "$name" || die "Invalid username: $name" "无效的用户名：$name"
  id "$name" >/dev/null 2>&1 && die "User '$name' already exists." "用户 '$name' 已存在。"
  NEW_USER="$name"
  ask_sudo_mode NEW_USER_SUDO "$NEW_USER"

  local have_target_keys=$(( TARGET_EXISTING_KEYS + ${#TARGET_NEW_KEYS[@]} ))
  if [ "$have_target_keys" -gt 0 ]; then
    say ""
    say "  $(L "SSH keys for '$NEW_USER':" "'$NEW_USER' 的 SSH 公钥：")"
    say "   $C_C$C_BOLD 1$C_0  $(L "Same key(s) as '$TARGET_USER' (recommended)" "与 '$TARGET_USER' 使用相同公钥（推荐）")"
    say "   $C_C$C_BOLD 2$C_0  $(L "Paste different key(s)" "粘贴其他公钥")"
    ask choice "$(L "Choice" "请选择") [1-2]" "1"
  else
    choice=2
  fi
  if [ "$choice" = 2 ]; then
    NEW_USER_KEYSRC="new"
    read_keys_interactive NEW_USER_KEYS ""
    [ ${#NEW_USER_KEYS[@]} -gt 0 ] || die "No usable key provided for '$NEW_USER'." "没有为 '$NEW_USER' 提供可用公钥。"
  else
    NEW_USER_KEYSRC="copy"
  fi
}

ensure_sudo_installed() {
  have sudo && return 0
  pkg_install sudo || { warn "sudo could not be installed." "无法安装 sudo。"; return 1; }
  have sudo
}

sudoers_file() { echo "/etc/sudoers.d/90-ssh-hardening-$1"; }

grant_sudo() {
  local user="$1" mode="$2" f sudoers_bak=""
  f="$(sudoers_file "$user")"
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
    warn "sudoers validation failed; sudo was not granted to '$user'." "sudoers 校验失败，未授予 '$user' sudo 权限。"
    return 1
  fi
  ok "Granted sudo to '$user' ($mode)." "已授予 '$user' sudo 权限（$( [ "$mode" = nopasswd ] && echo 免密 || echo 需密码)）。"
}

# create_user_account NAME SUDO_MODE KEY...   (empty KEY list allowed)
create_user_account() {
  local name="$1" sudo_mode="$2" shell=/bin/sh pw tries kf
  shift 2
  [ -x /bin/bash ] && shell=/bin/bash
  if have useradd; then
    useradd -m -U -s "$shell" "$name" 2>/dev/null || useradd -m -s "$shell" "$name"
  elif have adduser; then
    adduser -D -s "$shell" "$name"
  else
    die "Neither useradd nor adduser is available." "系统中没有 useradd 或 adduser。"
  fi
  ok "Created user '$name' (shell $shell)." "已创建用户 '$name'（shell $shell）。"

  if [ "$sudo_mode" = password ] && [ -n "$TTY_FD" ] && [ "$ASSUME_YES" = 0 ]; then
    info "Set a password for '$name' (used for sudo and console login, never for SSH):" \
         "为 '$name' 设置密码（用于 sudo 和控制台登录，SSH 不会使用密码）："
    for tries in 1 2 3; do
      if passwd "$name" <&"$TTY_FD"; then break; fi
      warn "Password not set (attempt $tries/3)." "密码未设置成功（第 $tries/3 次）。"
    done
  fi
  pw="$(shadow_pw "$name")"
  case "$pw" in
    '!'|'!!'|'*'|'!*'|'')
      unlock_account "$name"
      if [ "$sudo_mode" = password ]; then
        warn "'$name' has no password, so password-sudo would be unusable." "'$name' 没有密码，需要密码的 sudo 将无法使用。"
        if [ "$ASSUME_YES" = 0 ] && ask_yn "$(L "Use NOPASSWD sudo instead?" "改用免密 sudo？")" n; then sudo_mode=nopasswd
        else hint "Set it later with: passwd $name" "稍后可执行：passwd $name"; fi
      fi ;;
  esac
  if [ "$sudo_mode" != none ]; then grant_sudo "$name" "$sudo_mode" || true; fi
  kf="$(ensure_ssh_dir "$name")"
  append_keys "$kf" "$name" "$@"
  CREATED_SUDO_MODE="$sudo_mode"
}
CREATED_SUDO_MODE=""

key_lines_of() { # key_lines_of FILE -> non-comment lines
  local l
  [ -f "$1" ] || return 0
  while IFS= read -r l || [ -n "$l" ]; do
    l="$(trim "$l")"
    case "$l" in ""|\#*) continue ;; esac
    printf '%s\n' "$l"
  done <"$1"
}

create_new_user() {
  [ -n "$NEW_USER" ] || return 0
  section "Creating user '$NEW_USER'" "创建用户 '$NEW_USER'"
  local nkeys=() l
  if [ "$NEW_USER_KEYSRC" = copy ]; then
    while IFS= read -r l; do nkeys+=("$l"); done < <(key_lines_of "$TARGET_KEY_FILE")
  else
    nkeys=("${NEW_USER_KEYS[@]}")
  fi
  create_user_account "$NEW_USER" "$NEW_USER_SUDO" ${nkeys[@]+"${nkeys[@]}"}
  NEW_USER_SUDO="$CREATED_SUDO_MODE"
  summary "Created user $NEW_USER (sudo: $NEW_USER_SUDO)" "已创建用户 $NEW_USER（sudo：$NEW_USER_SUDO）"
}

# ----------------------------------------------------------------------------
# Wizard state
# ----------------------------------------------------------------------------
PORT="" LEVEL=""
TARGET_USER="" TARGET_HOME="" TARGET_GROUP="" TARGET_KEY_FILE=""
TARGET_EXISTING_KEYS=0
TARGET_NEW_KEYS=()
NEW_USER="" NEW_USER_SUDO="" NEW_USER_KEYSRC="" NEW_USER_KEYS=()
ROOT_LOGIN="" ALLOW_USERS=""
DO_FIREWALL=0 DO_FAIL2BAN=0 DO_AUTOUPD=0 DO_SYSCTL=0 DO_NOTIFY=0
STRICT_CRYPTO=1 CONFIRMED_LOGIN=0 PORT_IN_EPHEMERAL=0
REBOOT_REASONS=()
SUMMARY=()

summary() { SUMMARY+=("$(L "$@")"); }

reset_wizard_state() {
  PORT="" LEVEL="" TARGET_USER="" TARGET_HOME="" TARGET_GROUP="" TARGET_KEY_FILE=""
  TARGET_EXISTING_KEYS=0 TARGET_NEW_KEYS=() NEW_USER="" NEW_USER_SUDO="" NEW_USER_KEYSRC="" NEW_USER_KEYS=()
  ROOT_LOGIN="" ALLOW_USERS="" DO_FIREWALL=0 DO_FAIL2BAN=0 DO_AUTOUPD=0 DO_SYSCTL=0 DO_NOTIFY=0
  STRICT_CRYPTO=1 CONFIRMED_LOGIN=0 PORT_IN_EPHEMERAL=0 SUMMARY=() ACCOUNT_UNLOCK_USERS=() BACKUP_DIR=""
}

level_name() {
  case "$1" in
    basic) L "basic" "基础 basic" ;; standard) L "standard" "标准 standard" ;; strict) L "strict" "严格 strict" ;; *) echo "$1" ;;
  esac
}

random_port() { # a free port below the default ephemeral range (no reservation needed)
  local p i
  for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    p=$(( 20000 + RANDOM % 12000 ))
    port_listening "$p" || { echo "$p"; return 0; }
  done
  echo "$DEFAULT_PORT"
}

# ----------------------------------------------------------------------------
# Wizard steps
# ----------------------------------------------------------------------------
select_port() {
  local p="$OPT_PORT" lo hi
  if [ -z "$p" ]; then
    hint "Current port: $CUR_PORTS. Enter a port, press Enter for $DEFAULT_PORT, or 'r' for a random free port." \
         "当前端口：$CUR_PORTS。输入新端口；直接回车使用 $DEFAULT_PORT；输入 r 随机选择一个空闲端口。"
    while true; do
      ask p "$(L "SSH port" "SSH 端口")" "$DEFAULT_PORT"
      case "$(lower "$p")" in r|random) p="$(random_port)"; info "Picked port $p" "已选择端口 $p" ;; esac
      if [[ "$p" =~ ^[0-9]+$ ]] && { [ "$((10#$p))" -eq 22 ] || { [ "$((10#$p))" -ge 1024 ] && [ "$((10#$p))" -le 65535 ]; }; }; then break; fi
      warn "Port must be 22 or between 1024 and 65535." "端口必须是 22 或 1024-65535 之间的数字。"
      [ "$ASSUME_YES" = 1 ] && die "Invalid port: $p" "无效端口：$p"
    done
  fi
  [[ "$p" =~ ^[0-9]+$ ]] || die "Port must be numeric." "端口必须是数字。"
  p=$((10#$p))
  if [ "$p" -ne 22 ] && { [ "$p" -lt 1024 ] || [ "$p" -gt 65535 ]; }; then
    die "Port must be 22 or between 1024 and 65535." "端口必须是 22 或 1024-65535 之间的数字。"
  fi
  if port_listening "$p" && ! in_list "$p" "$CUR_PORTS"; then
    die "Port $p is already used by another service (check: ss -ltnp | grep :$p)." \
        "端口 $p 已被其他服务占用（检查：ss -ltnp | grep :$p）。"
  fi
  if [ -r /proc/sys/net/ipv4/ip_local_port_range ]; then
    read -r lo hi </proc/sys/net/ipv4/ip_local_port_range || true
    if [ -n "${lo:-}" ] && [ "$p" -ge "$lo" ] && [ "$p" -le "$hi" ]; then
      PORT_IN_EPHEMERAL=1
      hint "Port $p is in the ephemeral range ($lo-$hi); it will be reserved so outgoing connections cannot take it." \
           "端口 $p 位于临时端口范围（$lo-$hi），将自动保留，防止被出站连接占用。"
    fi
  fi
  PORT="$p"
  ok "SSH port: $PORT" "SSH 端口：$PORT"
}

select_target_user() {
  local u="$OPT_USER" def="${SUDO_USER:-root}"
  [ -n "$u" ] || ask u "$(L "SSH login user (keys are installed for this account)" "SSH 登录用户（公钥将安装到该账户）")" "$def"
  id "$u" >/dev/null 2>&1 || die "User not found: $u" "用户不存在：$u"
  TARGET_USER="$u"
  TARGET_HOME="$(user_field "$u" 6)"
  TARGET_GROUP="$(id -gn "$u")"
  [ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME" ] || die "Home directory of '$u' does not exist: ${TARGET_HOME:-?}" "用户 '$u' 的家目录不存在：${TARGET_HOME:-?}"
  TARGET_KEY_FILE="$TARGET_HOME/.ssh/authorized_keys"
}

collect_target_keys() {
  if [ -f "$TARGET_KEY_FILE" ]; then
    say "  $(L "Existing keys in" "现有公钥") $C_DIM$TARGET_KEY_FILE$C_0"
    inspect_authorized_keys "$TARGET_KEY_FILE"
    [ "$TARGET_EXISTING_KEYS" -gt 0 ] || hint "(none usable)" "（没有可用公钥）"
  else
    hint "$TARGET_KEY_FILE does not exist yet." "$TARGET_KEY_FILE 尚不存在。"
  fi

  local src f l
  for src in ${OPT_KEYS[@]+"${OPT_KEYS[@]}"}; do
    while IFS= read -r l; do collect_key_line TARGET_NEW_KEYS "$TARGET_KEY_FILE" "$l" || true; done < <(expand_key_source "$src")
  done
  for f in ${OPT_KEY_FILES[@]+"${OPT_KEY_FILES[@]}"}; do
    [ -r "$f" ] || die "Cannot read key file: $f" "无法读取公钥文件：$f"
    while IFS= read -r l || [ -n "$l" ]; do collect_key_line TARGET_NEW_KEYS "$TARGET_KEY_FILE" "$l" || true; done <"$f"
  done

  if [ ${#OPT_KEYS[@]} -eq 0 ] && [ ${#OPT_KEY_FILES[@]} -eq 0 ]; then
    if [ "$TARGET_EXISTING_KEYS" -gt 0 ]; then
      if ! ask_yn "$(L "Use the existing key(s) without adding new ones?" "直接使用现有公钥，不再添加？")" y; then
        read_keys_interactive TARGET_NEW_KEYS "$TARGET_KEY_FILE"
      fi
    else
      warn "No usable key found for '$TARGET_USER'. You must add at least one." "'$TARGET_USER' 没有可用公钥，至少需要添加一把。"
      read_keys_interactive TARGET_NEW_KEYS "$TARGET_KEY_FILE"
    fi
  fi
  [ $(( TARGET_EXISTING_KEYS + ${#TARGET_NEW_KEYS[@]} )) -gt 0 ] || die "No usable SSH key for '$TARGET_USER'. Cannot continue." "'$TARGET_USER' 没有可用的 SSH 公钥，无法继续。"
}

select_level() {
  if [ -n "$OPT_LEVEL" ]; then LEVEL="$OPT_LEVEL"; ok "Level: $(level_name "$LEVEL")" "等级：$(level_name "$LEVEL")"; return; fi
  local c
  say "   $C_C$C_BOLD 1$C_0  $C_BOLD$(L "basic" "基础 basic")$C_0"
  hint "  Key-only login, custom port, password / keyboard-interactive login off" "  仅密钥登录、自定义端口、关闭密码与键盘交互登录"
  say "   $C_C$C_BOLD 2$C_0  $C_BOLD$(L "standard" "标准 standard")$C_0  $C_G$(L "(recommended)" "（推荐）")$C_0"
  hint "  + root login restricted, login/session limits, X11 off, key fingerprints logged," \
       "  + 限制 root 登录、登录尝试与会话限制、关闭 X11、记录登录公钥指纹，"
  hint "    fail2ban / auto security updates / sysctl offered" "    并提供 fail2ban / 自动安全更新 / 内核参数加固"
  say "   $C_C$C_BOLD 3$C_0  $C_BOLD$(L "strict" "严格 strict")$C_0"
  hint "  + no root login, no forwarding / tunnels, modern crypto only" "  + 禁止 root 登录、禁止端口转发与隧道、仅现代加密算法"
  hint "    ${C_Y}breaks VS Code Remote-SSH and ssh -L/-D tunnels$C_0$C_DIM" "    ${C_Y}会导致 VS Code Remote-SSH 和 ssh -L/-D 隧道不可用$C_0$C_DIM"
  while true; do
    ask c "$(L "Level" "选择等级") [1-3]" "2"
    case "$(lower "$c")" in
      1|basic) LEVEL=basic; break ;;
      2|standard) LEVEL=standard; break ;;
      3|strict) LEVEL=strict; break ;;
      *) warn "Please enter 1, 2 or 3." "请输入 1、2 或 3。" ;;
    esac
  done
  ok "Level: $(level_name "$LEVEL")" "等级：$(level_name "$LEVEL")"
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
          die "Strict level disables root SSH login, but root is the only SSH user. Create a sudo user (--new-user) or choose standard." \
              "严格等级会禁止 root 登录，但 root 是唯一的 SSH 用户。请创建 sudo 用户（--new-user）或改选标准等级。"
        fi
        warn "Strict disables root SSH login and no SSH user with sudo rights was found." "严格等级会禁止 root 登录，但没有找到具有 sudo 权限的 SSH 用户。"
        hint "You would need 'su' with the root password to administer the server." "之后需要用 root 密码执行 su 才能管理服务器。"
        ask_yn "$(L "Continue anyway?" "仍然继续？")" n || die "Aborted." "已中止。"
      fi ;;
    standard)
      if [ -n "$OPT_ROOT_LOGIN" ]; then ROOT_LOGIN="$OPT_ROOT_LOGIN"
      elif [ "$ASSUME_YES" = 1 ]; then ROOT_LOGIN=prohibit-password
      elif [ -n "$admin" ]; then
        if ask_yn "$(L "Disable root SSH login completely (admin via '$admin' + sudo)?" "完全禁止 root 通过 SSH 登录？（改用 '$admin' + sudo 管理）")" y; then ROOT_LOGIN=no; else ROOT_LOGIN=prohibit-password; fi
      else
        ROOT_LOGIN=prohibit-password
      fi
      if [ "$ROOT_LOGIN" = no ] && [ -z "$admin" ]; then
        [ "$TARGET_USER" = root ] && die "--root-login no would lock out root, the only SSH user." "--root-login no 会锁死唯一的 SSH 用户 root。"
        warn "Root login disabled but no sudo-capable SSH user was found." "已禁止 root 登录，但没有找到具有 sudo 权限的 SSH 用户。"
      fi ;;
  esac
  if [ "$SSH_VER_NUM" -gt 0 ] && [ "$SSH_VER_NUM" -lt 700 ] && [ "$ROOT_LOGIN" = prohibit-password ]; then ROOT_LOGIN=without-password; fi
  return 0
}

users_with_keys() {
  local u home
  while IFS= read -r u; do
    home="$(user_field "$u" 6)"
    if [ -s "$home/.ssh/authorized_keys" ]; then printf '%s ' "$u"; fi
  done < <(login_users)
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
    hint "AllowUsers restricts SSH logins to an explicit list: $list" "AllowUsers 白名单：只允许这些用户通过 SSH 登录：$list"
    [ -n "$others" ] && warn "These users also have keys and would LOSE SSH access:$others" "以下用户也有公钥，启用后将无法再通过 SSH 登录：$others"
    ask_yn "$(L "Enable AllowUsers?" "启用 AllowUsers 白名单？")" "$def" || return 0
    local extra=""
    ask extra "$(L "Additional users to allow (space separated, empty for none)" "额外允许的用户（空格分隔，留空表示没有）")" ""
    for u in $extra; do
      if id "$u" >/dev/null 2>&1; then list="$list $u"; else warn "Skipping unknown user: $u" "跳过不存在的用户：$u"; fi
    done
  fi
  ALLOW_USERS="$list"
}

select_modules() {
  local def=n
  [ "$LEVEL" != basic ] && def=y
  # Firewall opening is a safety measure, on by default whenever a firewall is active
  if [ -n "$OPT_FIREWALL" ]; then DO_FIREWALL="$OPT_FIREWALL"
  elif [ "$FW" != none ]; then
    if ask_yn "$(L "Open TCP $PORT in the active firewall ($FW)?" "在当前防火墙（$FW）中放行 TCP $PORT？")" y; then DO_FIREWALL=1; fi
  else
    hint "No active host firewall detected — remember your provider's security group / cloud firewall." \
         "未检测到主机防火墙——别忘了在云服务商的安全组/防火墙中放行新端口。"
  fi
  if [ "$CONTAINER_KIND" = app ]; then
    hint "Running inside a $VIRT container: fail2ban, auto-updates, sysctl and login alerts are skipped." \
         "当前在 $VIRT 容器中运行：跳过 fail2ban、自动更新、sysctl 与登录提醒。"
    return 0
  fi
  if [ -n "$OPT_FAIL2BAN" ]; then DO_FAIL2BAN="$OPT_FAIL2BAN"
  elif ask_yn "$(L "Install fail2ban (ban IPs with repeated SSH failures)?" "安装 fail2ban（自动封禁反复登录失败的 IP）？")" "$def"; then DO_FAIL2BAN=1; fi
  if [ -n "$OPT_AUTOUPD" ]; then DO_AUTOUPD="$OPT_AUTOUPD"
  elif ask_yn "$(L "Enable automatic security updates?" "启用自动安全更新？")" "$def"; then DO_AUTOUPD=1; fi
  if [ "$CONTAINER_KIND" = system ]; then
    hint "System container ($VIRT): kernel sysctl hardening is usually not permitted; skipped." \
         "系统容器（$VIRT）通常不允许修改内核参数，跳过 sysctl 加固。"
  elif [ -n "$OPT_SYSCTL" ]; then DO_SYSCTL="$OPT_SYSCTL"
  elif ask_yn "$(L "Apply kernel/network sysctl hardening?" "应用内核/网络参数（sysctl）加固？")" "$def"; then DO_SYSCTL=1; fi
  if [ "$ASSUME_YES" = 0 ] && [ "$(eff usepam)" = yes ] && [ ! -f "$NOTIFY_CONF" ]; then
    if ask_yn "$(L "Set up login alerts (Telegram / WeCom / DingTalk / Feishu / webhook) afterwards?" "完成后配置登录提醒（Telegram / 企业微信 / 钉钉 / 飞书 / Webhook）？")" n; then DO_NOTIFY=1; fi
  fi
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
  local stage="$1" content keys f tmp header
  content="$(gen_config "$stage")"
  keys="$(awk '!/^#/ && NF { print tolower($1) }' <<<"$content" | sort -u | paste -sd'|' -)"
  while IFS= read -r f; do neutralize_file "$f" "$keys"; done < <(config_files)

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
  load_eff || { err "sshd -T failed." "sshd -T 执行失败。"; return 1; }
  local bad=0 v ports la
  ports="$(eff_all port | sort -u | tr '\n' ' ')"
  if [ "$(trim "$ports")" != "$PORT" ]; then err "Effective ports are '$ports', expected '$PORT'." "实际生效端口为 '$ports'，预期为 '$PORT'。"; bad=1; fi
  for la in $(eff_all listenaddress); do
    case "$la" in *:"$PORT") ;; *) err "ListenAddress $la does not use port $PORT." "ListenAddress $la 没有使用端口 $PORT。"; bad=1 ;; esac
  done
  check_kv() {
    v="$(lower "$(eff "$1")")"
    if [ -n "$v" ] && [ "$v" != "$2" ]; then err "Effective $1 is '$v', expected '$2'." "实际生效的 $1 为 '$v'，预期为 '$2'。"; bad=1; fi
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
    err "Another configuration source overrides the hardening. Files mentioning these settings:" \
        "有其他配置覆盖了加固设置。涉及这些选项的文件："
    grep -rniE '^[[:space:]]*(port|passwordauthentication|permitrootlogin|kbdinteractiveauthentication|listenaddress)[[:space:]]' \
      ${VENDOR_CFG:+"$VENDOR_CFG"} "$SSH_DIR"/sshd_config "$SSHD_DROPIN_DIR" 2>/dev/null | sed 's/^/      /' >&2 || true
    return 1
  fi
  ok "Effective configuration verified (sshd -T)." "已校验实际生效配置（sshd -T）。"
}

warn_match_overrides() {
  local f hits
  while IFS= read -r f; do
    hits="$(awk '
      { t=$0; sub(/^[ \t]+/, "", t); split(t, a, /[ \t=]+/); k=tolower(a[1]); v=tolower(a[2]) }
      k=="match" { m=1; hdr=t; next }
      m && t !~ /^#/ && ((k=="passwordauthentication" && v=="yes") || (k=="permitrootlogin" && v=="yes") || (k=="kbdinteractiveauthentication" && v=="yes")) { print "      " FILENAME ": [" hdr "] " t }
    ' "$f")"
    if [ -n "$hits" ]; then
      warn "Match blocks re-enable weaker authentication for some connections:" "Match 块为部分连接重新开启了较弱的认证方式："
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
  ok "Backup: $BACKUP_DIR" "已备份：$BACKUP_DIR"
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

list_backups() { ls -1d "$STATE_DIR"/backup-* 2>/dev/null | sort || true; }

meta_get() { sed -n "s/^$2=//p" "$1/meta" 2>/dev/null | head -n1; }

restore_backup_dir() { # restore_backup_dir DIR
  local dir="$1"
  [ -n "$dir" ] && [ -f "$dir/restore.sh" ] || die "No backup found${dir:+ in $dir} (backups live in $STATE_DIR)." "没有找到备份${dir:+（$dir）}（备份目录：$STATE_DIR）。"
  card_open "$(L "Restore backup" "恢复备份")"
  card_kv "$(L "Backup" "备份")" "$dir"
  card_kv "$(L "Created" "创建时间")" "$(meta_get "$dir" date)"
  card_kv "$(L "Port change" "端口变更")" "$(meta_get "$dir" old_ports) $G_ARROW $(meta_get "$dir" new_port)"
  card_kv "$(L "Level" "等级")" "$(level_name "$(meta_get "$dir" level)")"
  card_close "$(L "SSH config returns to the state BEFORE this run" "SSH 配置将恢复到该次运行之前的状态")"
  ask_yn "$(L "Restore this SSH configuration now?" "现在恢复该 SSH 配置？")" y || { info "Cancelled." "已取消。"; return 1; }
  if sh "$dir/restore.sh" >>"$LOG_FILE" 2>&1; then
    ok "Restored. Verify you can log in on the old port before closing this session." "已恢复。关闭当前会话前，请先确认能用原端口登录。"
    load_eff || true
    refresh_cur_ports
  else
    err "Restore script reported an error (see $LOG_FILE)." "恢复脚本报告错误（详见 $LOG_FILE）。"
    return 1
  fi
}

run_restore() {
  local dir="$OPT_RESTORE_DIR"
  [ -n "$dir" ] || dir="$(list_backups | tail -n1)"
  restore_backup_dir "$dir"
}

# ----------------------------------------------------------------------------
# Pre-apply system changes: SELinux, firewall, reserved port, host keys
# ----------------------------------------------------------------------------
selinux_allow_port() {
  have getenforce || return 0
  local mode labelled
  mode="$(getenforce 2>/dev/null || echo Disabled)"
  [ "$mode" != Disabled ] || return 0
  [ "$PORT" != 22 ] || return 0
  if ! have semanage; then
    case "$PKG" in
      dnf|zypper|apt-get) pkg_install policycoreutils-python-utils || true ;;
      yum) pkg_install policycoreutils-python || pkg_install policycoreutils-python-utils || true ;;
    esac
  fi
  if ! have semanage; then
    if [ "$mode" = Enforcing ]; then
      die "SELinux is enforcing and 'semanage' is unavailable: sshd could not bind port $PORT." \
          "SELinux 处于强制模式且没有 semanage：sshd 将无法绑定端口 $PORT。"
    fi
    warn "semanage unavailable; SELinux is $mode, continuing." "没有 semanage；SELinux 为 $mode 模式，继续。"
    return 0
  fi
  labelled="$(semanage port -l 2>/dev/null | awk '$1=="ssh_port_t" { $1=""; $2=""; gsub(/ /, ""); print }')"
  if in_list "$PORT" "${labelled//,/ }"; then
    info "SELinux already allows sshd on port $PORT." "SELinux 已允许 sshd 使用端口 $PORT。"
    return 0
  fi
  if semanage port -a -t ssh_port_t -p tcp "$PORT" 2>/dev/null || semanage port -m -t ssh_port_t -p tcp "$PORT" 2>/dev/null; then
    ok "SELinux: labelled tcp/$PORT as ssh_port_t." "SELinux：已将 tcp/$PORT 标记为 ssh_port_t。"
    summary "SELinux: tcp/$PORT labelled ssh_port_t" "SELinux：tcp/$PORT 已标记为 ssh_port_t"
  else
    die "Failed to label port $PORT for SELinux (semanage port -a -t ssh_port_t -p tcp $PORT)." \
        "无法为 SELinux 标记端口 $PORT（semanage port -a -t ssh_port_t -p tcp $PORT）。"
  fi
}

firewall_open_port() {
  [ "$DO_FIREWALL" = 1 ] || return 0
  case "$FW" in
    ufw)
      ufw allow "$PORT/tcp" comment 'ssh-hardening' >/dev/null 2>&1 || ufw allow "$PORT/tcp" >/dev/null 2>&1 \
        || { warn "ufw: failed to allow $PORT/tcp" "ufw：放行 $PORT/tcp 失败"; return 1; }
      ok "ufw: allowed $PORT/tcp" "ufw：已放行 $PORT/tcp" ;;
    firewalld)
      firewall-cmd --permanent --add-port="$PORT/tcp" >/dev/null 2>&1 && firewall-cmd --add-port="$PORT/tcp" >/dev/null 2>&1 \
        || { warn "firewalld: failed to open $PORT/tcp" "firewalld：放行 $PORT/tcp 失败"; return 1; }
      ok "firewalld: opened $PORT/tcp (runtime + permanent, default zone)" "firewalld：已放行 $PORT/tcp（运行时 + 永久，默认区域）" ;;
    iptables)
      local t
      for t in iptables ip6tables; do
        have "$t" || continue
        "$t" -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || "$t" -I INPUT 1 -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true
      done
      ok "iptables: inserted ACCEPT rule for tcp/$PORT" "iptables：已插入 tcp/$PORT 的 ACCEPT 规则"
      if have netfilter-persistent; then netfilter-persistent save >/dev/null 2>&1 && ok "Rules saved (netfilter-persistent)." "规则已保存（netfilter-persistent）。"
      elif [ "$FAMILY" = rhel ] && have service && service iptables save >/dev/null 2>&1; then ok "Rules saved (service iptables save)." "规则已保存（service iptables save）。"
      elif [ "$INIT" = openrc ] && rc-service iptables save >/dev/null 2>&1; then ok "Rules saved (rc-service iptables save)." "规则已保存（rc-service iptables save）。"
      else warn "iptables rule is NOT persistent across reboots. Save it with your distro's tool (e.g. iptables-save > /etc/iptables/rules.v4)." \
                "iptables 规则重启后会丢失，请用发行版工具保存（如 iptables-save > /etc/iptables/rules.v4）。"; fi ;;
    nftables)
      local fam tbl fam_tbl
      for fam_tbl in "inet filter" "ip filter"; do
        fam="${fam_tbl% *}"; tbl="${fam_tbl#* }"
        if nft list chain "$fam" "$tbl" input >/dev/null 2>&1; then
          nft insert rule "$fam" "$tbl" input tcp dport "$PORT" accept && ok "nftables: inserted accept rule for tcp/$PORT ($fam $tbl input)" "nftables：已插入 tcp/$PORT 放行规则（$fam $tbl input）"
          warn "Add 'tcp dport $PORT accept' to /etc/nftables.conf as well, or the rule is lost on reboot." \
               "请同时在 /etc/nftables.conf 中加入 'tcp dport $PORT accept'，否则重启后规则丢失。"
          return 0
        fi
      done
      warn "nftables input chain not found automatically — add 'tcp dport $PORT accept' manually BEFORE continuing." \
           "未能自动找到 nftables 的 input 链——请先手动添加 'tcp dport $PORT accept' 再继续。"
      ask_yn "$(L "Have you opened TCP $PORT yourself?" "你已经手动放行 TCP $PORT 了吗？")" n || die "Aborted: port not opened." "已中止：端口未放行。" ;;
  esac
  summary "Firewall ($FW): TCP $PORT opened" "防火墙（$FW）：已放行 TCP $PORT"
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
    ok "Reserved port $PORT (net.ipv4.ip_local_reserved_ports)." "已保留端口 $PORT（net.ipv4.ip_local_reserved_ports）。"
  fi
}

prepare_host_keys() {
  local t bits tmp
  [ "$LEVEL" = strict ] || return 0
  # Strict pins HostKey to Ed25519 + RSA: generate them if missing (never DSA)
  if [ ! -f "$SSH_DIR/ssh_host_ed25519_key" ]; then ssh-keygen -q -t ed25519 -N '' -f "$SSH_DIR/ssh_host_ed25519_key" && ok "Generated Ed25519 host key." "已生成 Ed25519 主机密钥。"; fi
  if [ ! -f "$SSH_DIR/ssh_host_rsa_key" ]; then ssh-keygen -q -t rsa -b 4096 -N '' -f "$SSH_DIR/ssh_host_rsa_key" && ok "Generated RSA-4096 host key." "已生成 RSA-4096 主机密钥。"; fi
  for t in "$SSH_DIR/ssh_host_dsa_key" "$SSH_DIR/ssh_host_dsa_key.pub"; do
    if [ -f "$t" ]; then mv "$t" "$t.disabled"; echo "$t" >>"$BACKUP_DIR/disabled_hostkeys"; ok "Disabled DSA host key: $t" "已禁用 DSA 主机密钥：$t"; fi
  done
  bits="$(ssh-keygen -l -f "$SSH_DIR/ssh_host_rsa_key.pub" 2>/dev/null | awk '{print $1}' || true)"
  if [ -n "$bits" ] && [ "$bits" -lt 3072 ]; then
    warn "RSA host key is only $bits bits. Regenerating changes the host fingerprint, so it is left alone:" \
         "RSA 主机密钥只有 $bits 位。重新生成会改变主机指纹，因此保持不变，如需更换请执行："
    hint "ssh-keygen -f $SSH_DIR/ssh_host_rsa_key -t rsa -b 4096 -N ''  (then update clients' known_hosts)" \
         "ssh-keygen -f $SSH_DIR/ssh_host_rsa_key -t rsa -b 4096 -N ''（之后更新客户端 known_hosts）"
  fi
  # Drop Diffie-Hellman group-exchange moduli smaller than 3072 bits
  if [ -f "$SSH_DIR/moduli" ]; then
    new_tmp; tmp="$NEW_TMP"
    awk '/^#/ || $5 >= 3071' "$SSH_DIR/moduli" >"$tmp"
    if [ "$(grep -vc '^#' "$tmp" || true)" -gt 0 ] && ! same_file "$tmp" "$SSH_DIR/moduli"; then
      cat "$tmp" >"$SSH_DIR/moduli"
      ok "Removed DH moduli < 3072 bits from $SSH_DIR/moduli." "已从 $SSH_DIR/moduli 移除小于 3072 位的 DH 参数。"
    fi
  fi
  if [ -d /etc/crypto-policies ]; then
    warn "crypto-policies are in use. On RHEL 8 they are passed to sshd on the command line and override the algorithm lists set here." \
         "系统使用 crypto-policies。RHEL 8 上它通过命令行传给 sshd，会覆盖这里设置的算法列表。"
    hint "Consider: update-crypto-policies --set FUTURE" "可考虑执行：update-crypto-policies --set FUTURE"
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
      warn "sshd rejected the algorithm lists ($SSHD_TEST_OUT); retrying with the distro's default crypto." \
           "sshd 不接受算法列表（$SSHD_TEST_OUT），改用发行版默认算法重试。"
      STRICT_CRYPTO=0
      write_sshd_config "$stage"
      sshd_test || { err "sshd -t: $SSHD_TEST_OUT"; return 1; }
    else
      err "sshd -t: $SSHD_TEST_OUT"
      return 1
    fi
  fi
  ok "Configuration syntax OK (sshd -t)." "配置语法检查通过（sshd -t）。"
  if [ "$stage" = final ]; then verify_effective || return 1; fi
  restart_and_verify "$ports"
}

ssh_self_test() {
  local out rc=0
  have ssh || { warn "ssh client not found; skipping self-test." "未找到 ssh 客户端，跳过自测。"; return 0; }
  out="$(ssh -o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=accept-new \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout="$SSH_SELFTEST_TIMEOUT" \
        -p "$PORT" "$TARGET_USER@127.0.0.1" true 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    warn "Self-test failed (exit $rc): $(printf '%s' "$out" | tail -n1)" "自测失败（退出码 $rc）：$(printf '%s' "$out" | tail -n1)"
    return 1
  fi
  ok "Self-test: key login to $TARGET_USER@127.0.0.1:$PORT works." "自测通过：$TARGET_USER@127.0.0.1:$PORT 密钥登录正常。"
}

# The account to test with: root is useless once root login is disabled
login_user() {
  if [ "$TARGET_USER" = root ] && [ "$ROOT_LOGIN" = no ] && [ -n "$NEW_USER" ]; then echo "$NEW_USER"; else echo "$TARGET_USER"; fi
}

# Dead-man switch: roll back automatically unless a new login is confirmed in time
confirm_new_login() {
  if [ "$CONFIRM_TIMEOUT" -eq 0 ] || [ -z "$TTY_FD" ] || [ "$ASSUME_YES" = 1 ]; then
    warn "Login confirmation skipped (non-interactive or --confirm-timeout 0)." "已跳过登录确认（非交互模式或 --confirm-timeout 0）。"
    hint "Keep this session open and test: ssh -p $PORT $(login_user)@$SERVER_IP" "请保持当前会话并测试：ssh -p $PORT $(login_user)@$SERVER_IP"
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

  card_open "$(L "Verify your new login — auto-rollback in ${CONFIRM_TIMEOUT}s" "请验证新登录 —— ${CONFIRM_TIMEOUT} 秒后自动回滚")"
  card_line "$(L "1. Keep THIS session open." "1. 保持当前会话，不要关闭。")"
  card_line "$(L "2. In a NEW terminal run:" "2. 新开一个终端执行：")"
  card_line ""
  card_line "     $C_BOLD$C_G ssh -p $PORT $(login_user)@$SERVER_IP $C_0"
  card_line ""
  card_line "$C_DIM$(L "   (allow TCP $PORT in your cloud security group first)" "   （请先在云服务商安全组中放行 TCP $PORT）")$C_0"
  card_line "$(L "3. Login works? Type 'yes' here. Type 'rollback' to revert now." "3. 能登录就回到这里输入 yes；输入 rollback 立即回滚。")"
  card_close "$(L "Timeout, a dropped session or 'rollback' restores the old configuration" "超时、会话断开或输入 rollback 都会自动恢复原配置")"
  start=$SECONDS
  while true; do
    left=$(( CONFIRM_TIMEOUT - (SECONDS - start) ))
    if [ "$left" -le 0 ]; then ans=""; break; fi
    if ! read_tty ans "$(prompt_fmt "$(L "Login works? (yes/rollback)" "新登录成功了吗？(yes/rollback)")" "$(L "${left}s left" "剩余 ${left} 秒")")" "$left"; then
      [ -n "$ans" ] || { ans=""; break; }
    fi
    ans="$(lower "$(trim "$ans")")"
    case "$ans" in
      yes|y|是)
        : >"$BACKUP_DIR/confirmed"; kill "$pid" 2>/dev/null || true; CONFIRMED_LOGIN=1
        ok "Confirmed. Rollback timer cancelled." "已确认，回滚计时器已取消。"; return 0 ;;
      rollback|no|n|回滚) break ;;
      *) say "  $(L "Please type 'yes' or 'rollback'." "请输入 yes 或 rollback。")" ;;
    esac
  done
  say ""
  : >"$BACKUP_DIR/confirmed"
  kill "$pid" 2>/dev/null || true
  ROLLBACK_ARMED=0
  warn "Not confirmed — restoring the previous SSH configuration." "未确认——正在恢复之前的 SSH 配置。"
  sh "$BACKUP_DIR/restore.sh" >>"$LOG_FILE" 2>&1 && ok "Previous configuration restored." "已恢复之前的配置。" \
    || err "Restore reported an error (see $LOG_FILE)." "恢复出错（详见 $LOG_FILE）。"
  die "Rolled back. Check the firewall / security group and your keys, then run again." \
      "已回滚。请检查防火墙/安全组和公钥后重新运行。"
}

# ----------------------------------------------------------------------------
# Optional modules
# ----------------------------------------------------------------------------
setup_auto_updates() {
  section "Automatic security updates" "自动安全更新"
  case "$FAMILY" in
    debian)
      pkg_install unattended-upgrades || { warn "Could not install unattended-upgrades." "无法安装 unattended-upgrades。"; return 1; }
      [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && [ -n "$BACKUP_DIR" ] && cp -p /etc/apt/apt.conf.d/20auto-upgrades "$BACKUP_DIR/" 2>/dev/null
      cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
      chmod 644 /etc/apt/apt.conf.d/20auto-upgrades
      if [ "$INIT" = systemd ]; then systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true; fi
      ok "unattended-upgrades enabled (security origins only; automatic reboot stays off)." "已启用 unattended-upgrades（仅安全更新，不会自动重启）。"
      summary "Auto updates: unattended-upgrades" "自动更新：unattended-upgrades" ;;
    rhel)
      if [ "$PKG" = dnf ]; then
        pkg_install dnf-automatic || pkg_install dnf5-plugin-automatic || { warn "Could not install dnf-automatic." "无法安装 dnf-automatic。"; return 1; }
        local conf=/etc/dnf/automatic.conf type=security t done_t=""
        [ "$OS_ID" = centos ] && type=default   # CentOS Stream publishes no security errata
        if [ -f "$conf" ]; then
          [ -n "$BACKUP_DIR" ] && cp -p "$conf" "$BACKUP_DIR/" 2>/dev/null || true
          sed -i -E "s/^#?[[:space:]]*upgrade_type[[:space:]]*=.*/upgrade_type = $type/; s/^#?[[:space:]]*apply_updates[[:space:]]*=.*/apply_updates = yes/" "$conf"
          grep -q '^upgrade_type' "$conf" || sed -i "/^\[commands\]/a upgrade_type = $type" "$conf"
          grep -q '^apply_updates' "$conf" || sed -i "/^\[commands\]/a apply_updates = yes" "$conf"
        else
          printf '[commands]\nupgrade_type = %s\napply_updates = yes\n' "$type" >"$conf"
        fi
        for t in dnf-automatic.timer dnf5-automatic.timer dnf-automatic-install.timer; do
          if systemctl enable --now "$t" >/dev/null 2>&1; then done_t="$t"; break; fi
        done
        [ -n "$done_t" ] || { warn "Could not enable a dnf-automatic timer." "无法启用 dnf-automatic 定时器。"; return 1; }
        ok "dnf-automatic enabled ($done_t, upgrade_type=$type)." "已启用 dnf-automatic（$done_t，upgrade_type=$type）。"
        summary "Auto updates: dnf-automatic ($type)" "自动更新：dnf-automatic（$type）"
      else
        pkg_install yum-cron || { warn "Could not install yum-cron." "无法安装 yum-cron。"; return 1; }
        sed -i -E 's/^update_cmd[[:space:]]*=.*/update_cmd = security/; s/^apply_updates[[:space:]]*=.*/apply_updates = yes/' /etc/yum/yum-cron.conf
        svc_enable_start yum-cron || true
        ok "yum-cron enabled (security updates)." "已启用 yum-cron（安全更新）。"
        summary "Auto updates: yum-cron" "自动更新：yum-cron"
      fi ;;
    suse)
      [ "$INIT" = systemd ] || { warn "Automatic updates on SUSE require systemd here; skipped." "SUSE 上的自动更新需要 systemd，已跳过。"; return 1; }
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
        || { warn "Could not enable the zypper patch timer." "无法启用 zypper 补丁定时器。"; return 1; }
      ok "Daily 'zypper patch --category security' timer enabled." "已启用每日 'zypper patch --category security' 定时器。"
      summary "Auto updates: zypper security patch timer" "自动更新：zypper 安全补丁定时器" ;;
    alpine)
      warn "Alpine has no official unattended-upgrade mechanism; schedule 'apk -U upgrade' yourself if desired." \
           "Alpine 没有官方的无人值守升级机制，如有需要请自行定时执行 'apk -U upgrade'。"; return 1 ;;
    arch)
      warn "Unattended upgrades are not recommended on Arch (rolling release); skipped." "Arch 为滚动发行版，不建议无人值守升级，已跳过。"; return 1 ;;
    *)
      warn "Automatic updates are not supported for this distribution; skipped." "当前发行版不支持自动更新，已跳过。"; return 1 ;;
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

setup_fail2ban() { # setup_fail2ban [port]
  local port="${1:-$PORT}"
  section "fail2ban"
  if ! have fail2ban-client; then
    local extra=()
    [ "$FAMILY" = debian ] && [ "$INIT" = systemd ] && extra=(python3-systemd)
    if ! pkg_install fail2ban ${extra[@]+"${extra[@]}"}; then
      if [ "$FAMILY" = rhel ] && [ "$PKG" != yum ] && ask_yn "$(L "fail2ban requires the EPEL repository. Enable EPEL?" "fail2ban 需要 EPEL 软件源，是否启用 EPEL？")" y; then
        case "$OS_ID" in
          ol) pkg_install "oracle-epel-release-el${OS_VER%%.*}" || true ;;
          *) pkg_install epel-release || true ;;
        esac
        pkg_install fail2ban || true
      fi
    fi
  fi
  have fail2ban-client || { warn "fail2ban is not available; skipped." "无法使用 fail2ban，已跳过。"; return 1; }

  local backend=auto banaction ignore="127.0.0.1/8 ::1"
  if [ ! -f /var/log/auth.log ] && [ ! -f /var/log/secure ] && [ ! -f /var/log/messages ]; then
    # Debian 12+/Ubuntu 24.04 minimal images log only to the journal
    if [ "$INIT" = systemd ] && have journalctl; then backend=systemd
    else warn "No SSH log file (auth.log/secure/messages) and no systemd journal: install a syslog daemon first." \
              "没有 SSH 日志文件（auth.log/secure/messages）也没有 systemd 日志，请先安装 syslog 服务。"; return 1; fi
  fi
  banaction="$(pick_f2b_banaction)"
  [ -n "$CLIENT_IP" ] && ignore="$ignore $CLIENT_IP"
  mkdir -p /etc/fail2ban/jail.d
  {
    echo "# Generated by ssh-hardening v$SCRIPT_VERSION"
    echo "[sshd]"
    echo "enabled = true"
    echo "port = $port"
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
    warn "fail2ban rejected the configuration; removing $F2B_JAIL_FILE." "fail2ban 拒绝了该配置，已删除 $F2B_JAIL_FILE。"
    rm -f "$F2B_JAIL_FILE"
    return 1
  fi
  svc_enable_start fail2ban || true
  sleep 2
  if fail2ban-client status sshd >/dev/null 2>&1; then
    ok "fail2ban active: sshd jail on port $port (backend=$backend${banaction:+, $banaction}${CLIENT_IP:+, whitelisted $CLIENT_IP})." \
       "fail2ban 已启用：sshd 监狱，端口 $port（backend=$backend${banaction:+，$banaction}${CLIENT_IP:+，已将 $CLIENT_IP 加入白名单}）。"
    summary "fail2ban: sshd jail enabled" "fail2ban：sshd 监狱已启用"
  else
    warn "fail2ban did not report the sshd jail yet; check: fail2ban-client status sshd" "fail2ban 暂未报告 sshd 监狱状态，请检查：fail2ban-client status sshd"
  fi
}

setup_sysctl() {
  section "Kernel / network sysctl hardening" "内核 / 网络参数加固"
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
  [ -f "$SYSCTL_FILE" ] && [ -n "$BACKUP_DIR" ] && cp -p "$SYSCTL_FILE" "$BACKUP_DIR/" 2>/dev/null
  cat "$tmp" >"$SYSCTL_FILE"
  chmod 644 "$SYSCTL_FILE"
  ok "Applied $applied sysctl setting(s) live and persisted them in $SYSCTL_FILE ($skipped not supported/permitted)." \
     "已即时应用 $applied 项内核参数并写入 $SYSCTL_FILE（$skipped 项不支持或不允许）。"
  hint "IP forwarding and rp_filter are deliberately untouched (Docker/VPN/router hosts depend on them)." \
       "刻意未修改 IP 转发与 rp_filter（Docker / VPN / 路由主机依赖它们）。"
  summary "sysctl: $applied settings in $SYSCTL_FILE" "sysctl：$SYSCTL_FILE 中 $applied 项设置"
}

check_reboot_required() {
  REBOOT_REASONS=()
  [ "$CONTAINER_KIND" = "" ] || return 0
  if [ -f /var/run/reboot-required ]; then
    REBOOT_REASONS+=("$(L "system reports /var/run/reboot-required" "系统提示需要重启（/var/run/reboot-required）")$( [ -f /var/run/reboot-required.pkgs ] && printf ' (%s)' "$(tr '\n' ' ' </var/run/reboot-required.pkgs | sed 's/ $//')")")
  fi
  if have needs-restarting; then
    needs-restarting -r >/dev/null 2>&1 || [ $? -ne 1 ] || REBOOT_REASONS+=("$(L "needs-restarting: core libraries or kernel updated" "needs-restarting：核心库或内核已更新")")
  elif [ "$PKG" = dnf ] && dnf needs-restarting --help >/dev/null 2>&1; then
    dnf needs-restarting -r >/dev/null 2>&1 || [ $? -ne 1 ] || REBOOT_REASONS+=("$(L "dnf needs-restarting: core libraries or kernel updated" "dnf needs-restarting：核心库或内核已更新")")
  fi
  if [ "$PKG" = zypper ]; then
    zypper needs-rebooting >/dev/null 2>&1 || [ $? -ne 102 ] || REBOOT_REASONS+=("zypper needs-rebooting")
  fi
  if [ -d /lib/modules ] && [ ! -d "/lib/modules/$(uname -r)" ] && [ -n "$(ls /lib/modules 2>/dev/null)" ]; then
    REBOOT_REASONS+=("$(L "running kernel $(uname -r) is no longer installed (kernel was upgraded)" "正在运行的内核 $(uname -r) 已被升级移除")")
  fi
  return 0
}

reboot_prompt() {
  [ "$CONTAINER_KIND" != app ] || return 0
  check_reboot_required
  if [ "$LEVEL" = basic ] && [ ${#REBOOT_REASONS[@]} -eq 0 ] && [ "$OPT_REBOOT" != 1 ]; then
    info "No reboot required (SSH changes are live)." "无需重启（SSH 修改已即时生效）。"
    return 0
  fi
  local r do_reboot=0 i
  if [ ${#REBOOT_REASONS[@]} -gt 0 ]; then
    card_open "$C_Y$(L "Reboot required" "需要重启")$C_0"
    for r in "${REBOOT_REASONS[@]}"; do card_line "$G_BULLET $r"; done
    card_close
  else
    card_open "$(L "Reboot (optional)" "重启（可选）")"
    card_line "$(L "Not strictly required: SSH, firewall and sysctl changes are already live." "并非必需：SSH、防火墙和内核参数的修改都已即时生效。")"
    card_line "$(L "Recommended once while you still have console access: it proves sshd," "建议趁还有控制台（VNC）访问时重启一次，验证 sshd、")"
    card_line "$(L "the firewall rule and sysctl settings all come back on port $PORT." "防火墙规则和内核参数在开机后都能在端口 $PORT 上正确恢复。")"
    card_close
  fi
  if [ "$CONFIRMED_LOGIN" != 1 ] && [ "$OPT_REBOOT" != 1 ]; then
    warn "Verify a NEW login on port $PORT before rebooting: ssh -p $PORT $(login_user)@$SERVER_IP" \
         "重启前请先验证新端口能登录：ssh -p $PORT $(login_user)@$SERVER_IP"
  fi
  if [ "$OPT_REBOOT" = 1 ]; then do_reboot=1
  elif [ "$OPT_REBOOT" = 0 ]; then do_reboot=0
  elif ask_yn "$(L "Reboot now?" "现在重启？")" n; then do_reboot=1; fi
  if [ "$do_reboot" = 0 ]; then
    [ ${#REBOOT_REASONS[@]} -gt 0 ] && warn "Remember to reboot soon (sudo reboot)." "请尽快重启（sudo reboot）。"
    return 0
  fi
  for i in 10 9 8 7 6 5 4 3 2 1; do
    printf '\r  %s%s%s ' "$C_Y" "$(L "Rebooting in ${i}s (Ctrl+C to cancel)..." "${i} 秒后重启（Ctrl+C 取消）……")" "$C_0" >&2
    sleep 1
  done
  printf '\n' >&2
  _log "Rebooting"
  sync
  if have systemctl && [ "$INIT" = systemd ]; then systemctl reboot; else reboot; fi
}

# ----------------------------------------------------------------------------
# Plan display & final report
# ----------------------------------------------------------------------------
yes_no() { if [ "$1" = 1 ]; then printf '%s%s%s' "$C_G" "$(L yes 是)" "$C_0"; else printf '%s%s%s' "$C_DIM" "$(L no 否)" "$C_0"; fi; }

show_plan() {
  local rl ln
  card_open "$(L "Plan" "执行计划")"
  card_kv "$(L "SSH port" "SSH 端口")" "$CUR_PORTS $G_ARROW $C_BOLD$PORT$C_0"
  card_kv "$(L "Level" "加固等级")" "$C_BOLD$(level_name "$LEVEL")$C_0"
  card_kv "$(L "Login user" "登录用户")" "$TARGET_USER $C_DIM($(L "$TARGET_EXISTING_KEYS existing key(s), ${#TARGET_NEW_KEYS[@]} new" "已有 $TARGET_EXISTING_KEYS 把公钥，新增 ${#TARGET_NEW_KEYS[@]} 把"))$C_0"
  if [ -n "$NEW_USER" ]; then
    card_kv "$(L "New user" "新建用户")" "$NEW_USER $C_DIM(sudo: $NEW_USER_SUDO, $(L keys 公钥): $NEW_USER_KEYSRC)$C_0"
  fi
  case "$ROOT_LOGIN" in
    no) rl="$(L "disabled" "禁止")" ;;
    prohibit-password|without-password) rl="$(L "key only" "仅允许密钥")" ;;
    *) rl="$(L "unchanged" "不变") ($(eff permitrootlogin))" ;;
  esac
  card_kv "$(L "Root login" "root 登录")" "$rl"
  card_kv "$(L "Password login" "密码登录")" "$C_R$(L "will be disabled" "将被关闭")$C_0"
  [ -n "$ALLOW_USERS" ] && card_kv "AllowUsers" "$ALLOW_USERS"
  if [ "$DO_FIREWALL" = 1 ]; then card_kv "$(L "Firewall" "防火墙")" "$(L "open TCP $PORT in $FW" "在 $FW 中放行 TCP $PORT")"
  else card_kv "$(L "Firewall" "防火墙")" "$C_DIM$(L "no change" "不变")$C_0"; fi
  card_kv "fail2ban" "$(yes_no "$DO_FAIL2BAN")"
  card_kv "$(L "Auto-updates" "自动更新")" "$(yes_no "$DO_AUTOUPD")"
  card_kv "sysctl" "$(yes_no "$DO_SYSCTL")"
  card_kv "$(L "Login alerts" "登录提醒")" "$(yes_no "$DO_NOTIFY")"
  if [ "$CONFIRM_TIMEOUT" -gt 0 ] && [ "$ASSUME_YES" = 0 ]; then card_kv "$(L "Rollback timer" "回滚计时")" "${CONFIRM_TIMEOUT}s"
  else card_kv "$(L "Rollback timer" "回滚计时")" "$C_Y$(L off 关闭)$C_0"; fi
  card_line ""
  card_line "$C_DIM$(L "sshd settings" "sshd 配置") $G_ARROW $( [ "$USE_DROPIN" = 1 ] && echo "$SSHD_DROPIN_DIR/$DROPIN_NAME" || L "top of $SSHD_CFG" "$SSHD_CFG 顶部")$C_0"
  while IFS= read -r ln; do card_line "  $C_DIM$ln$C_0"; done < <(gen_config final | grep -v '^#')
  card_close "$(L "Nothing has been changed yet" "目前尚未做任何修改")"
}

final_report() {
  load_eff || true
  local s
  card_open "$C_G$(L "SSH hardening complete" "SSH 加固完成")$C_0  $C_DIM($(level_name "$LEVEL"))$C_0"
  card_kv "$(L "Port" "端口")" "$(trim "$(eff_all port | tr '\n' ' ')")"
  if [ "$(eff passwordauthentication)" = no ]; then card_kv "$(L "Password login" "密码登录")" "$C_G$(L disabled 已关闭)$C_0"
  else card_kv "$(L "Password login" "密码登录")" "$C_R$(eff passwordauthentication)$C_0"; fi
  case "$(eff permitrootlogin)" in
    no) card_kv "$(L "Root login" "root 登录")" "$C_G$(L disabled 禁止)$C_0" ;;
    without-password|prohibit-password) card_kv "$(L "Root login" "root 登录")" "$(L "key only" "仅允许密钥")" ;;
    *) card_kv "$(L "Root login" "root 登录")" "$(eff permitrootlogin)" ;;
  esac
  for s in ${SUMMARY[@]+"${SUMMARY[@]}"}; do card_line "$C_G$G_OK$C_0 $s"; done
  card_line ""
  card_kv "$(L "Connect" "连接命令")" "$C_BOLD ssh -p $PORT $(login_user)@$SERVER_IP $C_0"
  card_kv "$(L "Restore" "恢复")" "sudo sh $BACKUP_DIR/restore.sh"
  card_kv "$(L "Log" "日志")" "$LOG_FILE"
  card_close "$(L "Re-run this script any time for the menu: security score, keys, logins, alerts..." "随时重新运行本脚本即可进入菜单：安全评分、公钥、登录记录、登录提醒……")"
  if [ "$CONFIRMED_LOGIN" != 1 ]; then
    warn "Do NOT close this session until a new login on port $PORT has worked." "在确认新端口 $PORT 能登录之前，不要关闭当前会话。"
  fi
  hint "Client tip: with many keys in ssh-agent, use 'IdentitiesOnly yes' + IdentityFile in ~/.ssh/config (MaxAuthTries)." \
       "客户端提示：ssh-agent 中密钥较多时，请在 ~/.ssh/config 中使用 IdentitiesOnly yes + IdentityFile，避免超过 MaxAuthTries。"
}

# ----------------------------------------------------------------------------
# Wizard
# ----------------------------------------------------------------------------
run_wizard() {
  reset_wizard_state
  if [ -z "$TTY_FD" ] && [ "$ASSUME_YES" = 0 ]; then
    die "No terminal available for questions. Run interactively, or use --yes with --key/--key-file (see --help)." \
        "没有可交互的终端。请在终端中运行，或使用 --yes 配合 --key/--key-file（参见 --help）。"
  fi
  if ! sshd_test; then
    if printf '%s' "$SSHD_TEST_OUT" | grep -qi 'no hostkeys available'; then
      ssh-keygen -A >/dev/null 2>&1 && ok "Generated missing host keys." "已生成缺失的主机密钥。"
      sshd_test || die "Current sshd configuration is invalid: $SSHD_TEST_OUT" "当前 sshd 配置无效：$SSHD_TEST_OUT"
    else
      die "Current sshd configuration is invalid; fix it first: $SSHD_TEST_OUT" "当前 sshd 配置无效，请先修复：$SSHD_TEST_OUT"
    fi
  fi
  load_eff || die "Could not read the effective sshd configuration (sshd -T)." "无法读取 sshd 实际生效配置（sshd -T）。"
  refresh_cur_ports

  wstep 1 "SSH port" "SSH 端口"
  select_port

  wstep 2 "Login user & public keys" "登录用户与公钥"
  select_target_user
  load_eff || true   # re-evaluate with the target user (Match blocks)
  collect_target_keys
  check_authorized_keys_file
  check_account_usable "$TARGET_USER"

  wstep 3 "Hardening level" "加固等级"
  select_level

  wstep 4 "Accounts & root login" "账户与 root 登录"
  local need_admin=0
  if [ "$LEVEL" != basic ] && { [ "$TARGET_USER" = root ] || ! user_has_sudo "$TARGET_USER"; }; then need_admin=1; fi
  if [ -n "$OPT_NEW_USER" ] || [ "$ASSUME_YES" = 0 ]; then plan_new_user "$need_admin"; fi
  decide_root_login
  decide_allow_users
  case "$ROOT_LOGIN" in
    no) ok "Root SSH login: disabled" "root 登录：禁止" ;;
    prohibit-password|without-password) ok "Root SSH login: key only" "root 登录：仅允许密钥" ;;
    *) ok "Root SSH login: unchanged (passwords are disabled for everyone)" "root 登录：不变（所有用户的密码登录都会关闭）" ;;
  esac

  wstep 5 "Extra protection" "附加防护"
  select_modules

  wstep 6 "Review" "确认计划"
  show_plan
  if [ "$DRY_RUN" = 1 ]; then
    ok "Dry run: no changes were made." "试运行：未做任何修改。"
    return 0
  fi
  ask_yn "$(L "Apply these changes now?" "现在执行以上修改？")" y || { info "Cancelled. Nothing was changed." "已取消，未做任何修改。"; return 0; }

  section "Accounts & keys" "账户与公钥"
  TARGET_KEY_FILE="$(ensure_ssh_dir "$TARGET_USER")"
  append_keys "$TARGET_KEY_FILE" "$TARGET_USER" ${TARGET_NEW_KEYS[@]+"${TARGET_NEW_KEYS[@]}"}
  local u
  for u in ${ACCOUNT_UNLOCK_USERS[@]+"${ACCOUNT_UNLOCK_USERS[@]}"}; do unlock_account "$u"; done
  [ "${#TARGET_NEW_KEYS[@]}" -gt 0 ] || ok "Keeping existing keys for '$TARGET_USER'." "保留 '$TARGET_USER' 的现有公钥。"
  create_new_user

  section "Preparing" "准备工作"
  create_backup
  ROLLBACK_ARMED=1
  selinux_allow_port
  firewall_open_port || { ask_yn "$(L "Firewall could not be updated. Continue anyway?" "防火墙更新失败，仍然继续？")" n || die "Aborted." "已中止。"; }
  reserve_port
  prepare_host_keys

  local warm_ports
  # shellcheck disable=SC2086  # CUR_PORTS is a space separated list
  warm_ports="$(printf '%s\n' "$PORT" $CUR_PORTS | awk '!seen[$0]++' | tr '\n' ' ')"
  section "Stage 1/2: port $PORT alongside $CUR_PORTS" "阶段 1/2：新端口 $PORT 与原端口 $CUR_PORTS 同时监听"
  apply_stage warmup "$warm_ports" || die "Stage 1 failed; previous configuration will be restored." "阶段 1 失败，将恢复原配置。"

  section "Stage 2/2: '$LEVEL' hardening" "阶段 2/2：应用 $(level_name "$LEVEL") 加固"
  apply_stage final "$PORT" || die "Stage 2 failed; previous configuration will be restored." "阶段 2 失败，将恢复原配置。"
  warn_match_overrides
  if [ "$SELF_TEST" = 1 ]; then
    ssh_self_test || die "Self-test failed; previous configuration will be restored." "自测失败，将恢复原配置。"
  fi
  summary "sshd: port $PORT, level $LEVEL" "sshd：端口 $PORT，等级 $(level_name "$LEVEL")"

  confirm_new_login
  ROLLBACK_ARMED=0
  refresh_cur_ports

  # Optional modules (failures are reported, never fatal)
  if [ "$DO_AUTOUPD" = 1 ]; then setup_auto_updates || warn "Automatic updates were not configured." "未能配置自动更新。"; fi
  if [ "$DO_FAIL2BAN" = 1 ]; then setup_fail2ban "$PORT" || warn "fail2ban was not configured." "未能配置 fail2ban。"; fi
  if [ "$DO_SYSCTL" = 1 ]; then setup_sysctl || warn "sysctl hardening was not applied." "未能应用 sysctl 加固。"; fi
  if [ "$DO_NOTIFY" = 1 ]; then notify_configure || warn "Login alerts were not configured." "未能配置登录提醒。"; fi

  final_report
  reboot_prompt
}

# ----------------------------------------------------------------------------
# Security audit & score (read-only)
# ----------------------------------------------------------------------------
AUD_CAT=() AUD_ST=() AUD_W=() AUD_MSG=() AUD_FIX=()
SCORE=0 SCORE_GRADE=""

chk() { # chk CATEGORY STATUS WEIGHT "message" ["fix hint"]
  AUD_CAT+=("$1") AUD_ST+=("$2") AUD_W+=("$3") AUD_MSG+=("$4") AUD_FIX+=("${5:-}")
}

f2b_active() { have fail2ban-client && fail2ban-client status sshd >/dev/null 2>&1; }

auto_updates_state() {
  if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] && grep -q 'Unattended-Upgrade "1"' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; then echo "unattended-upgrades"
  elif [ "$INIT" = systemd ] && { systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1 || systemctl is-enabled dnf5-automatic.timer >/dev/null 2>&1 || systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1; }; then echo "dnf-automatic"
  elif [ "$INIT" = systemd ] && systemctl is-enabled ssh-hardening-security-patch.timer >/dev/null 2>&1; then echo "zypper patch timer"
  elif [ -f /etc/yum/yum-cron.conf ] && grep -q '^apply_updates *= *yes' /etc/yum/yum-cron.conf 2>/dev/null; then echo "yum-cron"
  fi
  return 0
}

notify_enabled() { [ -f "$NOTIFY_CONF" ] && [ -f "$PAM_SSHD" ] && grep -qF "$NOTIFY_BIN" "$PAM_SSHD" 2>/dev/null; }

sysval() { cat "/proc/sys/${1//.//}" 2>/dev/null || true; }

audit_collect() {
  AUD_CAT=() AUD_ST=() AUD_W=() AUD_MSG=() AUD_FIX=()
  local fixw fixf fixk fixu fixn v p weak
  fixw="$(L "menu 1: hardening wizard" "菜单 1：一键加固")"
  fixk="$(L "menu 3: key management" "菜单 3：公钥管理")"
  fixu="$(L "menu 4: user management" "菜单 4：用户管理")"
  fixf="$(L "menu 5: fail2ban" "菜单 5：fail2ban 管理")"
  fixn="$(L "menu 7: login alerts" "菜单 7：登录提醒")"

  if ! sshd_test; then chk ssh FAIL 10 "$(L "sshd configuration test fails" "sshd 配置检查未通过"): $SSHD_TEST_OUT"; fi
  load_eff || true
  if [ -n "$EFF" ]; then
    v="$(eff passwordauthentication)"
    if [ "$v" = no ]; then chk ssh PASS 20 "$(L "Password login disabled" "密码登录已关闭")"
    else chk ssh FAIL 20 "$(L "Password login is ENABLED (brute-force target)" "密码登录处于开启状态（易被暴力破解）")" "$fixw"; fi
    v="$(eff kbdinteractiveauthentication)"
    if [ -z "$v" ] || [ "$v" = no ]; then chk ssh PASS 5 "$(L "Keyboard-interactive login disabled" "键盘交互登录已关闭")"
    else chk ssh WARN 5 "$(L "Keyboard-interactive login enabled (PAM may still prompt for passwords)" "键盘交互登录开启（PAM 仍可能提示输入密码）")" "$fixw"; fi
    v="$(eff permitrootlogin)"
    case "$v" in
      no) chk ssh PASS 10 "$(L "Root login disabled" "root 登录已禁止")" ;;
      without-password|prohibit-password) chk ssh PASS 10 "$(L "Root login: keys only" "root 登录：仅允许密钥")" ;;
      forced-commands-only) chk ssh PASS 10 "$(L "Root login: forced commands only" "root 登录：仅限强制命令")" ;;
      *) chk ssh FAIL 10 "$(L "Root can log in with a password" "root 可以使用密码登录")" "$fixw" ;;
    esac
    v="$(eff permitemptypasswords)"
    if [ "$v" = yes ]; then chk ssh FAIL 5 "$(L "Empty passwords permitted" "允许空密码登录")" "$fixw"
    else chk ssh PASS 5 "$(L "Empty passwords rejected" "禁止空密码登录")"; fi
    p="$(trim "$(eff_all port | tr '\n' ' ')")"
    if in_list 22 "$p"; then chk ssh WARN 5 "$(L "SSH on default port 22 (constant scanning, noisy logs)" "SSH 使用默认端口 22（持续被扫描，日志噪音大）")" "$fixw"
    else chk ssh PASS 5 "$(L "SSH port" "SSH 端口") $p"; fi
    v="$(eff maxauthtries)"
    if [ "${v:-6}" -le 4 ]; then chk ssh PASS 3 "MaxAuthTries $v"
    else chk ssh WARN 3 "$(L "MaxAuthTries $v (recommended <= 4)" "MaxAuthTries 为 $v（建议 ≤ 4）")" "$fixw"; fi
    v="$(eff x11forwarding)"
    if [ "$v" = no ]; then chk ssh PASS 2 "$(L "X11 forwarding disabled" "X11 转发已关闭")"
    else chk ssh WARN 2 "$(L "X11 forwarding enabled" "X11 转发开启")" "$fixw"; fi
    v="$(eff loglevel)"
    case "$v" in VERBOSE|DEBUG*) chk ssh PASS 2 "$(L "LogLevel $v (key fingerprints are logged)" "LogLevel $v（会记录登录所用公钥指纹）")" ;;
      *) chk ssh WARN 2 "$(L "LogLevel $v (VERBOSE records which key logged in)" "LogLevel $v（VERBOSE 才会记录登录所用的公钥）")" "$fixw" ;; esac
    weak="$( { eff ciphers; eff macs; eff kexalgorithms; } | tr ',' '\n' | grep -E -- '-cbc$|^3des|arcfour|hmac-md5|hmac-sha1|umac-64|diffie-hellman-group1-|diffie-hellman-group14-sha1|group-exchange-sha1' | tr '\n' ' ' || true)"
    if [ -n "$weak" ]; then chk ssh WARN 5 "$(L "Legacy algorithms enabled: " "启用了过时算法：")$(trim "$weak")" "$fixw"
    else chk ssh PASS 5 "$(L "No legacy ciphers / MACs / KEX" "没有启用过时的加密/MAC/密钥交换算法")"; fi
  fi
  if [ -f "$SSH_DIR/ssh_host_dsa_key" ]; then chk ssh WARN 2 "$(L "DSA host key present" "存在 DSA 主机密钥")" "$(L "strict level disables it" "严格等级会将其禁用")"; fi
  local f hits=""
  while IFS= read -r f; do
    if awk '{ t=$0; sub(/^[ \t]+/, "", t); split(t, a, /[ \t=]+/); k=tolower(a[1]); v=tolower(a[2]) }
            k=="match" { m=1; next }
            m && t !~ /^#/ && k=="passwordauthentication" && v=="yes" { f=1 } END { exit !f }' "$f"; then hits="$hits $f"; fi
  done < <(config_files; [ -f "$SSHD_DROPIN_DIR/$DROPIN_NAME" ] && echo "$SSHD_DROPIN_DIR/$DROPIN_NAME")
  if [ -n "$hits" ]; then chk ssh WARN 5 "$(L "Match blocks re-enable password login:" "Match 块重新开启了密码登录：")$hits"; fi

  # Accounts
  local u home n weakk total=0 weakt=0 users_k=""
  while IFS= read -r u; do
    home="$(user_field "$u" 6)"
    [ -f "$home/.ssh/authorized_keys" ] || continue
    n=0; weakk=0
    while IFS= read -r v; do
      key_info "$v" || continue
      n=$((n + 1))
      key_is_weak && weakk=$((weakk + 1))
    done < <(key_lines_of "$home/.ssh/authorized_keys")
    [ "$n" -gt 0 ] || continue
    total=$((total + n)); weakt=$((weakt + weakk)); users_k="$users_k $u($n)"
  done < <(login_users)
  if [ "$total" -eq 0 ]; then chk acct WARN 5 "$(L "No SSH public keys installed for any login user" "所有登录用户都没有安装 SSH 公钥")" "$fixk"
  elif [ "$weakt" -gt 0 ]; then chk acct WARN 5 "$(L "$weakt weak key(s) (DSA / RSA < 3072) among $total:" "共 $total 把公钥，其中 $weakt 把较弱（DSA / RSA < 3072）：")$users_k" "$fixk"
  else chk acct PASS 5 "$(L "$total strong public key(s):" "共 $total 把公钥，强度合格：")$users_k"; fi
  local empty uid0
  empty="$(awk -F: '$2=="" {printf "%s ", $1}' /etc/shadow 2>/dev/null || true)"
  if [ -n "$empty" ]; then chk acct FAIL 5 "$(L "Accounts with an EMPTY password: " "存在空密码账户：")$empty" "passwd -l <user>"
  else chk acct PASS 5 "$(L "No accounts with empty passwords" "没有空密码账户")"; fi
  uid0="$(awk -F: '$3==0 && $1!="root" {printf "%s ", $1}' /etc/passwd)"
  if [ -n "$uid0" ]; then chk acct FAIL 5 "$(L "Extra UID 0 (root-equivalent) accounts: " "存在额外的 UID 0（等同 root）账户：")$uid0" "$fixu"
  else chk acct PASS 5 "$(L "Only root has UID 0" "只有 root 的 UID 为 0")"; fi
  local np
  np="$(grep -rhsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ' || true)"
  [ -n "$np" ] && chk acct INFO 0 "$(L "Passwordless sudo for: " "免密 sudo：")$np"

  # System
  case "$FW" in
    none) chk sys WARN 8 "$(L "No active host firewall (a cloud firewall may still apply)" "未启用主机防火墙（可能有云防火墙）")" "$(L "enable ufw / firewalld" "启用 ufw / firewalld")" ;;
    *) chk sys PASS 8 "$(L "Firewall active: " "防火墙已启用：")$FW" ;;
  esac
  if f2b_active; then chk sys PASS 5 "$(L "fail2ban protects sshd" "fail2ban 正在保护 sshd")"
  else chk sys WARN 5 "$(L "fail2ban not active" "fail2ban 未启用")" "$fixf"; fi
  v="$(auto_updates_state)"
  if [ -n "$v" ]; then chk sys PASS 8 "$(L "Automatic security updates: " "自动安全更新：")$v"
  else chk sys WARN 8 "$(L "Automatic security updates not configured" "未配置自动安全更新")" "$fixw"; fi
  if [ "$CONTAINER_KIND" = "" ]; then
    local bad_s=""
    [ "$(sysval net.ipv4.tcp_syncookies)" = 1 ] || bad_s="$bad_s tcp_syncookies"
    [ "$(sysval net.ipv4.conf.all.accept_redirects)" = 0 ] || bad_s="$bad_s accept_redirects"
    [ "$(sysval net.ipv4.conf.all.accept_source_route)" = 0 ] || bad_s="$bad_s accept_source_route"
    [ "$(sysval kernel.kptr_restrict)" -ge 1 ] 2>/dev/null || bad_s="$bad_s kptr_restrict"
    [ "$(sysval kernel.dmesg_restrict)" = 1 ] || bad_s="$bad_s dmesg_restrict"
    [ "$(sysval fs.protected_symlinks)" = 1 ] || bad_s="$bad_s protected_symlinks"
    if [ -z "$bad_s" ]; then chk sys PASS 5 "$(L "Kernel/network sysctl hardened" "内核/网络参数已加固")"
    else chk sys WARN 5 "$(L "sysctl not hardened:" "内核参数未加固：")$bad_s" "$fixw"; fi
    check_reboot_required
    if [ ${#REBOOT_REASONS[@]} -gt 0 ]; then chk sys WARN 4 "$(L "Reboot pending: " "待重启：")${REBOOT_REASONS[0]}" "sudo reboot"
    else chk sys PASS 4 "$(L "No pending reboot" "没有待生效的重启")"; fi
  fi
  if notify_enabled; then chk sys INFO 0 "$(L "Login alerts enabled" "登录提醒已启用")"
  else chk sys INFO 0 "$(L "Login alerts not configured" "未配置登录提醒")" "$fixn"; fi
  if have getenforce; then chk sys INFO 0 "SELinux: $(getenforce 2>/dev/null || echo unknown)"; fi

  local i got=0 max=0
  for i in "${!AUD_ST[@]}"; do
    max=$((max + AUD_W[i]))
    case "${AUD_ST[i]}" in PASS) got=$((got + AUD_W[i] * 2)) ;; WARN) got=$((got + AUD_W[i])) ;; esac
  done
  if [ "$max" -gt 0 ]; then SCORE=$(( got * 50 / max )); else SCORE=0; fi
  if [ "$SCORE" -ge 90 ]; then SCORE_GRADE="A"; elif [ "$SCORE" -ge 75 ]; then SCORE_GRADE="B"; elif [ "$SCORE" -ge 60 ]; then SCORE_GRADE="C"; else SCORE_GRADE="D"; fi
}

grade_text() {
  case "$SCORE_GRADE" in
    A) L "excellent" "优秀" ;; B) L "good" "良好" ;; C) L "fair" "一般" ;; *) L "at risk" "危险" ;;
  esac
}

run_audit() {
  audit_collect
  local cat title i
  for cat in ssh acct sys; do
    case "$cat" in
      ssh) title="$(L "SSH service (effective configuration)" "SSH 服务（实际生效配置）")" ;;
      acct) title="$(L "Accounts & keys" "账户与公钥")" ;;
      sys) title="$(L "System protection" "系统防护")" ;;
    esac
    section "$title"
    for i in "${!AUD_ST[@]}"; do
      [ "${AUD_CAT[i]}" = "$cat" ] || continue
      say "    $(badge "${AUD_ST[i]}") ${AUD_MSG[i]}"
    done
  done
  # Distinct fix hints, in order of first appearance
  local fixes="" fx
  for i in "${!AUD_ST[@]}"; do
    fx="${AUD_FIX[i]}"
    [ "${AUD_ST[i]}" != PASS ] && [ -n "$fx" ] || continue
    case "$fixes" in *"|$fx|"*) ;; *) fixes="$fixes|$fx|" ;; esac
  done
  say ""
  say "    $C_BOLD$(L "Security score" "安全评分")$C_0  $(bar "$SCORE" 24)  $C_BOLD$SCORE$C_0/100  $C_BOLD$SCORE_GRADE$C_0 $C_DIM($(grade_text))$C_0"
  if [ -n "$fixes" ]; then
    card_open "$(L "How to improve" "改进建议")"
    local IFS='|'
    for fx in $fixes; do [ -n "$fx" ] && card_line "$C_C$G_ARROW$C_0 $fx"; done
    card_close
  fi
}

# ----------------------------------------------------------------------------
# SSH key management
# ----------------------------------------------------------------------------
# Fingerprint of the key used by the current SSH session (needs LogLevel VERBOSE)
SESSION_FP=""
detect_session_fp() {
  SESSION_FP=""
  [ -n "$CLIENT_IP" ] && [ -n "$CLIENT_PORT" ] || return 0
  local line
  line="$(ssh_log_lines 3 | grep -F "from $CLIENT_IP port $CLIENT_PORT " | grep 'Accepted publickey for ' | tail -n1 || true)"
  SESSION_FP="$(printf '%s' "$line" | sed -n 's/.*\(SHA256:[A-Za-z0-9+/=]*\).*/\1/p')"
}

KEYLIST_LINES=()   # authorized_keys line numbers of the listed keys
show_keys() { # show_keys USER
  local user="$1" home file l n=0 idx=0 marks
  home="$(user_field "$user" 6)"
  file="$home/.ssh/authorized_keys"
  KEYLIST_LINES=()
  card_open "$(L "Public keys of " "公钥列表：")$C_BOLD$user$C_0  $C_DIM$file$C_0"
  if [ ! -s "$file" ]; then
    card_line "$C_DIM$(L "(no keys)" "（没有公钥）")$C_0"
    card_close
    return 0
  fi
  while IFS= read -r l || [ -n "$l" ]; do
    n=$((n + 1))
    l="$(trim "$l")"
    case "$l" in ""|\#*) continue ;; esac
    idx=$((idx + 1))
    KEYLIST_LINES+=("$n")
    if key_info "$l"; then
      marks=""
      key_is_weak && marks="$marks $C_Y$(L "[weak]" "[较弱]")$C_0"
      [ -n "$SESSION_FP" ] && [ "$KI_FP" = "$SESSION_FP" ] && marks="$marks $C_G$(L "[this session]" "[当前会话]")$C_0"
      case "$l" in "$KI_TYPE"*) ;; *) marks="$marks $C_M$(L "[options]" "[带选项]")$C_0" ;; esac
      card_line "$C_C$C_BOLD$(pad "$idx" 3)$C_0 $(pad "$(short_type)" 10) $(pad "${KI_BITS:-?}" 5) $C_DIM${KI_FP:-}$C_0  ${KI_COMMENT:-}$marks"
    else
      card_line "$C_C$C_BOLD$(pad "$idx" 3)$C_0 $C_R$(L "invalid line" "无效行")$C_0  ${l:0:50}"
    fi
  done <"$file"
  card_close "$(L "$idx entr(ies)" "共 $idx 条")"
}

usable_key_count() { # usable_key_count FILE
  local c=0 l
  while IFS= read -r l; do
    key_info "$l" || continue
    key_usable >/dev/null 2>&1 && c=$((c + 1))
  done < <(key_lines_of "$1")
  echo "$c"
}

backup_key_file() { # backup_key_file USER FILE
  local d="$STATE_DIR/keys-backup"
  mkdir -p "$d"; chmod 700 "$d"
  cp -p "$2" "$d/$1-authorized_keys-$(date +%Y%m%d-%H%M%S)"
}

keys_delete() { # keys_delete USER
  local user="$1" home file sel nums=() i lines="" n remain
  home="$(user_field "$user" 6)"
  file="$home/.ssh/authorized_keys"
  [ ${#KEYLIST_LINES[@]} -gt 0 ] || { info "No keys to delete." "没有可删除的公钥。"; return 0; }
  ask sel "$(L "Number(s) to delete (e.g. 2 or 1,3)" "要删除的序号（如 2 或 1,3）")" ""
  [ -n "$sel" ] || return 0
  for i in ${sel//,/ }; do
    [[ "$i" =~ ^[0-9]+$ ]] && [ "$i" -ge 1 ] && [ "$i" -le ${#KEYLIST_LINES[@]} ] || { warn "Invalid number: $i" "无效序号：$i"; return 1; }
    nums+=("${KEYLIST_LINES[$((i - 1))]}")
  done
  lines=" ${nums[*]} "
  # Safety: count usable keys that would remain
  remain=0
  n=0
  while IFS= read -r l || [ -n "$l" ]; do
    n=$((n + 1))
    case "$lines" in *" $n "*) continue ;; esac
    l="$(trim "$l")"
    case "$l" in ""|\#*) continue ;; esac
    if key_info "$l" && key_usable >/dev/null 2>&1; then remain=$((remain + 1)); fi
  done <"$file"
  for i in "${nums[@]}"; do
    l="$(sed -n "${i}p" "$file")"
    if key_info "$l" && [ -n "$SESSION_FP" ] && [ "$KI_FP" = "$SESSION_FP" ]; then
      warn "You are deleting the key used by THIS session." "你正在删除当前会话所使用的公钥。"
    fi
  done
  if [ "$remain" -eq 0 ] && [ "$(eff passwordauthentication)" = no ]; then
    warn "'$user' would have NO usable key left and password login is disabled: '$user' could not log in via SSH." \
         "删除后 '$user' 将没有任何可用公钥，而密码登录已关闭：'$user' 将无法通过 SSH 登录。"
    ask_yn "$(L "Delete anyway?" "仍然删除？")" n || return 0
  else
    ask_yn "$(L "Delete ${#nums[@]} key(s)?" "确认删除 ${#nums[@]} 把公钥？")" n || return 0
  fi
  backup_key_file "$user" "$file"
  new_tmp
  awk -v del="$lines" 'index(del, " " NR " ") == 0' "$file" >"$NEW_TMP"
  cat "$NEW_TMP" >"$file"
  ok "Deleted ${#nums[@]} key(s). Backup: $STATE_DIR/keys-backup/" "已删除 ${#nums[@]} 把公钥，备份位于 $STATE_DIR/keys-backup/"
}

keys_add() { # keys_add USER
  local user="$1" home file add=()
  home="$(user_field "$user" 6)"
  file="$home/.ssh/authorized_keys"
  read_keys_interactive add "$file"
  [ ${#add[@]} -gt 0 ] || { info "No keys added." "未添加公钥。"; return 0; }
  file="$(ensure_ssh_dir "$user")"
  [ -s "$file" ] && backup_key_file "$user" "$file"
  append_keys "$file" "$user" "${add[@]}"
}

keys_user_menu() { # keys_user_menu USER
  local user="$1" c
  while true; do
    show_keys "$user"
    menu_item a "Add keys (paste / gh:user)" "添加公钥（粘贴 / gh:用户名）"
    menu_item d "Delete keys" "删除公钥"
    menu_item 0 "Back" "返回"
    ask c "$(L "Choice" "请选择")" "0"
    case "$(lower "$c")" in
      a) keys_add "$user" || true ;;
      d) keys_delete "$user" || true ;;
      0|q|b|"") return 0 ;;
      *) warn "Unknown choice." "无效选项。" ;;
    esac
  done
}

pick_user() { # pick_user VAR "prompt" -> one of the login users (or any existing user)
  # locals are prefixed with __ so they never shadow the caller's result variable
  local __u __def="${SUDO_USER:-root}" __i=0 __names=() __pu __n __home
  while IFS= read -r __pu; do
    __names+=("$__pu")
    __i=$((__i + 1))
    __home="$(user_field "$__pu" 6)"
    __n="$(key_lines_of "$__home/.ssh/authorized_keys" | wc -l | tr -d ' ')"
    say "   $C_C$C_BOLD$(pad "$__i" 2)$C_0  $(pad "$__pu" 16) $C_DIM$(L "$__n key(s)" "$__n 把公钥")$( user_has_sudo "$__pu" && printf ' · sudo')$C_0"
  done < <(login_users)
  ask __u "$2" "$__def"
  if [[ "$__u" =~ ^[0-9]+$ ]] && [ "$__u" -ge 1 ] && [ "$__u" -le ${#__names[@]} ]; then __u="${__names[$((__u - 1))]}"; fi
  id "$__u" >/dev/null 2>&1 || { warn "User not found: $__u" "用户不存在：$__u"; return 1; }
  printf -v "$1" '%s' "$__u"
}

keys_menu() {
  local user
  section "SSH public keys" "SSH 公钥管理"
  detect_session_fp
  pick_user user "$(L "User (number or name)" "选择用户（序号或用户名）")" || return 0
  keys_user_menu "$user"
}

# ----------------------------------------------------------------------------
# User management
# ----------------------------------------------------------------------------
user_status() { # -> text: normal / disabled / locked / no password
  local u="$1" pw exp
  pw="$(shadow_pw "$u")"
  exp="$(awk -F: -v u="$u" '$1==u {print $8; exit}' /etc/shadow 2>/dev/null || true)"
  if [ -n "$exp" ] && [ "$exp" -le "$(( $(date +%s) / 86400 ))" ] 2>/dev/null; then L "disabled" "已禁用"; return; fi
  case "$pw" in
    '!'*'$'*) L "password locked" "密码已锁定" ;;
    '!'|'!!'|'*'|'!*'|'') L "no password" "无密码" ;;
    *) L "password set" "已设密码" ;;
  esac
}

show_users() {
  local u uid home n s
  card_open "$(L "Login-capable users" "可登录用户")"
  card_line "$C_DIM$(pad "$(L user 用户)" 16) $(pad UID 6) $(pad sudo 5) $(pad "$(L keys 公钥)" 6) $(L status 状态)$C_0"
  while IFS= read -r u; do
    uid="$(id -u "$u")"
    home="$(user_field "$u" 6)"
    n="$(key_lines_of "$home/.ssh/authorized_keys" | wc -l | tr -d ' ')"
    s="$(user_status "$u")"
    card_line "$(pad "$u" 16) $(pad "$uid" 6) $(pad "$(user_has_sudo "$u" && L yes 是 || L no 否)" 5) $(pad "$n" 6) $s"
  done < <(login_users)
  card_close
}

guard_self() { # refuse to act on root or on the user running this session
  if [ "$1" = root ] || [ "$1" = "${SUDO_USER:-}" ]; then
    warn "Refusing to change '$1': it is root or the account you are using." "拒绝修改 '$1'：它是 root 或你当前正在使用的账户。"
    return 1
  fi
}

users_menu() {
  local c u mode ukeys=() l
  while true; do
    section "User management" "用户管理"
    show_users
    menu_item 1 "Create sudo user" "新建 sudo 用户"
    menu_item 2 "Grant sudo" "授予 sudo"
    menu_item 3 "Revoke sudo (granted by this tool)" "撤销 sudo（本工具授予的）"
    menu_item 4 "Disable account (blocks all logins)" "禁用账户（禁止所有登录）"
    menu_item 5 "Enable account" "启用账户"
    menu_item 6 "Set password (for sudo / console)" "设置密码（用于 sudo / 控制台）"
    menu_item 0 "Back" "返回"
    ask c "$(L "Choice" "请选择")" "0"
    case "$c" in
      1)
        ask_new_username u || continue
        ask_sudo_mode mode "$u"
        ukeys=()
        say "  $(L "SSH keys for '$u' (empty line = copy from ${SUDO_USER:-root}):" "'$u' 的 SSH 公钥（直接空行 = 复制 ${SUDO_USER:-root} 的公钥）：")"
        read_keys_interactive ukeys ""
        if [ ${#ukeys[@]} -eq 0 ]; then
          while IFS= read -r l; do ukeys+=("$l"); done < <(key_lines_of "$(user_field "${SUDO_USER:-root}" 6)/.ssh/authorized_keys")
        fi
        create_user_account "$u" "$mode" ${ukeys[@]+"${ukeys[@]}"}
        if [ -n "$(eff_all allowusers | tr -d '[:space:]')" ]; then
          warn "AllowUsers is active: add '$u' via the hardening wizard or sshd_config to allow SSH login." \
               "已启用 AllowUsers：需通过加固向导或 sshd_config 把 '$u' 加入白名单才能 SSH 登录。"
        fi ;;
      2)
        pick_user u "$(L "User" "选择用户")" || continue
        [ "$u" != root ] || continue
        ask_sudo_mode mode "$u"
        [ "$mode" = none ] || grant_sudo "$u" "$mode" || true ;;
      3)
        pick_user u "$(L "User" "选择用户")" || continue
        guard_self "$u" || continue
        if [ -f "$(sudoers_file "$u")" ]; then
          rm -f "$(sudoers_file "$u")"; ok "Revoked sudo granted by this tool for '$u'." "已撤销本工具授予 '$u' 的 sudo 权限。"
        else
          info "No sudoers entry created by this tool for '$u'." "本工具没有为 '$u' 创建过 sudo 规则。"
        fi
        user_has_sudo "$u" && hint "'$u' still has sudo via group membership ($(id -nG "$u")); remove with: gpasswd -d $u <group>" \
                                   "'$u' 仍通过用户组（$(id -nG "$u")）拥有 sudo，可执行：gpasswd -d $u <组名>" ;;
      4)
        pick_user u "$(L "User" "选择用户")" || continue
        guard_self "$u" || continue
        ask_yn "$(L "Disable '$u'? All logins (SSH keys included) will be refused." "禁用 '$u'？所有登录方式（包括 SSH 公钥）都将被拒绝。")" n || continue
        if usermod -e 1 "$u" 2>/dev/null || chage -E 0 "$u" 2>/dev/null; then ok "Disabled '$u'." "已禁用 '$u'。"
        else warn "usermod/chage not available (install the shadow package)." "缺少 usermod/chage（请安装 shadow 软件包）。"; fi ;;
      5)
        pick_user u "$(L "User" "选择用户")" || continue
        if usermod -e '' "$u" 2>/dev/null || chage -E -1 "$u" 2>/dev/null; then ok "Enabled '$u'." "已启用 '$u'。"
        else warn "usermod/chage not available (install the shadow package)." "缺少 usermod/chage（请安装 shadow 软件包）。"; fi ;;
      6)
        pick_user u "$(L "User" "选择用户")" || continue
        passwd "$u" <&"$TTY_FD" || warn "Password not changed." "密码未修改。" ;;
      0|q|"") return 0 ;;
      *) warn "Unknown choice." "无效选项。" ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Login history
# ----------------------------------------------------------------------------
# ssh_log_lines DAYS -> sshd log lines of the last DAYS days (journal or syslog files)
ssh_log_lines() {
  local days="${1:-7}" f
  if have journalctl && [ "$INIT" = systemd ]; then
    journalctl --no-pager -q -o short-iso --since "-${days}d" _COMM=sshd _COMM=sshd-session 2>/dev/null && return 0
  fi
  for f in /var/log/auth.log /var/log/secure /var/log/messages; do
    if [ -r "$f" ]; then grep -hE 'sshd(-session)?\[' "$f" "$f.1" 2>/dev/null || true; return 0; fi
  done
  return 0
}

fp_comment_map() { # prints "FINGERPRINT user:comment" for every installed key
  local u home
  have ssh-keygen || return 0
  while IFS= read -r u; do
    home="$(user_field "$u" 6)"
    [ -s "$home/.ssh/authorized_keys" ] || continue
    ssh-keygen -l -f "$home/.ssh/authorized_keys" 2>/dev/null | awk -v u="$u" '{ c=""; for (i=3; i<NF; i++) c = c (c=="" ? "" : " ") $i; print $2, (c=="" ? "-" : c) }'
  done < <(login_users)
  return 0
}

logins_report() {
  local days=7 logs map line ts user ip method fp label count=0
  section "Login history (last $days days)" "登录记录（最近 $days 天）"
  logs="$(ssh_log_lines "$days")"
  if [ -z "$logs" ]; then
    warn "No sshd log found (journal or /var/log/auth.log|secure|messages)." "未找到 sshd 日志（journal 或 /var/log/auth.log|secure|messages）。"
    return 0
  fi
  map="$(fp_comment_map)"
  card_open "$(L "Successful logins (latest 15)" "成功登录（最近 15 次）")"
  card_line "$C_DIM$(pad "$(L time 时间)" 20) $(pad "$(L user 用户)" 12) $(pad "$(L from 来源)" 17) $(pad "$(L method 方式)" 10) $(L key 公钥)$C_0"
  while IFS= read -r line; do
    ts="$(printf '%s' "$line" | awk '{print $1}' | cut -c1-19 | tr 'T' ' ')"
    case "$ts" in [0-9][0-9][0-9][0-9]-*) ;; *) ts="$(printf '%s' "$line" | awk '{print $1, $2, $3}')" ;; esac
    user="$(printf '%s' "$line" | sed -n 's/.*Accepted [^ ]* for \([^ ]*\) from.*/\1/p')"
    ip="$(printf '%s' "$line" | sed -n 's/.* from \([^ ]*\) port.*/\1/p')"
    method="$(printf '%s' "$line" | sed -n 's/.*Accepted \([^ ]*\) for.*/\1/p')"
    fp="$(printf '%s' "$line" | sed -n 's/.*\(SHA256:[A-Za-z0-9+/=]*\).*/\1/p')"
    label=""
    if [ -n "$fp" ]; then
      label="$(awk -v f="$fp" '$1==f { $1=""; sub(/^ /, ""); print; exit }' <<<"$map")"
      [ -n "$label" ] || label="${fp:0:20}…"
    fi
    case "$method" in password|keyboard-interactive*) method="$C_Y$method$C_0" ;; esac
    card_line "$(pad "$ts" 20) $(pad "$user" 12) $(pad "$ip" 17) $(pad "$method" 10) $C_DIM$label$C_0"
    count=$((count + 1))
  done < <(printf '%s\n' "$logs" | grep -E 'Accepted [a-z/-]+ for ' | tail -n 15)
  [ "$count" -gt 0 ] || card_line "$C_DIM$(L "(none)" "（无）")$C_0"
  card_close

  local fails total
  fails="$(printf '%s\n' "$logs" | grep -E 'Failed (password|publickey|none)|Invalid user|authenticating user .* \[preauth\]|maximum authentication attempts|Did not receive identification|banner exchange' \
    | sed -nE 's/.* from ([0-9a-fA-F:.]+).*/\1/p; t; s/.*(invalid|authenticating) user [^ ]+ ([0-9a-fA-F:.]+) port.*/\2/p' || true)"
  total="$(printf '%s' "$fails" | grep -c . || true)"
  card_open "$(L "Failed / rejected attempts: " "失败/被拒绝的尝试：")$C_BOLD$total$C_0"
  if [ "$total" -gt 0 ]; then
    card_line "$C_DIM$(pad "$(L attempts 次数)" 8) $(L "source IP" "来源 IP")$C_0"
    while read -r count ip; do
      card_line "$(pad "$count" 8) $ip"
    done < <(printf '%s\n' "$fails" | sort | uniq -c | sort -rn | head -n 10)
  else
    card_line "$C_DIM$(L "(none)" "（无）")$C_0"
  fi
  if [ "$total" -gt 0 ] && ! f2b_active; then card_close "$(L "Tip: enable fail2ban (menu 5) to ban these sources automatically" "提示：启用 fail2ban（菜单 5）可自动封禁这些来源")"
  else card_close; fi

  if have who; then
    card_open "$(L "Currently logged in" "当前在线")"
    while IFS= read -r line; do card_line "$line"; done < <(who 2>/dev/null)
    card_close
  fi
}

# ----------------------------------------------------------------------------
# fail2ban management
# ----------------------------------------------------------------------------
f2b_status_show() {
  local st cur tot banned_n banned
  st="$(fail2ban-client status sshd 2>/dev/null || true)"
  cur="$(printf '%s\n' "$st" | sed -n 's/.*Currently failed:[[:space:]]*//p')"
  tot="$(printf '%s\n' "$st" | sed -n 's/.*Total failed:[[:space:]]*//p')"
  banned_n="$(printf '%s\n' "$st" | sed -n 's/.*Currently banned:[[:space:]]*//p')"
  banned="$(printf '%s\n' "$st" | sed -n 's/.*Banned IP list:[[:space:]]*//p')"
  card_open "$(L "fail2ban · sshd jail" "fail2ban · sshd 监狱")"
  card_kv "$(L "Failing now" "当前失败数")" "${cur:-0}"
  card_kv "$(L "Total failed" "累计失败")" "${tot:-0}"
  card_kv "$(L "Banned now" "当前封禁")" "$C_BOLD${banned_n:-0}$C_0"
  if [ -n "$(trim "$banned")" ]; then
    local ip
    for ip in $banned; do card_line "  $C_R$G_BULLET$C_0 $ip"; done
  fi
  [ -f "$F2B_JAIL_FILE" ] && card_kv "$(L "Config" "配置文件")" "$F2B_JAIL_FILE"
  card_close
}

f2b_menu() {
  local c ip
  section "fail2ban"
  if ! f2b_active; then
    warn "fail2ban is not protecting sshd." "fail2ban 当前没有保护 sshd。"
    if [ "$CONTAINER_KIND" = app ]; then hint "Not available inside a $VIRT container." "在 $VIRT 容器中不可用。"; return 0; fi
    if ask_yn "$(L "Install and enable fail2ban for SSH port ${CUR_PORTS%% *} now?" "现在为 SSH 端口 ${CUR_PORTS%% *} 安装并启用 fail2ban？")" y; then
      setup_fail2ban "${CUR_PORTS%% *}" || true
    fi
    f2b_active || return 0
  fi
  while true; do
    f2b_status_show
    menu_item 1 "Unban an IP" "解封 IP"
    menu_item 2 "Ban an IP" "封禁 IP"
    menu_item 3 "Unban all" "全部解封"
    menu_item 0 "Back" "返回"
    ask c "$(L "Choice" "请选择")" "0"
    case "$c" in
      1) ask ip "IP" ""; valid_ip "$ip" || { warn "Invalid IP." "IP 格式无效。"; continue; }
         fail2ban-client set sshd unbanip "$ip" >/dev/null 2>&1 && ok "Unbanned $ip" "已解封 $ip" || warn "$ip is not banned." "$ip 未被封禁。" ;;
      2) ask ip "IP" ""; valid_ip "$ip" || { warn "Invalid IP." "IP 格式无效。"; continue; }
         if [ "$ip" = "$CLIENT_IP" ]; then warn "That is your own IP ($CLIENT_IP); refusing." "这是你自己的 IP（$CLIENT_IP），已拒绝。"; continue; fi
         fail2ban-client set sshd banip "$ip" >/dev/null 2>&1 && ok "Banned $ip" "已封禁 $ip" || warn "Could not ban $ip." "无法封禁 $ip。" ;;
      3) ask_yn "$(L "Unban all IPs in the sshd jail?" "解封 sshd 监狱中的所有 IP？")" n || continue
         fail2ban-client set sshd unbanip --all >/dev/null 2>&1 || fail2ban-client unban --all >/dev/null 2>&1 || true
         ok "All IPs unbanned." "已全部解封。" ;;
      0|q|"") return 0 ;;
      *) warn "Unknown choice." "无效选项。" ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Login alerts (PAM session hook -> Telegram / WeCom / DingTalk / Feishu / webhook)
# ----------------------------------------------------------------------------
notify_type_name() {
  case "$1" in
    telegram) echo Telegram ;; wecom) L "WeCom bot" "企业微信机器人" ;; dingtalk) L "DingTalk bot" "钉钉机器人" ;;
    feishu) L "Feishu / Lark bot" "飞书机器人" ;; webhook) L "Generic webhook" "自定义 Webhook" ;; *) echo "$1" ;;
  esac
}

write_notify_script() {
  mkdir -p "$(dirname "$NOTIFY_BIN")"
  cat >"$NOTIFY_BIN" <<'EOF'
#!/bin/sh
# Installed by ssh-hardening: sends a message for every SSH login (called by pam_exec).
# Config: /etc/ssh-hardening/notify.conf      Test: ssh-hardening-notify test
CONF=/etc/ssh-hardening/notify.conf
[ "${PAM_TYPE:-}" = open_session ] || [ "${1:-}" = test ] || exit 0
[ -r "$CONF" ] || exit 0
TYPE="" URL="" TG_TOKEN="" TG_CHAT="" MSG_LANG=en
. "$CONF"
clean() { printf '%s' "$1" | tr -cd 'A-Za-z0-9._:@%-' | cut -c1-64; }
U=$(clean "${PAM_USER:-${USER:-root}}")
R=$(clean "${PAM_RHOST:-local}")
H=$(clean "$(hostname 2>/dev/null)")
T=$(date '+%Y-%m-%d %H:%M:%S %Z')
if [ "${1:-}" = test ]; then U="test"; R="test"; fi
if [ "$MSG_LANG" = zh ]; then
  MSG="[SSH 登录提醒] 用户 $U 登录了 $H，来源 $R，时间 $T"
else
  MSG="[SSH login] user $U logged in to $H from $R at $T"
fi
case "$TYPE" in
  telegram) URL="https://api.telegram.org/bot$TG_TOKEN/sendMessage"; DATA="{\"chat_id\":\"$TG_CHAT\",\"text\":\"$MSG\"}" ;;
  wecom|dingtalk) DATA="{\"msgtype\":\"text\",\"text\":{\"content\":\"$MSG\"}}" ;;
  feishu) DATA="{\"msg_type\":\"text\",\"content\":{\"text\":\"$MSG\"}}" ;;
  *) DATA="{\"text\":\"$MSG\",\"user\":\"$U\",\"host\":\"$H\",\"from\":\"$R\"}" ;;
esac
send() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 10 -H 'Content-Type: application/json' -d "$DATA" "$URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 10 -O- --header='Content-Type: application/json' --post-data="$DATA" "$URL"
  else
    return 1
  fi
}
if [ "${1:-}" = test ]; then send; exit $?; fi
# Never delay or break the login: send in the background
( send >/dev/null 2>&1 & ) </dev/null >/dev/null 2>&1
exit 0
EOF
  chmod 755 "$NOTIFY_BIN"
}

pam_notify_enable() {
  [ -f "$PAM_SSHD" ] || { warn "$PAM_SSHD not found." "找不到 $PAM_SSHD。"; return 1; }
  if ! grep -qF "$NOTIFY_BIN" "$PAM_SSHD"; then
    cp -p "$PAM_SSHD" "$STATE_DIR/pam.d-sshd.bak" 2>/dev/null || true
    printf '\n# ssh-hardening login alert (optional: never blocks a login)\n%s\n' "$PAM_NOTIFY_LINE" >>"$PAM_SSHD"
  fi
}

pam_notify_disable() {
  [ -f "$PAM_SSHD" ] || return 0
  new_tmp
  grep -vF -e "$NOTIFY_BIN" -e "# ssh-hardening login alert" "$PAM_SSHD" >"$NEW_TMP" || true
  cat "$NEW_TMP" >"$PAM_SSHD"
}

notify_configure() {
  local c type="" url="" token="" chat="" url_re='^https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+$'
  section "Login alerts" "登录提醒"
  if [ "$(eff usepam)" != yes ]; then
    warn "sshd runs without PAM (UsePAM no); login alerts need PAM." "sshd 未启用 PAM（UsePAM no），登录提醒需要 PAM。"
    [ "$FAMILY" = alpine ] && hint "Alpine: apk add openssh-server-pam and set 'UsePAM yes'." "Alpine：apk add openssh-server-pam 并设置 'UsePAM yes'。"
    return 1
  fi
  if ! have curl && ! have wget; then pkg_install curl || return 1; fi
  menu_item 1 "Telegram bot" "Telegram 机器人"
  menu_item 2 "WeCom bot" "企业微信机器人"
  menu_item 3 "DingTalk bot" "钉钉机器人" "$(L "(add keyword: SSH)" "（安全设置请添加关键词：SSH）")"
  menu_item 4 "Feishu / Lark bot" "飞书机器人"
  menu_item 5 "Generic webhook (JSON POST)" "自定义 Webhook（JSON POST）"
  ask c "$(L "Channel" "推送渠道") [1-5]" "1"
  case "$c" in
    1) type=telegram
       ask token "$(L "Bot token (from @BotFather)" "Bot Token（从 @BotFather 获取）")" ""
       [[ "$token" =~ ^[0-9]+:[A-Za-z0-9_-]+$ ]] || { warn "Invalid bot token." "Bot Token 格式无效。"; return 1; }
       ask chat "$(L "Chat ID (e.g. 123456789 or -100…)" "Chat ID（如 123456789 或 -100…）")" ""
       [[ "$chat" =~ ^-?[0-9]+$|^@[A-Za-z0-9_]{5,}$ ]] || { warn "Invalid chat ID." "Chat ID 格式无效。"; return 1; } ;;
    2|3|4|5)
       case "$c" in 2) type=wecom ;; 3) type=dingtalk ;; 4) type=feishu ;; 5) type=webhook ;; esac
       ask url "$(L "Webhook URL" "Webhook 地址")" ""
       [[ "$url" =~ $url_re ]] || { warn "Invalid URL." "URL 格式无效。"; return 1; } ;;
    *) warn "Unknown choice." "无效选项。"; return 1 ;;
  esac
  mkdir -p "$NOTIFY_DIR"; chmod 700 "$NOTIFY_DIR"
  {
    echo "# ssh-hardening login alerts — $(notify_type_name "$type")"
    echo "TYPE='$type'"
    echo "URL='$url'"
    echo "TG_TOKEN='$token'"
    echo "TG_CHAT='$chat'"
    echo "MSG_LANG='$UI_LANG'"
  } >"$NOTIFY_CONF"
  chmod 600 "$NOTIFY_CONF"
  write_notify_script
  if spin "Sending a test message" "发送测试消息" -- "$NOTIFY_BIN" test; then
    pam_notify_enable || return 1
    ok "Login alerts enabled ($(notify_type_name "$type")). Every SSH login now sends a message." \
       "登录提醒已启用（$(notify_type_name "$type")），之后每次 SSH 登录都会推送消息。"
    summary "Login alerts: $(notify_type_name "$type")" "登录提醒：$(notify_type_name "$type")"
  else
    warn "The test message failed; alerts were NOT enabled. Check the token/URL and network access." \
         "测试消息发送失败，未启用提醒。请检查 Token/地址以及服务器能否访问该服务。"
    [ "$type" = telegram ] && hint "Servers in mainland China usually cannot reach api.telegram.org." "中国大陆服务器通常无法访问 api.telegram.org。"
    return 1
  fi
}

notify_menu() {
  local c type
  while true; do
    section "Login alerts" "登录提醒"
    card_open "$(L "Status" "状态")"
    if notify_enabled; then
      type="$(sed -n "s/^TYPE='\(.*\)'$/\1/p" "$NOTIFY_CONF")"
      card_kv "$(L "Alerts" "提醒")" "$C_G$(L enabled 已启用)$C_0 · $(notify_type_name "$type")"
    else
      card_kv "$(L "Alerts" "提醒")" "$C_DIM$(L "not configured" "未配置")$C_0"
    fi
    card_kv "$(L "Mechanism" "实现方式")" "pam_exec ($PAM_SSHD)"
    card_close
    menu_item 1 "Configure / change channel" "配置 / 更换推送渠道"
    menu_item 2 "Send a test message" "发送测试消息"
    menu_item 3 "Disable alerts" "关闭提醒"
    menu_item 0 "Back" "返回"
    ask c "$(L "Choice" "请选择")" "0"
    case "$c" in
      1) notify_configure || true ;;
      2) if [ -x "$NOTIFY_BIN" ] && [ -f "$NOTIFY_CONF" ]; then spin "Sending a test message" "发送测试消息" -- "$NOTIFY_BIN" test || true
         else warn "Not configured yet." "尚未配置。"; fi ;;
      3) pam_notify_disable; rm -f "$NOTIFY_CONF"; ok "Login alerts disabled." "登录提醒已关闭。" ;;
      0|q|"") return 0 ;;
      *) warn "Unknown choice." "无效选项。" ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Backups
# ----------------------------------------------------------------------------
backups_menu() {
  local c dirs=() d i=0 st
  while true; do
    section "Backups" "备份与恢复"
    dirs=()
    while IFS= read -r d; do [ -n "$d" ] && dirs+=("$d"); done < <(list_backups)
    if [ ${#dirs[@]} -eq 0 ]; then info "No backups yet (one is created every time the wizard applies changes)." "暂无备份（每次通过向导应用修改都会自动创建）。"; return 0; fi
    card_open "$(L "Backups in" "备份目录") $STATE_DIR"
    card_line "$C_DIM$(pad "#" 4) $(pad "$(L created 创建时间)" 20) $(pad "$(L ports 端口)" 16) $(pad "$(L level 等级)" 10) $(L state 状态)$C_0"
    i=0
    for d in "${dirs[@]}"; do
      i=$((i + 1))
      st=""
      [ -f "$d/restored" ] && st="$C_Y$(L restored 已恢复)$C_0"
      card_line "$C_C$C_BOLD$(pad "$i" 4)$C_0 $(pad "$(meta_get "$d" date)" 20) $(pad "$(meta_get "$d" old_ports) $G_ARROW $(meta_get "$d" new_port)" 16) $(pad "$(meta_get "$d" level)" 10) $st"
    done
    card_close "$(L "Restoring returns SSH to the state BEFORE that run" "恢复会把 SSH 配置还原到该次运行之前的状态")"
    menu_item r "Restore a backup" "恢复某个备份"
    menu_item c "Clean up (keep the original + newest 5)" "清理旧备份（保留最初的原始备份 + 最近 5 个）"
    menu_item 0 "Back" "返回"
    ask c "$(L "Choice" "请选择")" "0"
    case "$(lower "$c")" in
      r) ask i "$(L "Backup number" "备份序号")" "${#dirs[@]}"
         if [[ "$i" =~ ^[0-9]+$ ]] && [ "$i" -ge 1 ] && [ "$i" -le ${#dirs[@]} ]; then restore_backup_dir "${dirs[$((i - 1))]}" || true
         else warn "Invalid number." "无效序号。"; fi ;;
      c) # The first backup is the pre-hardening original: never delete it
         if [ ${#dirs[@]} -le 6 ]; then info "Nothing to clean." "无需清理。"
         elif ask_yn "$(L "Delete $(( ${#dirs[@]} - 6 )) old backup(s)? The original backup is kept." "删除 $(( ${#dirs[@]} - 6 )) 个旧备份？最初的原始备份会保留。")" n; then
           for d in "${dirs[@]:1:$(( ${#dirs[@]} - 6 ))}"; do rm -rf "$d"; done
           ok "Old backups removed." "已删除旧备份。"
         fi ;;
      0|q|"") return 0 ;;
      *) warn "Unknown choice." "无效选项。" ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Main menu
# ----------------------------------------------------------------------------
# No right-hand border: box-drawing characters are "ambiguous width" and many CJK
# terminals (Xshell, FinalShell, iTerm2 option) draw them double-wide.
banner() {
  printf '\n  %s%s%s %sSSH Hardening Toolkit%s %sv%s%s\n' "$C_C$C_BOLD" "$B_V" "$C_0" "$C_BOLD" "$C_0" "$C_DIM" "$SCRIPT_VERSION" "$C_0" >&2
  printf '  %s%s%s %s%s%s\n' "$C_C$C_BOLD" "$B_V" "$C_0" "$C_DIM" "$(L "SSH & server security for VPS / dedicated servers" "VPS / 独立服务器 SSH 与安全加固")" "$C_0" >&2
  printf '  %s%s%s\n' "$C_C" "$(rep "$B_H" 36)" "$C_0" >&2
}

status_panel() {
  local pw rl au virt
  load_eff || true
  refresh_cur_ports
  detect_firewall
  audit_collect
  pw="$(eff passwordauthentication)"
  case "$(eff permitrootlogin)" in
    no) rl="$C_G$(L disabled 禁止)$C_0" ;;
    without-password|prohibit-password) rl="$(L "key only" "仅密钥")" ;;
    *) rl="$C_R$(L "password allowed" "允许密码")$C_0" ;;
  esac
  au="$(auto_updates_state)"
  virt="$VIRT"; [ "$virt" = none ] && virt="$(L "bare metal / unknown" "物理机/未知")"
  kv "$(L "System" "系统")" "$OS_NAME $C_DIM· $virt · $INIT$C_0"
  kv "SSH" "OpenSSH $SSH_VER $C_DIM·$C_0 $(L port 端口) $C_BOLD$CUR_PORTS$C_0 $C_DIM·$C_0 $(L "password login" "密码登录") $( [ "$pw" = no ] && printf '%s%s%s' "$C_G" "$(L off 关闭)" "$C_0" || printf '%s%s%s' "$C_R" "$(L ON 开启)" "$C_0") $C_DIM·$C_0 root $rl"
  kv "$(L "Protection" "防护")" "$(L firewall 防火墙) $( [ "$FW" = none ] && printf '%s%s%s' "$C_Y" "$(L none 无)" "$C_0" || printf '%s' "$FW") $C_DIM·$C_0 fail2ban $(f2b_active && onoff 1 || onoff 0) $C_DIM·$C_0 $(L updates 自动更新) $( [ -n "$au" ] && onoff 1 || onoff 0) $C_DIM·$C_0 $(L alerts 登录提醒) $(notify_enabled && onoff 1 || onoff 0)"
  kv "$(L "Score" "安全评分")" "$(bar "$SCORE" 20) $C_BOLD$SCORE$C_0/100 $C_BOLD$SCORE_GRADE$C_0 $C_DIM($(grade_text))$C_0"
}

main_menu() {
  local c
  while true; do
    clear_screen
    banner
    status_panel
    say ""
    menu_item 1 "Hardening wizard" "一键加固向导" "$(L "port, keys, level, fail2ban, updates" "端口 / 公钥 / 等级 / fail2ban / 自动更新")"
    menu_item 2 "Security check & score" "安全体检与评分" "$(L "read-only report with fixes" "只读报告与修复建议")"
    menu_item 3 "SSH public keys" "SSH 公钥管理" "$(L "list / add / delete" "列出 / 添加 / 删除")"
    menu_item 4 "Users" "用户管理" "$(L "sudo users, disable / enable" "sudo 用户、禁用 / 启用")"
    menu_item 5 "fail2ban" "fail2ban 管理" "$(L "status, banned IPs, unban" "状态、封禁列表、解封")"
    menu_item 6 "Login history" "登录记录" "$(L "who logged in with which key, failed sources" "谁用哪把公钥登录、失败来源")"
    menu_item 7 "Login alerts" "登录提醒" "Telegram / $(L "WeCom / DingTalk / Feishu" "企业微信 / 钉钉 / 飞书")"
    menu_item 8 "Backups & restore" "备份与恢复"
    menu_item 9 "Language: English / 中文" "切换语言：中文 / English"
    menu_item 0 "Exit" "退出"
    say ""
    ask c "$(L "Choice" "请选择")" ""
    case "$c" in
      "") ;;
      1) run_wizard; pause ;;
      2) run_audit; pause ;;
      3) keys_menu || true ;;
      4) users_menu || true ;;
      5) f2b_menu || true ;;
      6) logins_report; pause ;;
      7) notify_menu || true ;;
      8) backups_menu || true ;;
      9) if [ "$UI_LANG" = zh ]; then UI_LANG=en; else UI_LANG=zh; fi
         echo "$UI_LANG" >"$STATE_DIR/lang" ;;
      0|q|exit) return 0 ;;
      *) warn "Unknown choice." "无效选项。"; sleep 1 ;;
    esac
  done
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
  parse_args "$@"
  ui_init
  if [ "$MODE" = help ]; then ui_lang_init; usage; exit 0; fi
  [ "$(uname -s)" = Linux ] || die "This script supports Linux only." "本脚本仅支持 Linux。"
  [ "${EUID:-$(id -u)}" -eq 0 ] || die "Please run as root (e.g. sudo bash main.sh)." "请以 root 身份运行（例如 sudo bash main.sh）。"

  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  ui_lang_init
  touch "$LOG_FILE" && chmod 600 "$LOG_FILE" && LOG_READY=1
  _log "---- ssh-hardening v$SCRIPT_VERSION start (mode=$MODE dry_run=$DRY_RUN lang=$UI_LANG) ----"
  setup_input
  case "$MODE" in audit|logins) ;; *) acquire_lock ;; esac

  detect_os
  detect_virt
  detect_sshd
  resolve_sshd_paths
  detect_ssh_service
  detect_firewall
  detect_ips
  load_eff || true
  refresh_cur_ports

  if [ "$MODE" != menu ] && [ "$MODE" != audit ]; then banner; fi
  case "$MODE" in
    menu)
      if [ -z "$TTY_FD" ]; then
        die "No terminal available. Use --audit, or --yes with --key for unattended hardening (see --help)." \
            "没有可交互的终端。可使用 --audit，或 --yes 配合 --key 进行无人值守加固（参见 --help）。"
      fi
      main_menu ;;
    wizard)  run_wizard ;;
    audit)   banner; run_audit ;;
    restore) run_restore ;;
    keys)    keys_menu ;;
    users)   users_menu ;;
    logins)  logins_report ;;
    f2b)     f2b_menu ;;
    notify)  notify_menu ;;
    backups) backups_menu ;;
  esac
  _log "---- finished ----"
}

main "$@"
