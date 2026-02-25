# ssh-key

Configures SSH for **public-key-only** authentication and moves SSH off port 22 (default: **54271**).

## Requirements

- Linux server (Debian/Ubuntu, Alpine, CentOS/RHEL families)
- Run as **root** (or via `sudo`)
- `sshd` installed and running

## Usage

```bash
sudo ./main.sh
```

远程一键执行（需信任此仓库，确保以 root / sudo 运行；保留 TTY 以便交互输入端口和公钥）：

```bash
# 推荐：先下载再执行，交互正常
curl -fsSL https://raw.githubusercontent.com/Banezzz/ssh-key/refs/heads/main/main.sh -o /tmp/main.sh
sudo bash /tmp/main.sh

# 或一行式（保留 TTY）：让脚本从 /dev/tty 读交互
curl -fsSL https://raw.githubusercontent.com/Banezzz/ssh-key/refs/heads/main/main.sh | sudo bash -s -- </dev/tty
# wget 版本
wget -qO- https://raw.githubusercontent.com/Banezzz/ssh-key/refs/heads/main/main.sh | sudo bash -s -- </dev/tty
```

运行时会提示输入 SSH 端口（直接回车默认 54271），也可继续使用位置参数传入：

```bash
sudo ./main.sh 60022        # 自定义端口
sudo ./main.sh 60022 /etc/ssh/sshd_config
```

You will be prompted to:

- Choose the target username whose `~/.ssh/authorized_keys` will be updated
- **Use existing keys or add new ones**: If valid keys already exist, you can skip key input
- Paste one or more SSH public keys (press Enter on an empty line to finish) - only if adding new keys
- **Select hardening level** (basic / standard / strict)
- Confirm you have opened the new SSH port in firewall/security group before applying changes

## Features

- Username is validated to exist on the system (format + presence)
- **Validates authorized_keys**: checks file is not empty and contains valid SSH keys
- **Weak key warnings**: warns about deprecated ssh-dss (DSA) and ssh-rsa (SHA-1) key types, recommends ssh-ed25519
- **Key fingerprint display**: shows SHA256 fingerprint after adding each key for visual verification
- **Home directory permission check**: auto-fixes group/world-writable home directories that would cause StrictModes to reject key auth
- **Safe two-stage apply**:
  - Stage 1 (warmup): keeps old port + enables new port, keeps password auth on
  - Optional self-test: `ssh -p <new> user@localhost`
  - Stage 2 (final): switches to key-only auth, new port only, applies hardening
  - Optional self-test after final stage
  - If any step fails, automatically restores backup
- **Interrupt-safe**: if the script is interrupted (Ctrl+C / kill) during the two-stage apply, it automatically restores the sshd_config backup and restarts SSH via EXIT trap
- **Concurrent execution lock**: prevents multiple instances from running simultaneously via PID-based lock file
- Self-test is **skipped by default** (适用于在服务器本机执行、没有私钥在本机的情况)。若你在有私钥的客户端执行，建议加 `--self-test`（或 `--enable-self-test`）开启本机自测以避免配置错误。

## Hardening Levels

| Level | Description |
| --- | --- |
| **basic** | Disable password auth, change port, disable insecure auth methods |
| **standard** | Basic + restrict root login, auth limits, timeouts, connection limits, disable DNS lookup |
| **strict** | Standard + fully deny root login, disable all forwarding, strong ciphers only, host key preference, re-keying, verbose logging |

### Base Level Configurations (All Levels)

```bash
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
StrictModes yes
```

### Standard Level Additions

```bash
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:60
UseDNS no
PrintLastLog yes
```

### Strict Level Additions

```bash
PermitRootLogin no
AllowTcpForwarding no
AllowAgentForwarding no
X11Forwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
RekeyLimit 512M 1h
LogLevel VERBOSE
```

> **Note**: Strict 模式会额外禁用 DSA host key（重命名为 `.disabled`），并显式指定仅使用 Ed25519 和 RSA host key。`PermitRootLogin` 会从 standard 的 `prohibit-password` 升级为 `no`（完全禁止 root SSH 登录）。

## Arguments

`main.sh` accepts up to two positional arguments (optional if 你在交互中输入端口):

- `<port>`: SSH port (default: 54271; must be 1024-65535). If omitted, you will be prompted.
- `<sshd_config_path>`: path to sshd_config (default: `/etc/ssh/sshd_config`)

Optional flags:

- `--self-test` / `--enable-self-test`: enable the localhost SSH self-test on the new port after both stages (default is skipped).
- `--skip-self-test`: explicitly skip the self-test (default behavior).

## Important

After this runs, SSH should listen on the new port and password login will be disabled.

**WARNING**: Do NOT close your current SSH session until you have verified connectivity with the new configuration from another terminal:

```bash
ssh -p 54271 user@server-ip
```

## Firewall Configuration

Make sure your firewall allows the new SSH port **before** running this script:

```bash
# UFW (Ubuntu/Debian)
ufw allow 54271/tcp && ufw reload

# firewalld (CentOS/RHEL)
firewall-cmd --permanent --add-port=54271/tcp && firewall-cmd --reload

# iptables
iptables -A INPUT -p tcp --dport 54271 -j ACCEPT
```
