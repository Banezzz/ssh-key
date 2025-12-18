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
- Paste one or more SSH public keys (press Enter on an empty line to finish)
- Confirm you have opened the new SSH port in firewall/security group before applying changes
- Username is validated to exist on the system (format + presence)
- Safe mode: two-stage apply. Stage 1 keeps old port + enables new port without disabling passwords, self-tests `ssh -p <new> user@localhost`. Only after pass does Stage 2 switch to key-only and new port.
- Self-test is **skipped by default** (适用于在服务器本机执行、没有私钥在本机的情况)。若你在有私钥的客户端执行，建议加 `--self-test`（或 `--enable-self-test`）开启本机自测以避免配置错误。

## Arguments

`main.sh` accepts up to two positional arguments (optional if你在交互中输入端口):

- `<port>`: SSH port (default: 54271; must be 1024-65535). If omitted, you will be prompted.
- `<sshd_config_path>`: path to sshd_config (default: `/etc/ssh/sshd_config`)

Optional flag:

- `--self-test` / `--enable-self-test`: enable the localhost SSH self-test on the new port (default is skipped).
- `--skip-self-test`: explicitly skip the self-test (default behavior).

## Important

After this runs, SSH should listen on the new port and password login will be disabled.

Example connection:

```bash
ssh -p 54271 user@server-ip
```
