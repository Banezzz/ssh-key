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

## Arguments

`main.sh` accepts up to two positional arguments (optional if你在交互中输入端口):

- `<port>`: SSH port (default: 54271; must be 1024-65535). If omitted, you will be prompted.
- `<sshd_config_path>`: path to sshd_config (default: `/etc/ssh/sshd_config`)

## Important

After this runs, SSH should listen on the new port and password login will be disabled.

Example connection:

```bash
ssh -p 54271 user@server-ip
```
