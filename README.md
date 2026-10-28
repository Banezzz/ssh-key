# ssh-key — VPS / 独立服务器 SSH 与基础安全加固

单文件 Bash 脚本：把 SSH 改为**仅公钥登录**、迁移到自定义端口（默认 **54271**），并可选地完成 fail2ban、自动安全更新、内核/网络 sysctl 加固和重启检查。全程有防锁死保护：分阶段应用、`sshd -T` 生效校验、端口监听校验，以及**未确认新登录则自动回滚**的倒计时。

## 支持的系统

| 系列 | 发行版（按 `/etc/os-release` 识别，未知发行版按包管理器回退） | 包管理 |
| --- | --- | --- |
| Debian | Debian、Ubuntu、Linux Mint、Kali、Deepin、UOS、Raspbian | apt |
| RHEL | RHEL、CentOS 7/Stream、Rocky、AlmaLinux、Oracle Linux、Fedora、Amazon Linux 2/2023、openEuler、Anolis、Alibaba Cloud Linux、OpenCloudOS、TencentOS、Kylin | dnf / yum |
| Alpine | Alpine（需先 `apk add bash`） | apk |
| Arch | Arch、Manjaro、EndeavourOS | pacman |
| SUSE | openSUSE Leap / Tumbleweed（含 `/usr/etc` vendor 配置）、SLES | zypper |
| Gentoo | Gentoo | — |

服务管理：systemd（含 Ubuntu 22.10+ 的 `ssh.socket` 套接字激活）、OpenRC、SysV、runit。虚拟化：KVM/物理机正常运行；OpenVZ/LXC 容器型 VPS 会自动跳过 sysctl；Docker 中仅做 SSH 部分。

## 快速开始

```bash
# 推荐：先下载、检查，再执行
curl -fsSL https://raw.githubusercontent.com/Banezzz/ssh-key/main/main.sh -o main.sh
sudo bash main.sh --audit      # 只读体检，不做任何修改
sudo bash main.sh              # 交互式加固

# 一行式（脚本会自动从 /dev/tty 读取交互输入，无需再加 </dev/tty）
curl -fsSL https://raw.githubusercontent.com/Banezzz/ssh-key/main/main.sh | sudo bash
```

交互流程：端口 → 登录用户 → 公钥（可粘贴，或输入 `gh:<GitHub用户名>` 导入）→ 加固等级 →（可选）创建 sudo 用户 → root 登录策略 / AllowUsers → 附加模块 → **显示完整计划后确认** → 执行 → 在新终端验证登录并输入 `yes` →（standard/strict）重启提示。

确认计划之前**不会修改任何文件**；`--dry-run` 会走完全部问题并打印将写入的配置后退出。

## 加固等级

| 等级 | 内容 |
| --- | --- |
| **basic** | 仅公钥登录；关闭密码、keyboard-interactive、空密码、hostbased；自定义端口 |
| **standard**（推荐） | basic + root 仅允许密钥或完全禁止（有 sudo 用户时默认禁止）、`MaxAuthTries 4`、`LoginGraceTime 30`、`MaxStartups`、空闲探测、关闭 X11、`LogLevel VERBOSE`（记录登录所用公钥指纹）、移除 SHA-1/umac-64 MAC、隐藏 Debian 版本横幅；可选 AllowUsers；默认启用 fail2ban、自动安全更新、sysctl |
| **strict** | standard + `PermitRootLogin no`（必须有非 root 的 SSH 用户）、关闭 TCP/agent/stream-local 转发与隧道、仅现代算法（按本机 OpenSSH 实际支持自动筛选，含 `sntrup761`/`mlkem768` 抗量子 KEX）、仅 Ed25519/RSA 主机密钥、禁用 DSA 主机密钥、移除 < 3072 位 DH moduli、`RekeyLimit` |

> strict 会让 **VS Code Remote-SSH、`ssh -L/-D` 隧道、agent 转发** 失效，这是预期行为。

生成的配置写入 `/etc/ssh/sshd_config.d/00-ssh-hardening.conf`（主配置有 `Include` 时）或主配置**顶部**的受管块（无 `Include` 的老系统）。sshd 对大多数指令是"首个值生效"，因此两种方式都能压过 `50-cloud-init.conf` 等其它来源；与之冲突的旧指令会被注释为 `# [ssh-hardening] ...`，`Port` 这类可叠加的指令会在所有文件中注释掉。

## 防锁死机制

1. **预检**：当前配置必须能通过 `sshd -t`；拒绝 DSA 与 < 2048 位 RSA 公钥（OpenSSH 7.0+ 默认不接受 DSA，会导致锁死）；检查 `AuthorizedKeysFile` 是否真的读取 `~/.ssh/authorized_keys`、账号是否被锁（无 PAM 时被锁账号连密钥也无法登录，常见于 Alpine）、shell 是否为 nologin、现有 `AllowUsers/DenyUsers` 是否排除目标用户、新端口是否被其它服务占用。
2. **SELinux**（RHEL 系）：自动 `semanage port -a -t ssh_port_t`，否则 sshd 无法绑定新端口。
3. **防火墙**：检测 ufw / firewalld / iptables / nftables 并放行新端口（在切换之前）。云厂商安全组无法检测，需要你自己放行。
4. **阶段 1**：新旧端口同时监听，确认新端口确实在监听（读取 `/proc/net/tcp`）。
5. **阶段 2**：写入最终配置 → `sshd -t` → `sshd -T` 校验实际生效值（端口、密码登录、root 登录等），被其它配置覆盖则视为失败 → 重启 → 再次确认监听。
6. **倒计时确认**（默认 180 秒）：在**新终端**用新端口登录成功后输入 `yes`。超时、输入 `rollback`、或当前会话断开，都会自动恢复原配置（后台独立进程执行，不依赖当前会话存活）。
7. 任何一步失败、Ctrl+C、SIGHUP 都会触发恢复。

每次运行的备份在 `/var/lib/ssh-hardening/backup-<时间>/`，其中的 `restore.sh` 可以随时手动执行；或使用 `sudo bash main.sh --restore`。日志：`/var/log/ssh-hardening.log`。

## 附加模块

| 模块 | 说明 |
| --- | --- |
| fail2ban | 为新端口配置 sshd jail（递增封禁时长、白名单当前客户端 IP）；自动选择 `backend`（无 auth.log 时用 systemd journal）与 `banaction`（firewalld / ufw / nftables / iptables）；RHEL 系会询问是否启用 EPEL |
| 自动安全更新 | Debian/Ubuntu: unattended-upgrades；RHEL 8+/Fedora: dnf-automatic（仅安全更新，CentOS Stream 无安全公告则用 default）；EL7/AL2: yum-cron；SUSE: 每日 `zypper patch --category security` 定时器。Arch/Alpine/Gentoo 不做无人值守升级 |
| sysctl | SYN cookies、禁止 ICMP 重定向/源路由、`kptr_restrict`、`dmesg_restrict`、`ptrace_scope`、受保护硬/软链接等；strict 另加 `log_martians`、禁止非特权 BPF、`bpf_jit_harden` 等。只写入内核支持的键。**不改动** `ip_forward` 与 `rp_filter`（Docker/VPN/路由主机依赖它们） |
| 端口保留 | 若 SSH 端口位于临时端口范围（默认 54271 就在 32768–60999 内），自动加入 `net.ipv4.ip_local_reserved_ports`，避免出站连接占用该端口导致 sshd 重启后无法绑定 |

## 关于重启

修改 SSH、防火墙、sysctl **都是即时生效的，本身不需要重启**。脚本在结束时：

- 检测是否**真的需要**重启：`/var/run/reboot-required`（Debian/Ubuntu）、`needs-restarting -r`（RHEL）、`zypper needs-rebooting`、运行中的内核已被升级移除；
- standard / strict 等级会提示是否重启，并说明原因——即使没有待生效的更新，也建议趁还有控制台（VNC）访问时重启一次，验证 sshd、防火墙规则和 sysctl 在开机后都能正确恢复（例如未持久化的 iptables 规则在重启后会丢失）；
- 默认答案为 **No**；只在新登录确认成功后才建议重启；Docker 容器内不提示；`--reboot` / `--no-reboot` 用于无人值守。

## 命令行参数

```text
模式
      --audit              只读安全体检（不修改任何内容）
      --dry-run            回答所有问题并显示计划与生成的配置，不修改任何内容
      --restore [DIR]      从最近一次（或指定）备份恢复 SSH 配置

SSH
  -p, --port N             SSH 端口（默认 54271；22 或 1024–65535）
  -l, --level L            basic | standard | strict
  -u, --user NAME          登录用户（管理其 authorized_keys）
  -k, --key "PUBKEY"       添加公钥（可重复）；"gh:NAME" 导入 github.com/NAME.keys
      --key-file FILE      从文件添加公钥（可重复）
      --new-user NAME      同时创建 sudo 用户（复制相同公钥）
      --root-login MODE    no | prohibit-password（standard 等级）
      --allow-users / --no-allow-users
  -c, --config PATH        sshd_config 路径（默认 /etc/ssh/sshd_config）

安全
      --confirm-timeout S  新登录确认时限，超时自动回滚（默认 180，0 关闭）
      --self-test          额外执行 ssh -p PORT user@localhost 自测（需要本机有私钥）

附加模块（不指定则询问；standard/strict 默认开启）
      --firewall / --no-firewall
      --fail2ban / --no-fail2ban
      --auto-updates / --no-auto-updates
      --sysctl / --no-sysctl
      --reboot / --no-reboot

  -y, --yes                非交互：全部使用默认值（需要提供公钥来源）
```

旧的位置参数仍然兼容：`sudo bash main.sh 60022 /etc/ssh/sshd_config`。

### 无人值守示例（cloud-init / 批量部署）

```bash
sudo bash main.sh --yes -p 2222 -l standard -u deploy -k gh:your-github-name \
  --fail2ban --auto-updates --sysctl --no-reboot
```

`--yes` 模式没有人工确认环节（倒计时回滚关闭），请确保公钥正确；建议加 `--self-test`（若本机有对应私钥）或先用 `--dry-run` 检查。`--yes` 下新建用户默认使用 NOPASSWD sudo（无法非交互地设置密码），root 登录默认保持 `prohibit-password`，除非显式传入 `--root-login no`。

## 注意事项

- **云安全组**（阿里云、腾讯云、AWS、GCP 等）必须自行放行新端口，脚本无法检测。
- 在**确认新终端可以登录之前**不要关闭当前会话。
- 客户端 ssh-agent 中密钥较多时，请在 `~/.ssh/config` 中使用 `IdentitiesOnly yes` + `IdentityFile`，否则可能在尝试到正确密钥前就耗尽 `MaxAuthTries`。
- RHEL 8 的 crypto-policies 通过命令行参数传给 sshd，会覆盖 strict 设置的算法列表；如需更严格，可执行 `update-crypto-policies --set FUTURE`。
- 恢复只回滚 SSH 配置；已放行的防火墙规则、SELinux 端口标签、已创建的用户与已安装的软件包会保留。
- 脚本输出为英文，便于在不支持中文的 VNC/串口控制台中阅读。
