# bootstrap-auditd-bindplane

Takes a Linux server from no audit telemetry to auditd running the
[Neo23x0 ruleset](https://github.com/Neo23x0/auditd) with the BindPlane agent shipping it.

Detects the package manager, installs auditd, applies the ruleset, installs the agent.
POSIX `sh`, no dependencies.

## Install

```sh
sudo sh -c "$(curl -fsSL https://raw.githubusercontent.com/VadimV1/bootstrap-auditd-bindplane/main/bootstrap-auditd-bindplane.sh)" bootstrap-auditd-bindplane.sh -s '<SECRET_KEY>' -k 'fleet=<FLEET_NAME>'
```

Keep the key out of shell history:

```sh
export BP_SECRET_KEY='<SECRET_KEY>'
sudo -E sh -c "$(curl -fsSL https://raw.githubusercontent.com/VadimV1/bootstrap-auditd-bindplane/main/bootstrap-auditd-bindplane.sh)" bootstrap-auditd-bindplane.sh -k 'fleet=<FLEET_NAME>'
```

> The repeated script name becomes `$0`. Drop it and your first flag is silently swallowed.

## Options

```
-e, --endpoint URL       OpAMP endpoint (default: wss://app.bindplane.com/v1/opamp)
-s, --secret-key KEY     BindPlane secret key (or set BP_SECRET_KEY)
-v, --version VER        Agent version (default: 1.107.0)
-k, --labels LABELS      Comma-separated labels, e.g. fleet=prod-linux
-b, --base-url URL       Installer base URL
    --rules-ref REF      Pin a historical commit/tag/branch (default: master = latest)
    --rules-file PATH    Use a local ruleset instead of downloading
    --rules-url URL      Override the ruleset URL
    --rules-sha256 SUM   Require this sha256 of the ruleset before applying
    --audit-log-group G  Set log_group=G + log_file_mode=0640 for a non-root collector
    --min-coverage PCT   Fail if fewer than PCT% of rules load (default 80)
    --keep-b32           Keep 32-bit-ABI rules on non-x86
    --skip-auditd        Agent install only
    --skip-agent         auditd + rules only
    --secret-argv        Secret on installer argv instead of SECRET_KEY env
-f, --force              Proceed past the safety pre-flights
-h, --help               Show help
```

## It refuses to run when

- `auditd.conf` sets `disk_full_action`/`admin_space_left_action` to `halt` or `single` —
  ~250 new rules on a partition sized for the empty stock ruleset can take the host down
- `/etc/audit/rules.d` holds foreign rulesets (Wazuh, STIG, config management)
- the fetched ruleset contains `-e 2` (immutable until reboot) or `-f 2` (kernel panic)

Override any of these with `--force`. It warns, without stopping, when another audit-netlink
consumer is running — only one process can hold that socket.

## It verifies rather than assumes

- Content-checks the download: a 404 or captive-portal HTML body is still a successful transfer
- Counts real rule lines — `auditctl -l` prints `No rules` when empty, so `wc -l` returns 1
- Measures loaded-vs-expected coverage: on ARM64 a partial load still looks non-zero
- Probes that the collector user can actually read `/var/log/audit/audit.log`

## Scope

Debian/Ubuntu, RHEL/Rocky/Alma/CentOS/Fedora, Amazon Linux 2 and 2023, SLES/openSUSE.

Not Alpine or Arch — BindPlane ships `.deb`/`.rpm` only, so those hosts have no agent package.

## Rollback

The script prints the exact command with the backup path:

```sh
rm -f /etc/audit/rules.d/audit.rules
cp -a /etc/audit/rules.d.backup-<STAMP>/. /etc/audit/rules.d/
augenrules --load
```

## Credits

The ruleset is downloaded at runtime from [Neo23x0/auditd](https://github.com/Neo23x0/auditd)
(Nextron Systems) and is not vendored here. Apache-2.0.

Runs as root, changes kernel audit policy, restarts a system service. Test on a non-production
host first.
