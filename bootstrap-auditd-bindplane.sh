#!/bin/sh
#
# bootstrap-auditd-bindplane.sh
#
# Bootstraps a Linux host for audit telemetry collection:
#   1. Detects the package manager (apt-get / dnf / yum / zypper)
#   2. Installs and enables auditd
#   3. Fetches the Neo23x0 "Linux Audit Daemon - Best Practice Configuration"
#      (https://github.com/Neo23x0/auditd) and applies it
#   4. Installs the BindPlane agent via the vendor's install_unix.sh
#
# POSIX sh on purpose: this runs on a bare host before anything is installed,
# so it may not assume bash, curl, python or any other runtime is present.
#
# Usage:
#   sudo ./bootstrap-auditd-bindplane.sh -s <SECRET_KEY> -k fleet=<FLEET_NAME>
#
#   -e, --endpoint URL       OpAMP endpoint      (default: wss://app.bindplane.com/v1/opamp)
#   -s, --secret-key KEY     BindPlane secret key. Prefer the BP_SECRET_KEY env var.
#   -v, --version VER        Agent version       (default: 1.107.0)
#   -k, --labels LABELS      Comma-separated labels, e.g. fleet=prod-linux
#   -b, --base-url URL       Installer base URL  (default: https://bdot.bindplane.com)
#       --rules-ref REF      Pin a historical commit/tag/branch of the Neo23x0 repo.
#                            Default is master, i.e. always the latest ruleset.
#       --rules-file PATH    Use a local ruleset instead of downloading (airgapped hosts)
#       --rules-url URL      Override the ruleset URL entirely
#       --rules-sha256 SUM   Require this sha256 of the ruleset before applying
#       --audit-log-group G  Set auditd log_group=G + log_file_mode=0640 so a
#                            non-root collector can read /var/log/audit/audit.log
#       --min-coverage PCT   Fail if fewer than PCT% of rules actually load (default 80)
#       --keep-b32           Keep 32-bit-ABI rules on non-x86 architectures
#       --skip-auditd        Skip steps 1-3 (agent install only)
#       --skip-agent         Skip step 4 (auditd + rules only)
#       --secret-argv        Pass the secret on the installer's argv instead of via the
#                            SECRET_KEY env var. Reproduces the vendor one-liner exactly,
#                            but exposes the key in `ps` output during the install.
#   -f, --force              Proceed past the safety pre-flights (see below)
#   -h, --help               Show this help
#
# Safety pre-flights that stop the run unless --force is given:
#   * auditd.conf has disk_full_action/admin_space_left_action = halt|single
#     (adding ~250 rules to a host sized for the empty stock ruleset can halt it)
#   * /etc/audit/rules.d already holds foreign rules (Wazuh, STIG, Ansible-managed)
#   * the fetched ruleset contains an uncommented `-e 2` (immutable until reboot)
#     or `-f 2` (kernel panic on audit failure)
#
set -eu

# ---------------------------------------------------------------- defaults ---
ENDPOINT="wss://app.bindplane.com/v1/opamp"
BP_VERSION="1.107.0"
BASE_URL="https://bdot.bindplane.com"
LABELS=""
SECRET="${BP_SECRET_KEY:-}"
RULES_REF="master"
RULES_URL=""
RULES_LOCAL=""
RULES_SHA=""
AUDIT_LOG_GROUP=""
MIN_COVERAGE=80
RULES_DIR="/etc/audit/rules.d"
RULES_FILE="${RULES_DIR}/audit.rules"
AUDITD_CONF="/etc/audit/auditd.conf"
KEEP_B32=0
DO_AUDITD=1
DO_AGENT=1
SECRET_ARGV=0
FORCE=0

log()  { printf '[*] %s\n' "$*"; }
ok()   { printf '[+] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
# gate <message> - hard stop unless the operator passed --force
gate() {
  if [ "$FORCE" -eq 1 ]; then warn "FORCED PAST: $1"; else
    die "$1
    Re-run with --force once you have accepted this, or fix the condition first."
  fi
}
# When run via `curl | sh` there is no script file on disk, so $0 is not readable
# and the header-comment trick cannot work. Fall back to a compact synopsis.
usage() {
  if [ -r "$0" ]; then
    sed -n '3,45p' "$0" | sed 's/^# \{0,1\}//'
  else
    cat <<'USAGE'
bootstrap-auditd-bindplane.sh

  sudo ./bootstrap-auditd-bindplane.sh -s <SECRET_KEY> -k fleet=<FLEET_NAME>

  -e, --endpoint URL       OpAMP endpoint (default: wss://app.bindplane.com/v1/opamp)
  -s, --secret-key KEY     BindPlane secret key (or set BP_SECRET_KEY)
  -v, --version VER        Agent version (default: 1.107.0)
  -k, --labels LABELS      Comma-separated labels, e.g. fleet=prod-linux
  -b, --base-url URL       Installer base URL
      --rules-ref REF      Pin a historical commit/tag/branch (default: master = latest)
      --rules-file PATH    Use a local ruleset instead of downloading
      --rules-url URL      Override the ruleset URL entirely
      --rules-sha256 SUM   Require this sha256 of the ruleset before applying
      --audit-log-group G  Set log_group=G + log_file_mode=0640 for a non-root collector
      --min-coverage PCT   Fail if fewer than PCT% of rules load (default 80)
      --keep-b32           Keep 32-bit-ABI rules on non-x86 architectures
      --skip-auditd        Agent install only
      --skip-agent         auditd + rules only
      --secret-argv        Put the secret on the installer argv instead of SECRET_KEY env
  -f, --force              Proceed past the safety pre-flights
  -h, --help               Show this help

Full documentation: see README.md in the repository.
USAGE
  fi
  exit 0
}

# ------------------------------------------------------------------- args ---
while [ $# -gt 0 ]; do
  case "$1" in
    -e|--endpoint)     ENDPOINT="${2:?--endpoint needs a value}";     shift 2 ;;
    -s|--secret-key)   SECRET="${2:?--secret-key needs a value}";     shift 2 ;;
    -v|--version)      BP_VERSION="${2:?--version needs a value}";    shift 2 ;;
    -k|--labels)       LABELS="${2:?--labels needs a value}";         shift 2 ;;
    -b|--base-url)     BASE_URL="${2:?--base-url needs a value}";     shift 2 ;;
    --rules-ref)       RULES_REF="${2:?--rules-ref needs a value}";   shift 2 ;;
    --rules-file)      RULES_LOCAL="${2:?--rules-file needs a path}"; shift 2 ;;
    --rules-url)       RULES_URL="${2:?--rules-url needs a value}";   shift 2 ;;
    --rules-sha256)    RULES_SHA="${2:?--rules-sha256 needs a value}"; shift 2 ;;
    --audit-log-group) AUDIT_LOG_GROUP="${2:?--audit-log-group needs a group}"; shift 2 ;;
    --min-coverage)    MIN_COVERAGE="${2:?--min-coverage needs a percentage}"; shift 2 ;;
    --keep-b32)        KEEP_B32=1;    shift ;;
    --skip-auditd)     DO_AUDITD=0;   shift ;;
    --skip-agent)      DO_AGENT=0;    shift ;;
    --secret-argv)     SECRET_ARGV=1; shift ;;
    -f|--force)        FORCE=1;       shift ;;
    -h|--help)         usage ;;
    *) die "unknown argument: $1  (try --help)" ;;
  esac
done
[ -n "$RULES_URL" ] || RULES_URL="https://raw.githubusercontent.com/Neo23x0/auditd/${RULES_REF}/audit.rules"

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"

# ---------------------------------------------------- 1. package manager ---
# Detect by binary presence, never by /etc/os-release. The distro NAME is a lossy
# proxy: Amazon Linux 2 uses yum while 2023 uses dnf, and every RHEL rebuild would
# otherwise need its own special case.
PM=""
for c in apt-get dnf yum zypper; do
  if have "$c"; then PM="$c"; break; fi
done
[ -n "$PM" ] || die "no supported package manager found (apt-get/dnf/yum/zypper)"
ARCH="$(uname -m)"
log "package manager: ${PM}   architecture: ${ARCH}"

pm_install() {
  case "$PM" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
               -o Dpkg::Options::=--force-confold "$@" ;;
    dnf)     dnf install -y "$@" ;;
    yum)     yum install -y "$@" ;;
    # zypper returns 100-106 for NON-error outcomes (already installed, reboot
    # needed, patches applied). Under `set -e` those would kill a successful run.
    zypper)  set +e; zypper --non-interactive install --no-recommends "$@"; rc=$?; set -e
             case "$rc" in 0|100|101|102|103|106) return 0 ;; *) return "$rc" ;; esac ;;
  esac
}
pm_refresh() {
  case "$PM" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get update -qq ;;
    zypper)  set +e; zypper --non-interactive refresh >/dev/null; set -e ;;
    *)       : ;;
  esac
}
pm_refresh

if ! have curl && ! have wget; then
  log "installing curl"
  pm_install curl || pm_install wget || die "could not install curl or wget"
fi
fetch() {  # fetch <url> <dest>
  if have curl; then curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"
  else wget -q -t 3 -O "$2" "$1"; fi
}

if [ "$DO_AUDITD" -eq 1 ]; then

  # ------------------------------------------------- 2. kernel audit check ---
  # Unprivileged containers, WSL2, and hosts booted `audit=0` have no audit
  # subsystem at all. Everything below would fail confusingly.
  [ -r /proc/self/loginuid ] || gate "no /proc/self/loginuid - kernel audit subsystem looks absent (container? WSL? audit=0?)"

  # ----------------------------------------- 3. detect competing consumers ---
  # Only ONE process may hold the audit netlink unicast socket. Restarting
  # auditd re-parents it and silently starves whoever had it.
  for consumer in auditbeat wazuh-modulesd wazuh-agentd go-audit falco sysmonforlinux osqueryd; do
    if pgrep -x "$consumer" >/dev/null 2>&1; then
      warn "'${consumer}' is running and may be consuming the audit netlink socket - it can stop receiving events after auditd restarts"
    fi
  done

  # ------------------------------------------------------ 4. install auditd ---
  # Package name differs by family: Debian/Ubuntu ship "auditd", RHEL/SUSE ship "audit".
  case "$PM" in
    apt-get) AUDIT_PKGS="auditd" ;;
    *)       AUDIT_PKGS="audit"  ;;
  esac
  log "installing ${AUDIT_PKGS}"
  pm_install "$AUDIT_PKGS" || die "failed to install ${AUDIT_PKGS}"
  # Bundled into the base package on RHEL 8+ and SUSE - best effort only.
  pm_install audispd-plugins >/dev/null 2>&1 || log "audispd-plugins not a separate package here (fine)"
  have auditctl || die "auditctl not on PATH after install"
  ok "auditd installed"

  # -------------------------------------------- 5. disk-full safety gate ---
  # The stock ruleset is empty. We are about to add ~250 rules including execve
  # and failed-open auditing to a partition sized for silence. On a CIS/STIG
  # image where *_action is halt or single, filling it takes production down.
  if [ -r "$AUDITD_CONF" ]; then
    BAD_ACTION=$(grep -iE '^[[:space:]]*(disk_full_action|admin_space_left_action|disk_error_action)[[:space:]]*=[[:space:]]*(halt|single)' "$AUDITD_CONF" || true)
    if [ -n "$BAD_ACTION" ]; then
      warn "auditd.conf will halt or single-user this host when /var/log/audit fills:"
      printf '%s\n' "$BAD_ACTION" | sed 's/^/      /' >&2
      gate "refusing to multiply audit volume on a host configured to halt on disk-full"
    fi
    log "audit log sizing: $(grep -iE '^[[:space:]]*(max_log_file|num_logs|space_left)[[:space:]]*=' "$AUDITD_CONF" | tr -s ' \n' ' ' || echo 'defaults')"
  fi

  # ---------------------------------------------- 6. obtain the ruleset ---
  TMP_RULES="$(mktemp)"
  # shellcheck disable=SC2064
  trap "rm -f '$TMP_RULES'" EXIT INT TERM

  if [ -n "$RULES_LOCAL" ]; then
    [ -r "$RULES_LOCAL" ] || die "--rules-file not readable: ${RULES_LOCAL}"
    cp "$RULES_LOCAL" "$TMP_RULES"
    log "using local ruleset: ${RULES_LOCAL}"
  else
    log "fetching audit ruleset: ${RULES_URL}"
    fetch "$RULES_URL" "$TMP_RULES" || die "download failed: ${RULES_URL}"
  fi

  # Validate CONTENT, not just the exit code. A proxy error page or an HTML 404
  # body is a *successful* transfer that would leave auditd running with no rules.
  [ -s "$TMP_RULES" ] || die "ruleset is empty - refusing to apply"
  grep -q '^-a always,exit' "$TMP_RULES" || die "file does not look like an audit ruleset - refusing to apply"

  if [ -n "$RULES_SHA" ]; then
    have sha256sum || die "--rules-sha256 given but sha256sum is not available"
    GOT="$(sha256sum "$TMP_RULES" | cut -d' ' -f1)"
    [ "$GOT" = "$RULES_SHA" ] || die "ruleset sha256 mismatch: expected ${RULES_SHA}, got ${GOT}"
    ok "ruleset sha256 verified"
  else
    have sha256sum && log "ruleset sha256: $(sha256sum "$TMP_RULES" | cut -d' ' -f1)  (record this to replay it later)"
  fi

  # Upstream is a moving branch. Two one-line upstream edits would be disastrous:
  #   -e 2  makes the config immutable until reboot (breaks re-runs AND rollback)
  #   -f 2  panics the kernel when auditd cannot write
  grep -qE '^[[:space:]]*-e[[:space:]]+2[[:space:]]*$' "$TMP_RULES" \
    && gate "ruleset sets '-e 2' (immutable until reboot) - this would lock out rollback"
  grep -qE '^[[:space:]]*-f[[:space:]]+2[[:space:]]*$' "$TMP_RULES" \
    && gate "ruleset sets '-f 2' (kernel panic on audit failure)"
  ok "ruleset validated ($(wc -l < "$TMP_RULES") lines)"

  # 32-bit ABI rules cannot load where CONFIG_COMPAT is absent (ARM64, s390x,
  # ppc64le). Left in, they produce dozens of individual load failures.
  case "$ARCH" in
    x86_64|amd64|i?86) : ;;
    *) if [ "$KEEP_B32" -eq 0 ]; then
         B32=$(grep -c '^-.*arch=b32' "$TMP_RULES" || true)
         sed -i '/^-.*arch=b32/d' "$TMP_RULES"
         log "stripped ${B32} arch=b32 rules (unsupported on ${ARCH}; --keep-b32 to override)"
       fi ;;
  esac

  # ------------------------------------------------------- 7. apply ruleset ---
  # The Neo23x0 file starts with "-D" and sets -b/-f, so it must be the ONLY file
  # in rules.d. Added as a numbered file it would wipe every rule that augenrules
  # had already concatenated ahead of it.
  mkdir -p "$RULES_DIR"
  FOREIGN=$(find "$RULES_DIR" -maxdepth 1 -name '*.rules' ! -name 'audit.rules' 2>/dev/null | head -5 || true)
  if [ -n "$FOREIGN" ]; then
    warn "foreign rulesets present in ${RULES_DIR} (Wazuh / STIG / config-management?):"
    printf '%s\n' "$FOREIGN" | sed 's/^/      /' >&2
    gate "replacing rules.d would delete these and flap against whatever manages them"
  fi

  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  BACKUP="/etc/audit/rules.d.backup-${STAMP}"
  if [ -n "$(ls -A "$RULES_DIR" 2>/dev/null || true)" ]; then
    mkdir -p "$BACKUP"; cp -a "$RULES_DIR"/. "$BACKUP"/ 2>/dev/null || true
    rm -f "$RULES_DIR"/*.rules
    ok "existing rules backed up to ${BACKUP}"
  fi
  [ -f /etc/audit/audit.rules ] && cp -a /etc/audit/audit.rules "/etc/audit/audit.rules.bak-${STAMP}" || true
  install -m 0640 -o root -g root "$TMP_RULES" "$RULES_FILE"
  ok "ruleset installed: ${RULES_FILE}"

  # Optionally make the log readable by a non-root collector. Without this the
  # rules load perfectly and the agent still ships nothing - /var/log/audit is
  # 0700 root and audit.log is 0600 root by default.
  if [ -n "$AUDIT_LOG_GROUP" ] && [ -w "$AUDITD_CONF" ]; then
    if have getent; then getent group "$AUDIT_LOG_GROUP" >/dev/null 2>&1 || die "group not found: ${AUDIT_LOG_GROUP}"; fi
    cp -a "$AUDITD_CONF" "${AUDITD_CONF}.bak-${STAMP}"
    if grep -qE '^[[:space:]]*log_group[[:space:]]*=' "$AUDITD_CONF"; then
      sed -i "s|^[[:space:]]*log_group[[:space:]]*=.*|log_group = ${AUDIT_LOG_GROUP}|" "$AUDITD_CONF"
    else printf 'log_group = %s\n' "$AUDIT_LOG_GROUP" >> "$AUDITD_CONF"; fi
    if grep -qE '^[[:space:]]*log_file_mode[[:space:]]*=' "$AUDITD_CONF"; then
      sed -i 's|^[[:space:]]*log_file_mode[[:space:]]*=.*|log_file_mode = 0640|' "$AUDITD_CONF"
    else printf 'log_file_mode = 0640\n' >> "$AUDITD_CONF"; fi
    ok "auditd log_group=${AUDIT_LOG_GROUP}, log_file_mode=0640 (collector user must be in that group)"
  fi

  # Load. augenrules/auditctl exit non-zero if ANY single rule fails, which is
  # normal on a stock kernel - tolerate the exit code, judge by the result.
  log "loading rules"
  if have augenrules; then
    augenrules --load || warn "augenrules reported errors (partial load is expected on some kernels)"
  else
    auditctl -R "$RULES_FILE" >/dev/null 2>&1 || auditctl -c -R "$RULES_FILE" >/dev/null 2>&1 \
      || warn "auditctl reported errors while loading"
  fi

  # ------------------------------------------------------ 8. enable service ---
  if [ -d /run/systemd/system ] && have systemctl; then
    systemctl enable auditd >/dev/null 2>&1 || warn "could not enable auditd unit"
    # RHEL/CentOS auditd.service sets RefuseManualStop=yes, so `systemctl restart
    # auditd` fails by design. The SysV wrapper is the supported path there.
    if have service; then service auditd restart >/dev/null 2>&1 || systemctl start auditd >/dev/null 2>&1 || true
    else systemctl restart auditd >/dev/null 2>&1 || systemctl start auditd >/dev/null 2>&1 || true; fi
  elif have service; then
    service auditd restart >/dev/null 2>&1 || service auditd start >/dev/null 2>&1 || true
  else warn "no recognised service manager - start auditd manually"; fi

  # ------------------------------------------------- 9. verify the load ---
  # `auditctl -l` prints the literal string "No rules" when empty, so a bare
  # line count is 1 and would pass. Count only lines that ARE rules.
  EXPECTED=$(grep -cE '^-[aw] ' "$RULES_FILE" || true)
  LOADED=$(auditctl -l 2>/dev/null | grep -cE '^-[aw] ' || true)
  [ "${LOADED:-0}" -gt 0 ] || die "auditd has 0 rules loaded - the ruleset did not apply"
  # A partial b64 load (arm64 lacks open/fork/stat/chmod/rename/unlink syscalls)
  # still yields a non-zero count. Measure coverage, do not just assert non-empty.
  PCT=$(( LOADED * 100 / (EXPECTED > 0 ? EXPECTED : 1) ))
  if [ "$PCT" -lt "$MIN_COVERAGE" ]; then
    warn "only ${LOADED}/${EXPECTED} rules loaded (${PCT}%) - many were rejected by this kernel/arch"
    gate "rule coverage ${PCT}% is below --min-coverage ${MIN_COVERAGE}%"
  fi
  ok "auditd active: ${LOADED}/${EXPECTED} rules loaded (${PCT}%)"
  log "rollback: rm -f ${RULES_FILE} && cp -a ${BACKUP}/. ${RULES_DIR}/ && augenrules --load"
fi

# ----------------------------------------------- 10. BindPlane agent ---
if [ "$DO_AGENT" -eq 1 ]; then
  [ -n "$SECRET" ] || die "no secret key: pass -s <KEY> or set BP_SECRET_KEY"
  [ -n "$LABELS" ] || warn "no labels given (-k fleet=<NAME>) - agent will install unlabelled"

  # The version appears in BOTH the installer URL path and the -v flag. Deriving
  # the URL from the same variable is what stops the two drifting apart and
  # installing a build that does not match what the script reports.
  INSTALLER_URL="${BASE_URL}/v${BP_VERSION}/install_unix.sh"
  log "installing BindPlane agent ${BP_VERSION} from ${INSTALLER_URL}"
  log "endpoint: ${ENDPOINT}   labels: ${LABELS:-<none>}"

  set -- -e "$ENDPOINT" -v "$BP_VERSION"
  [ -n "$LABELS" ] && set -- "$@" -k "$LABELS"

  if [ "$SECRET_ARGV" -eq 1 ]; then
    # Vendor's documented form. The key is visible in `ps` while it runs.
    set -- "$@" -s "$SECRET"
    sh -c "$(fetch "$INSTALLER_URL" /dev/stdout)" install_unix.sh "$@" || die "BindPlane agent install failed"
  else
    # Same installer, same flags, but the secret travels in the environment
    # (SECRET_KEY is documented by the installer) so it never reaches argv,
    # `ps aux`, or shell history.
    SECRET_KEY="$SECRET" sh -c "$(fetch "$INSTALLER_URL" /dev/stdout)" install_unix.sh "$@" \
      || die "BindPlane agent install failed"
  fi
  ok "BindPlane agent installed"

  if have systemctl && systemctl is-active --quiet observiq-otel-collector 2>/dev/null; then
    ok "collector service is running"
  else
    warn "collector service not reporting active - check: systemctl status observiq-otel-collector"
  fi

  # Rules loading and the agent running still does not mean events flow: the
  # collector runs unprivileged and /var/log/audit is 0700 root by default.
  COLLECTOR_USER="$(ps -o user= -C observiq-otel-collector 2>/dev/null | head -1 | tr -d ' ' || true)"
  if [ -n "$COLLECTOR_USER" ] && [ "$COLLECTOR_USER" != "root" ]; then
    if su -s /bin/sh -c 'head -c1 /var/log/audit/audit.log >/dev/null 2>&1' "$COLLECTOR_USER" 2>/dev/null; then
      ok "collector user '${COLLECTOR_USER}' can read /var/log/audit/audit.log"
    else
      warn "collector runs as '${COLLECTOR_USER}' and CANNOT read /var/log/audit/audit.log - rules load but nothing ships."
      warn "  fix: re-run with --audit-log-group <group> and add '${COLLECTOR_USER}' to that group"
    fi
  fi
fi

ok "bootstrap complete"
