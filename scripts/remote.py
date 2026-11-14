#!/usr/bin/env python3
"""Run commands and push files to the portal server over SSH.

Why this exists rather than plain ssh/scp:
  - Windows has no sshpass/plink, so password auth can't be scripted with the
    stock OpenSSH client.
  - The server has no GitHub credentials and the repo is private, so `push`
    ships the working tree directly instead of putting a token on the box.

Connection details come from wifi-portal/.remote.env (gitignored) so that no
credential ever appears on a command line or in shell history. Copy
.remote.env.example to .remote.env and fill it in.

Usage:
    remote.py run    "<shell command>"    run a command, print stdout
    remote.py sudo   "<shell command>"    same, wrapped in sudo -S
    remote.py script <local.sh>           run a local script in ONE session
    remote.py push   [--dry-run]          upload wifi-portal/ to REMOTE_DIR
    remote.py check                       connectivity + host facts

Prefer `script` over several `run` calls: the UDM runs IPS in blocking mode, and
a burst of separate SSH connections trips a brute-force signature that blocks
the source for minutes (tcp/22 stops answering while ICMP still does).

Prefers key auth when SSH_KEY is set and installed; otherwise uses SSH_PASS.
"""

from __future__ import annotations

import argparse
import os
import posixpath
import sys

try:
    import paramiko
except ImportError:
    sys.exit("paramiko is required:  pip install paramiko")

HERE = os.path.dirname(os.path.abspath(__file__))
PORTAL_DIR = os.path.dirname(HERE)
ENV_FILE = os.path.join(PORTAL_DIR, ".remote.env")

# Never uploaded: virtualenvs, caches, local state, secrets.
SKIP_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", "instance", ".git", "node_modules"}
SKIP_FILES = {".env", ".remote.env", ".DS_Store"}
SKIP_EXT = {".pyc", ".pyo", ".sqlite", ".db"}


def load_env() -> dict[str, str]:
    if not os.path.exists(ENV_FILE):
        sys.exit(
            f"missing {ENV_FILE}\n"
            "Copy .remote.env.example to .remote.env and fill in SSH_HOST/SSH_USER/SSH_PASS."
        )
    cfg: dict[str, str] = {}
    with open(ENV_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    for required in ("SSH_HOST", "SSH_USER"):
        if not cfg.get(required):
            sys.exit(f"{required} not set in {ENV_FILE}")
    return cfg


def connect(cfg: dict[str, str]) -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    host, user = cfg["SSH_HOST"], cfg["SSH_USER"]
    port = int(cfg.get("SSH_PORT", "22"))
    key = os.path.expanduser(cfg.get("SSH_KEY", ""))

    # Try the key only when one is configured AND marked installed. Attempting
    # it speculatively costs a failed auth on every invocation, which is enough
    # to trip sshd rate limiting or fail2ban after a handful of commands.
    if key and os.path.exists(key) and cfg.get("SSH_KEY_INSTALLED", "").lower() in ("1", "true", "yes"):
        try:
            c.connect(host, port=port, username=user, key_filename=key, timeout=25)
            print(f"[auth: key {os.path.basename(key)}]", file=sys.stderr)
            return c
        except paramiko.AuthenticationException:
            print("key auth failed, falling back to password", file=sys.stderr)

    if not cfg.get("SSH_PASS"):
        sys.exit("no usable key and SSH_PASS is not set")
    c.connect(host, port=port, username=user, password=cfg["SSH_PASS"],
              timeout=25, look_for_keys=False)
    # Printed so a silent fallback to password auth is never mistaken for key
    # auth working - the two are indistinguishable from the command's output.
    print("[auth: password]", file=sys.stderr)
    return c


def run_cmd(c: paramiko.SSHClient, cmd: str, sudo_pass: str | None = None) -> int:
    # No pty when feeding sudo a password: `sudo -S` reads stdin and needs no
    # tty, and a pty would echo the password straight back into stdout - i.e.
    # into logs and transcripts.
    stdin, stdout, stderr = c.exec_command(cmd, get_pty=sudo_pass is None, timeout=900)
    if sudo_pass:
        stdin.write(sudo_pass + "\n")
        stdin.flush()
    for line in iter(stdout.readline, ""):
        sys.stdout.write(line)
        sys.stdout.flush()
    rc = stdout.channel.recv_exit_status()
    err = stderr.read().decode(errors="replace")
    if err.strip():
        sys.stderr.write("--- stderr ---\n" + err)
    return rc


def run_script(c: paramiko.SSHClient, script_path: str) -> int:
    """Execute a local shell script remotely over ONE session, via stdin.

    Two reasons this exists instead of `run "<long command>"`:

    1. The UDM runs IPS in blocking mode (ips_mode="ips"). Opening a fresh SSH
       session per command trips a brute-force signature after a handful of
       connections and the source IP is blocked for several minutes - it
       presents as tcp/22 going unreachable while ICMP still answers. Batching
       work into one session avoids it.
    2. Piping the script on stdin sidesteps shell quoting entirely, so
       heredocs, nested quotes and newlines survive intact.
    """
    with open(script_path, encoding="utf-8") as f:
        body = f.read()
    # get_pty=False: with a pty the script would be echoed back into stdout.
    stdin, stdout, stderr = c.exec_command("bash -s", get_pty=False, timeout=900)
    stdin.write(body)
    stdin.channel.shutdown_write()
    for line in iter(stdout.readline, ""):
        sys.stdout.write(line)
        sys.stdout.flush()
    rc = stdout.channel.recv_exit_status()
    err = stderr.read().decode(errors="replace")
    if err.strip():
        sys.stderr.write("--- stderr ---\n" + err)
    return rc


def run_sudo_script(c: paramiko.SSHClient, script_path: str, sudo_pass: str) -> int:
    """Run a local script remotely as root, over ONE session.

    `sudo -S` wants the password on stdin and `bash -s` wants the script there
    too, so they cannot share it. The script is therefore SFTP'd to a temp file
    first and stdin is reserved for the password.

    Also avoids the trap that bit this project twice: because the script body
    never appears in any process's argv, a `pkill -f <pattern>` inside it cannot
    match the shell that is running it. (`sudo bash -c "<text>"` puts the whole
    script in argv, which is how `pkill -f 'certbot certonly'` ended up killing
    its own parent.)
    """
    remote_tmp = "/tmp/portal_root_task.sh"
    sftp = c.open_sftp()
    try:
        sftp.put(script_path, remote_tmp)
        sftp.chmod(remote_tmp, 0o700)
    finally:
        sftp.close()
    try:
        return run_cmd(c, f"sudo -S -p '' bash {remote_tmp}", sudo_pass=sudo_pass)
    finally:
        try:
            c.exec_command(f"rm -f {remote_tmp}", timeout=30)
        except Exception:
            pass


def ensure_dir(sftp, path: str) -> None:
    cur = ""
    for part in path.strip("/").split("/"):
        cur += "/" + part
        try:
            sftp.stat(cur)
        except FileNotFoundError:
            sftp.mkdir(cur)


def push(c: paramiko.SSHClient, remote_dir: str, dry_run: bool) -> int:
    sftp = None if dry_run else c.open_sftp()
    if sftp:
        ensure_dir(sftp, remote_dir)
    count = 0
    for root, dirs, files in os.walk(PORTAL_DIR):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        rel = os.path.relpath(root, PORTAL_DIR).replace("\\", "/")
        rdir = remote_dir if rel == "." else posixpath.join(remote_dir, rel)
        if sftp:
            ensure_dir(sftp, rdir)
        for f in sorted(files):
            if f in SKIP_FILES or os.path.splitext(f)[1] in SKIP_EXT:
                continue
            rp = posixpath.join(rdir, f)
            shown = f if rel == "." else f"{rel}/{f}"
            if sftp:
                sftp.put(os.path.join(root, f), rp)
                if f.endswith(".sh") or (rel == "scripts" and f.endswith(".py")):
                    sftp.chmod(rp, 0o755)
            print(f"  {'would send' if dry_run else 'sent'}  {shown}")
            count += 1
    if sftp:
        sftp.close()
    print(f"\n{count} files {'to send' if dry_run else 'uploaded'} -> {remote_dir}")
    return 0


CHECK_SCRIPT = r"""
echo "host      : $(hostname)"
echo "os        : $(. /etc/os-release; echo $PRETTY_NAME)"
echo "clock     : $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "ntp sync  : $(timedatectl show -p NTPSynchronized --value 2>/dev/null)"
echo "ipv4      : $(ip -4 -br addr show scope global | tr -s ' ' | tr '\n' ' ')"
echo "portal    : $(systemctl is-active wifi-portal 2>/dev/null)"
echo "nginx     : $(systemctl is-active nginx 2>/dev/null)"
echo "freeradius: $(systemctl is-active freeradius 2>/dev/null)"
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="action", required=True)
    p_run = sub.add_parser("run"); p_run.add_argument("command")
    p_sudo = sub.add_parser("sudo"); p_sudo.add_argument("command")
    p_push = sub.add_parser("push"); p_push.add_argument("--dry-run", action="store_true")
    p_scr = sub.add_parser("script"); p_scr.add_argument("path")
    p_sscr = sub.add_parser("sudo-script"); p_sscr.add_argument("path")
    sub.add_parser("check")

    args = ap.parse_args()
    cfg = load_env()
    remote_dir = cfg.get("REMOTE_DIR", "/home/it_admin/portal")

    if args.action == "push" and args.dry_run:
        return push(None, remote_dir, dry_run=True)  # no connection needed

    c = connect(cfg)
    try:
        if args.action == "run":
            return run_cmd(c, args.command)
        if args.action == "sudo":
            return run_cmd(c, f"sudo -S -p '' bash -c {shell_quote(args.command)}",
                           sudo_pass=cfg.get("SSH_PASS"))
        if args.action == "push":
            return push(c, remote_dir, dry_run=False)
        if args.action == "script":
            return run_script(c, args.path)
        if args.action == "sudo-script":
            if not cfg.get("SSH_PASS"):
                sys.exit("sudo-script needs SSH_PASS in .remote.env")
            return run_sudo_script(c, args.path, cfg["SSH_PASS"])
        if args.action == "check":
            return run_cmd(c, CHECK_SCRIPT)
    finally:
        c.close()
    return 1


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


if __name__ == "__main__":
    sys.exit(main())
