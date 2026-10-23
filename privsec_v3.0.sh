#!/bin/bash

#  PRIVSEC - Privilege Escalation and Security Audit Tool
#  Version: 3.0
#  Author: Syrus

RUN_LINPEAS=false
INSTALL_OPENSCAP=false
SHOW_PROGRESS=true

for arg in "$@"; do
    case "$arg" in
        --openscap)
            INSTALL_OPENSCAP=true
            ;;
        --no-progress)
            SHOW_PROGRESS=false
            ;;
        --linpeas)
            RUN_LINPEAS=true
            ;;
        -h|--help)
            echo "PRIVSEC - Privilege Escalation Security Audit Tool v3.0"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --linpeas        Run LinPEAS after PRIVSEC scan"
            echo "  --openscap       Install OpenSCAP if missing, then run the audit"
            echo "  --no-progress    Disable interactive scan progress bar"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  sudo $0"
            echo "  sudo $0 --linpeas"
            echo "  sudo $0 --openscap"
            echo ""
            exit 0
            ;;
    esac
done

if [ "$INSTALL_OPENSCAP" = true ]; then
    if [ -r /etc/os-release ]; then
        . /etc/os-release
    fi
    if [ "${ID:-}" != "ubuntu" ] && [ "${ID:-}" != "debian" ]; then
        echo "[!] --openscap: automatic installation supports Ubuntu/Debian only." >&2
    elif command -v oscap >/dev/null 2>&1; then
        echo "[+] OpenSCAP already installed: $(command -v oscap)"
    elif [ "$(id -u)" -ne 0 ]; then
        echo "[!] Installation requires root. Run: sudo $0 --openscap" >&2
        exit 1
    elif ! command -v apt-get >/dev/null 2>&1; then
        echo "[!] apt-get not found; OpenSCAP installation skipped." >&2
    else
        echo "[+] Installing OpenSCAP from distribution repositories..."
        if apt-get update; then
            OPENSCAP_PACKAGE=""
            for candidate in openscap-scanner libopenscap8; do
                if apt-cache show "$candidate" >/dev/null 2>&1; then
                    OPENSCAP_PACKAGE="$candidate"
                    break
                fi
            done
            if [ -n "$OPENSCAP_PACKAGE" ] && DEBIAN_FRONTEND=noninteractive apt-get install -y "$OPENSCAP_PACKAGE" && command -v oscap >/dev/null 2>&1; then
                echo "[+] OpenSCAP installed successfully."
            else
                echo "[!] OpenSCAP installation unsuccessful; audit will continue without OVAL evaluation." >&2
            fi
        else
            echo "[!] apt update failed; audit will continue without OpenSCAP." >&2
        fi
    fi
fi

readonly YELLOW="\033[1;33m"
readonly CYAN="\033[1;36m"
readonly RED="\033[1;31m"
readonly GREEN="\033[1;32m"
readonly BLUE="\033[1;34m"
readonly MAGENTA="\033[1;35m"
readonly WHITE="\033[1;37m"
readonly GRAY="\033[0;90m"
readonly UNDERLINE="\033[4m"
readonly BOLD="\033[1m"
readonly DIM="\033[2m"
readonly RESET="\033[0m"

HIGH=0
MEDIUM=0
PASS=0
INFO=0 

EXCLUDE_PATHS="-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -path /run -prune -o -path /mnt -prune -o -path /media -prune -o -path /var/lib -prune -o -path /var/cache -prune -o -path /var/log -prune -o -path /tmp -prune -o -path /var/tmp -prune -o -path /dev/shm -prune -o -path /var/spool -prune -o -path /etc/dbus-1 -prune -o -path /usr/src -prune -o -path /usr/lib -prune -o"

GTFO_BINARIES=(
    "2g" "a2p" "a52dec" "agetty" "alpine" "anarres" "ansible-playbook" "apg" "apt" 
    "apt-get" "arp" "arpspoof" "as" "ascii" "at" "atob" "awk" "base32" "base64" 
    "bash" "bpftrace" "busybox" "byobu" "c89" "c99" "capsh" "cat" "ccat" "cdist" 
    "chfn" "chmod" "chown" "chroot" "ciftop" "cksum" "cmp" "cobc" "column" 
    "comm" "composer" "cp" "cpan" "csh" "csplit" "csvtool" "curl" "cut" "dash" 
    "date" "dc" "dd" "debug" "dialog" "diff" "dig" "distcc" "dmesg" "dmsetup" 
    "docker" "dos2unix" "ed" "efax" "emacs" "env" "eqn" "ethtool" "ex" "expect" 
    "facter" "file" "find" "fish" "flock" "fmt" "fold" "fping" "ftp" "gawk" 
    "gcc" "gdb" "gem" "genisoimage" "gimp" "git" "go" "gofish" "gpasswd" "greadelf" 
    "grep" "gsettings" "gzip" "hd" "head" "hexyl" "hurl" "iconv" "iftop" "install" 
    "ionice" "ip" "irb" "ispell" "jjs" "joe" "join" "jq" "jsh" "kermit" "kscript" 
    "ksh" "ksshell" "larn" "last" "less" "lessc" "ln" "logsave" "look" "ltrace" 
    "lua" "make" "man" "mawk" "more" "moserial" "mount" "mpclient" "msfconsole" 
    "msgfmt" "mtools" "mtr" "multishell" "nano" "nasm" "nc" "netcat" "nice" 
    "nl" "nmap" "node" "nohup" "nroff" "objdump" "openvpn" "openssl" "pandoc" 
    "paste" "patchelf" "pdb" "pedal" "perl" "perlbug" "pg" "php" "pic" "pip" 
    "pkexec" "pr" "pry" "ps" "pview" "python" "python2" "python3" "rake" "rc" 
    "readelf" "red" "rename" "restic" "rlwrap" "rsh" "rsync" "ruby" "run-mailcap" 
    "sash" "scp" "screen" "sed" "service" "setarch" "sftp" "sh" "shell" "shuf" 
    "smbclient" "socat" "soelim" "sort" "sqlite3" "ss" "ssh" "stat" "strace" 
    "strings" "systemctl" "sysv-rc-conf" "tac" "tail" "tar" "taskset" "tclsh" 
    "tee" "telnet" "tftp" "time" "timeout" "tmate" "tmux" "top" "torify" 
    "troff" "ul" "unexpand" "uniq" "unshare" "unzip" "vi" "vigr" "view" "vim" 
    "w3m" "wall" "watch" "wget" "whois" "wireshark" "xargs" "xclip" "xidel" 
    "yash" "yum" "zip" "zip_v3" "zsh"
)

IGNORE_SUID_SGID=(
    "/bin/mount" "/bin/umount" "/usr/bin/passwd" "/usr/bin/chfn" 
    "/usr/bin/chsh" "/usr/bin/newgrp" "/usr/bin/gpasswd" "/usr/bin/su"
    "/usr/bin/ssh-agent" "/usr/bin/sudo" "/usr/bin/pkexec" "/usr/bin/fusermount3" 
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper" "/usr/libexec/polkit-agent-helper-1" 
    "/usr/lib/openssh/ssh-keysign" "/usr/lib/eject/dmcrypt-get-device"
    "/usr/bin/mount" "/usr/bin/umount"
    "/usr/bin/ssh-agent" "/usr/bin/crontab" "/usr/bin/chage" "/usr/bin/expiry" 
    "/usr/sbin/unix_chkpwd" "/usr/sbin/pam_extrausers_chkpwd" "/usr/lib/x86_64-linux-gnu/utempter/utempter"
)

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo -e "  ╔═══════════════════════════════════════════════════════════════════════╗"
    echo -e "  ║                                                                       ║"
    echo -e "  ║   ${WHITE}██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗${CYAN}                ║"
    echo -e "  ║   ${WHITE}██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝${CYAN}                ║"
    echo -e "  ║   ${WHITE}██████╔╝██████╔╝██║██║   ██║███████╗█████╗  ██║     ${CYAN}                ║"
    echo -e "  ║   ${WHITE}██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝╚════██║██╔══╝  ██║     ${CYAN}                ║"
    echo -e "  ║   ${WHITE}██║     ██║  ██║██║ ╚████╔╝ ███████║███████╗╚██████╗${CYAN}                ║"
    echo -e "  ║   ${WHITE}╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝${CYAN}                ║"
    echo -e "  ║   ${WHITE}Made by Syrus${CYAN}                                                       ║"
	echo -e "  ║                                                                       ║"
    echo -e "  ║   ${YELLOW}Privilege Escalation and Security Audit Tool ${DIM}v3.0${RESET}${CYAN}                   ║"
    echo -e "  ║   ${GRAY}Automated Security Assessment & Vulnerability Analysis${CYAN}              ║"
    echo -e "  ║                                                                       ║"
    echo -e "  ╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  ${GRAY}Scan initiated: ${WHITE}$(date '+%Y-%m-%d %H:%M:%S')${RESET}\n"
}

SCAN_TOTAL_SECTIONS=27
SCAN_SECTIONS_STARTED=0
SCAN_START_EPOCH=$(date +%s)
PROGRESS_ACTIVE=false
PROGRESS_PID=""
PROGRESS_STATE_DIR=""

progress_restore_terminal() {
    [ "$PROGRESS_ACTIVE" = true ] || return 0
    PROGRESS_ACTIVE=false
    # Close the pipe first so the single terminal renderer can flush output,
    # remove its scroll region and position the prompt correctly.
    exec 1>&3 2>&4
    exec 3>&- 4>&-
    if [ -n "$PROGRESS_PID" ]; then
        wait "$PROGRESS_PID" 2>/dev/null || true
        PROGRESS_PID=""
    fi
    if [ -n "$PROGRESS_STATE_DIR" ]; then
        rm -rf -- "$PROGRESS_STATE_DIR"
        PROGRESS_STATE_DIR=""
    fi
}

progress_setup_terminal() {
    [ "$SHOW_PROGRESS" = true ] || return 0
    [ -t 1 ] && [ -t 2 ] || return 0
    [ "${TERM:-dumb}" != dumb ] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    local rows cols
    rows=$(tput lines 2>/dev/null) || return 0
    cols=$(tput cols 2>/dev/null) || return 0
    [[ "$rows" =~ ^[0-9]+$ && "$cols" =~ ^[0-9]+$ ]] || return 0
    [ "$rows" -ge 8 ] && [ "$cols" -ge 62 ] || return 0
    PROGRESS_STATE_DIR=$(mktemp -d "${TMPDIR:-/tmp}/privsec-progress.XXXXXXXX") || return 0
    mkfifo "$PROGRESS_STATE_DIR/output" || { rm -rf "$PROGRESS_STATE_DIR"; return 0; }
    printf '0\nStarting audit\n' > "$PROGRESS_STATE_DIR/state"
    # Only the renderer writes to the terminal. This prevents the timer from
    # racing with the scan's output and appearing between report sections.
    exec 3>&1 4>&2
    cat > "$PROGRESS_STATE_DIR/renderer.py" <<'PYRENDER'
import os, sys, time, select, shutil
state, total, started = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
out = sys.stdout.buffer
fd = sys.stdin.fileno()
last_size = (0, 0)
last_draw = 0

def write(data):
    out.write(data)
    out.flush()

def size():
    s = shutil.get_terminal_size((80, 24))
    return s.lines, s.columns

def footer():
    global last_size, last_draw
    rows, cols = size()
    if rows < 8 or cols < 62:
        return
    if (rows, cols) != last_size:
        write(f'\x1b[r\x1b[1;{rows-1}r'.encode())
        last_size = (rows, cols)
    try:
        with open(state, encoding='utf-8') as f:
            completed = int(f.readline().strip())
            label = f.readline().strip()
    except (OSError, ValueError):
        completed, label = 0, 'Starting audit'
    pct = min(100, max(0, completed * 100 // total))
    fill = pct * 24 // 100
    elapsed = max(0, int(time.time()) - started)
    h, rem = divmod(elapsed, 3600)
    m, sec = divmod(rem, 60)
    status = f' PRIVSEC [{"█" * fill}{"░" * (24-fill)}] {pct:3d}% | {h:02d}:{m:02d}:{sec:02d} | {label}'
    # Render exclusively in the reserved bottom row, restoring the cursor.
    status = status[:max(0, cols-1)]
    write(f'\x1b7\x1b[{rows};1H\x1b[2K\x1b[1;36m{status}\x1b[0m\x1b8'.encode())
    last_draw = time.monotonic()

try:
    rows, cols = size()
    if rows >= 8:
        write(f'\x1b[1;{rows-1}r'.encode())
    footer()
    while True:
        ready, _, _ = select.select([fd], [], [], 0.25)
        if ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            write(chunk)
        if time.monotonic() - last_draw >= 1.0:
            footer()
finally:
    rows, _ = size()
    write(f'\x1b[r\x1b[{rows};1H\x1b[2K\n'.encode())
PYRENDER
    python3 -u "$PROGRESS_STATE_DIR/renderer.py" "$PROGRESS_STATE_DIR/state" "$SCAN_TOTAL_SECTIONS" "$SCAN_START_EPOCH" < "$PROGRESS_STATE_DIR/output" >&3 2>&4 &
    PROGRESS_PID=$!
    # Redirect both report streams through the same renderer.
    exec 1> "$PROGRESS_STATE_DIR/output" 2>&1
    PROGRESS_ACTIVE=true
    trap 'progress_restore_terminal' EXIT
    trap 'progress_restore_terminal; exit 130' INT
    trap 'progress_restore_terminal; exit 143' TERM
}

scan_progress() {
    [ "$PROGRESS_ACTIVE" = true ] || return 0
    local completed="$1" label="$2" tmp
    tmp="$PROGRESS_STATE_DIR/state.$$"
    printf '%s\n%s\n' "$completed" "$label" > "$tmp" && mv -f -- "$tmp" "$PROGRESS_STATE_DIR/state"
}

progress_setup_terminal
scan_progress 0 'Starting audit'

section() {
    if [ "$PROGRESS_ACTIVE" = true ]; then
        if [ "$SCAN_SECTIONS_STARTED" -gt 0 ]; then
            scan_progress "$SCAN_SECTIONS_STARTED" "Sections: $SCAN_SECTIONS_STARTED/$SCAN_TOTAL_SECTIONS"
        fi
        SCAN_SECTIONS_STARTED=$((SCAN_SECTIONS_STARTED + 1))
    fi
    echo -e "\n${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
    printf "${CYAN}║ ${WHITE}${BOLD}%-75s${RESET}${CYAN}   ║${RESET}\n" "$1"
    echo -e "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"
}

item() {
    local level="$1"
    local text="$2"
    local path_to_highlight="$3"
    local ICON_COLOR="" 
    local ICON=""
    
    case "$level" in
        HIGH)    
            ICON_COLOR="$RED"
            ICON="●"
            HIGH=$((HIGH+1))
            ;;
        MEDIUM)  
            ICON_COLOR="$YELLOW"
            ICON="◐"
            MEDIUM=$((MEDIUM+1))
            ;;
        PASS)     
            ICON_COLOR="$GREEN"
            ICON="○"
            PASS=$((PASS+1))
            ;;
        INFO)    
            ICON_COLOR="$CYAN"
            ICON="ℹ"
            INFO=$((INFO+1))
            ;;
        *)       
            ICON_COLOR="$CYAN"
            ICON="ℹ"
            level="INFO"
            ;;
    esac

    if [ -n "$path_to_highlight" ]; then
        echo -e "  ${ICON_COLOR}${BOLD}${ICON}${RESET} ${GRAY}${text}${RESET}"
    else
        echo -e "  ${ICON_COLOR}${BOLD}${ICON}${RESET} ${GRAY}${text}${RESET}"
    fi
}

is_ignored() {
    local path="$1"
    for safe in "${IGNORE_SUID_SGID[@]}"; do
        if [ "$path" == "$safe" ]; then
            return 0
        fi
    done
    return 1
}

# Evaluate actual discretionary permissions, not root's ability to override them.
# Root-owned files writable only by root are not privilege-escalation findings.
privsec_unprivileged_writable() {
    local target="$1" mode owner group acl
    [ -e "$target" ] || return 1
    mode=$(stat -Lc '%a' -- "$target" 2>/dev/null) || return 1
    owner=$(stat -Lc '%u' -- "$target" 2>/dev/null) || return 1
    group=$(stat -Lc '%g' -- "$target" 2>/dev/null) || return 1
    # Any other-user write bit, or non-root group write bit.
    if (( (8#$mode & 2) != 0 )); then return 0; fi
    if (( (8#$mode & 16) != 0 )) && [ "$group" != 0 ]; then return 0; fi
    # ACLs can grant write access without changing the traditional mode bits.
    if command -v getfacl >/dev/null 2>&1; then
        acl=$(getfacl -cp -- "$target" 2>/dev/null) || return 1
        if printf '%s\n' "$acl" | awk -F: '
            /^user:[^:]+:/ && $2 != "root" && $3 ~ /w/ { found=1 }
            /^group:[^:]+:/ && $2 != "root" && $3 ~ /w/ { found=1 }
            END { exit !found }
        '; then return 0; fi
    fi
    return 1
}

print_banner

section "0x01 │ System Context & Environment"

item INFO "User: $(id -un) (UID: $(id -u))"
item INFO "Groups: $(id -Gn)"
item INFO "Hostname: $(hostname)"
item INFO "Kernel: $(uname -r)"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    item INFO "Distribution: $PRETTY_NAME"
elif [ -f /etc/issue ]; then
    item INFO "Distribution: $(head -n 1 /etc/issue | sed 's/\\n//g;s/\\l//g')"
else
    item INFO "Distribution: Unknown"
fi

section "0x02 │ SUID Binaries Analysis"

SUID=$(find / $EXCLUDE_PATHS -path /snap -prune -o -perm -4000 -type f -print 2>/dev/null | sort)
FOUND_SUID=0

if [ -n "$SUID" ]; then
    while read -r f; do
        if is_ignored "$f"; then
            continue
        fi
        
        IS_GTFO=0
        BIN_NAME=$(basename "$f")
        
        for gtfo in "${GTFO_BINARIES[@]}"; do
            if [ "$BIN_NAME" == "$gtfo" ]; then
                item HIGH "SUID/GTFO Found: $f (GTFOBins: https://gtfobins.github.io)"
                IS_GTFO=1
                FOUND_SUID=1
                break
            fi
        done
        
        if [ "$IS_GTFO" -eq 0 ]; then
            SUID_PACKAGE=""
            if command -v dpkg-query >/dev/null 2>&1; then
                SUID_PACKAGE=$(dpkg-query -S -- "$f" 2>/dev/null | head -n 1 | cut -d: -f1)
            fi
            if [ -n "$SUID_PACKAGE" ]; then
                if command -v dpkg >/dev/null 2>&1 && dpkg -V "$SUID_PACKAGE" 2>/dev/null | grep -F -- "$f" >/dev/null; then
                    item MEDIUM "Packaged SUID with package verification mismatch: $f ($SUID_PACKAGE; review changes)"
                else
                    item INFO "Packaged SUID: $f ($SUID_PACKAGE; expected use must be verified)"
                fi
            else
                item MEDIUM "Unowned/unrecognized SUID: $f (Manual Analysis Required)"
            fi
            FOUND_SUID=1
        fi
    done <<< "$SUID"
fi

if [ "$FOUND_SUID" -eq 0 ]; then
    item PASS "No exploitable SUID binaries detected"
fi

section "0x03 │ SGID Binaries Analysis"

SGID=$(find / $EXCLUDE_PATHS -path /snap -prune -o -perm -2000 -type f -print 2>/dev/null | sort)
FOUND_SGID=0

if [ -n "$SGID" ]; then
    while read -r f; do
        if is_ignored "$f"; then
            continue
        fi
        
        item MEDIUM "Unusual SGID: $f (Manual Verification Needed)"
        FOUND_SGID=1
    done <<< "$SGID"
fi

if [ "$FOUND_SGID" -eq 0 ]; then
    item PASS "No unusual SGID binaries found"
fi

section "0x04 │ Linux Capabilities Audit"

CAP=$(getcap -r / 2>/dev/null | grep -vE "/snap/|/usr/lib|/usr/src")
FOUND_CAP=0

if [ -n "$CAP" ]; then
    while read -r c; do
        if echo "$c" | grep -E 'cap_setuid|cap_dac_override' | grep -q '=(e'; then
            item HIGH "High-Risk Capability: $c (Root/File Access Possible)"
            FOUND_CAP=1
        elif echo "$c" | grep -q '=(e'; then
            item MEDIUM "Effective Capability: $c (Investigation Required)"
            FOUND_CAP=1
        fi
    done <<< "$CAP"
fi

if [ "$FOUND_CAP" -eq 0 ]; then
    item PASS "No high-risk capabilities detected"
fi

section "0x05 │ World-Writable Files"

CRITICAL_WW_PATHS="/etc/ /usr/local/bin/ /opt/ /var/www/ /var/mail /root"
WWF=$(find $CRITICAL_WW_PATHS -type f -perm -0002 2>/dev/null | grep -v "/snap/")

if [ -n "$WWF" ]; then
    while read -r f; do
        if echo "$f" | grep -E '\.bashrc|\.profile|\.service|\.conf|\.sh'; then
            item HIGH "WW Config/Script: $f (Persistence Vector)"
        else
            item MEDIUM "WW File: $f (Critical Directory)"
        fi
    done <<< "$WWF"
else
    item PASS "No world-writable files in critical paths"
fi

section "0x06 │ World-Writable Directories"

FOUND_WWD=0

WWD_HIGH=$(find / $EXCLUDE_PATHS -path /snap -prune -o -type d -perm -0003 -print 2>/dev/null)
if [ -n "$WWD_HIGH" ]; then
    while read -r d; do
        if echo "$d" | grep -E '/tmp|/var/tmp|/var/crash|/var/lib|/var/cache|/dev/shm' >/dev/null; then
             continue 
        else
            item HIGH "WW Directory (777): $d (Injection/Execution Risk)"
            FOUND_WWD=1
        fi
    done <<< "$WWD_HIGH"
fi

WWD_MEDIUM=$(find / $EXCLUDE_PATHS -path /snap -prune -o -type d -perm -0002 ! -perm -0001 -print 2>/dev/null)
if [ -n "$WWD_MEDIUM" ]; then
    while read -r d; do
        if echo "$d" | grep -E '/tmp|/var/tmp|/var/crash|/var/lib|/var/cache|/dev/shm' >/dev/null; then
             continue 
        else
            item MEDIUM "WW Directory: $d (File Injection Possible)"
            FOUND_WWD=1
        fi
    done <<< "$WWD_MEDIUM"
fi

if [ "$FOUND_WWD" -eq 0 ]; then
    item PASS "No unusual world-writable directories detected"
fi

if [ "$FOUND_WWD" -ne 0 ] && [ -d "/var/www/html/mysite.local" ]; then
    PERMS=$(ls -ld /var/www/html/mysite.local 2>/dev/null)
    WEB_USER=$(ps aux | grep -E 'apache|nginx|httpd' | grep -v grep | awk '{print $1}' | sort -u | head -n 1)
    
    item INFO "Web Directory Details:"
    item INFO "  → Permissions: $PERMS"
    if [ -n "$WEB_USER" ]; then
        item INFO "  → Web Server User: $WEB_USER (RCE Possible)"
    else
        item INFO "  → Web Server User: Not detected (RCE Possible)"
    fi
fi

section "0x07 │ Critical File Permissions"

SHADOW=$(ls -l /etc/shadow 2>/dev/null)
PASSWD=$(ls -l /etc/passwd 2>/dev/null)

if [ -f /etc/shadow ] && find /etc/shadow -maxdepth 0 -perm /0004 -print -quit 2>/dev/null | grep -q .; then
    item HIGH "/etc/shadow readable by user (Permission Failure)"
else
    item PASS "/etc/shadow → $SHADOW"
fi

if privsec_unprivileged_writable /etc/passwd; then
    item HIGH "/etc/passwd writable (Critical Permission Failure)"
else
    item PASS "/etc/passwd → $PASSWD (Readable - Expected)"
fi

section "0x08 │ Cron Jobs Security"

CRON_FILES=$(grep -R "." /etc/cron* /var/spool/cron/crontabs 2>/dev/null | cut -d: -f1 | sort -u)
FOUND_CRON=0

for c in $CRON_FILES; do
    if privsec_unprivileged_writable "$c"; then
        item HIGH "Writable Cron File: $c (Persistence Possible)"
        FOUND_CRON=1
    fi
done

if [ "$FOUND_CRON" -eq 0 ]; then
    item PASS "No writable cron files detected"
fi

section "0x09 │ Systemd Services Audit"

SYSTEMD=$(systemctl list-unit-files --type=service --no-pager 2>/dev/null | awk '{print $1}')
FOUND_SYSTEMD=0

for s in $SYSTEMD; do
    FILE=$(systemctl show -p FragmentPath "$s" 2>/dev/null | cut -d= -f2)
    
    if [ -n "$FILE" ] && ! echo "$FILE" | grep -q "/snap/"; then
        FINAL_FILE=$(readlink -f "$FILE" 2>/dev/null)

        if [ -f "$FILE" ] && privsec_unprivileged_writable "$FILE"; then
            item HIGH "Writable Service: $FILE (Root Vector Possible)"
            FOUND_SYSTEMD=1
        elif [ ! -f "$FILE" ] && privsec_unprivileged_writable "$FILE"; then
             if [ "$FINAL_FILE" == "/dev/null" ]; then
                 continue 
             fi
             
             FILE_TYPE=$(file -b "$FILE" 2>/dev/null)
             item MEDIUM "Writable Service: $FILE (Type: $FILE_TYPE)"
             FOUND_SYSTEMD=1
        fi
    fi
done

if [ "$FOUND_SYSTEMD" -eq 0 ]; then
    item PASS "No writable systemd services found"
fi

section "0x0A │ PATH Hijacking Analysis"

FOUND_PATH=0
IFS=':' read -ra P <<< "$PATH"

for d in "${P[@]}"; do
    if [ -d "$d" ] && privsec_unprivileged_writable "$d"; then
        item HIGH "Writable PATH Directory: $d (Hijacking Possible)"
        FOUND_PATH=1
    fi
done

if [ "$FOUND_PATH" -eq 0 ]; then
    item PASS "No writable PATH directories detected"
fi

section "0x0B │ Dynamic Linker Configuration"

if [ -n "$LD_PRELOAD" ]; then
    item HIGH "LD_PRELOAD defined: $LD_PRELOAD (Code Injection Possible)"
elif [ -n "$LD_AUDIT" ]; then
    item HIGH "LD_AUDIT defined: $LD_AUDIT (Code Injection Possible)"
else
    item PASS "No LD_* environment variables defined"
fi

section "0x0C │ Kernel Vulnerability Assessment"

KERNEL=$(uname -r)

case "$KERNEL" in
    *3.13*|*3.2*|*2.6.3*|*4.4.0-21*|*5.4.0-*)
        item HIGH "Kernel potentially vulnerable: $KERNEL (Known Public Exploits)"
        ;;
    *)
        item PASS "No known critical kernel vulnerabilities"
        ;;
esac

section "0x0D │ Shared Library Security"

WSO=$(find / $EXCLUDE_PATHS -type f -name "*.so*" -perm -0002 -print 2>/dev/null)

if [ -n "$WSO" ]; then
    while read -r lib; do
        item HIGH "World-Writable Library: $lib (Code Injection Risk)"
    done <<< "$WSO"
else
    item PASS "No world-writable libraries found"
fi

section "0x0E │ NFS Security Configuration"

if mount | grep -q "nfs"; then
    SHOW=$(grep "no_root_squash" /etc/exports 2>/dev/null)
    if [ -n "$SHOW" ]; then
        item HIGH "NFS no_root_squash: $SHOW (Remote Escalation Possible)"
    else
        item PASS "NFS active with secure root-squash configuration"
    fi
else
    item PASS "No NFS mounts detected"
fi

section "0x0F │ Credential & Configuration Analysis"

CREDENTIAL_TERMS='PASSWD|PASSWORD|SECRET|API_KEY|APIKEY|TOKEN|auth_key|user=|pass=|key=|secret=|connect_string|database_url'
SENSITIVE_PATHS="/etc /var/www /opt" 

SENSITIVE_FILES=$(find $SENSITIVE_PATHS -path /etc/dbus-1 -prune -o -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.yaml" -o -name "*.yml" -o -name "*.ini" -o -name "*.json" -o -name "*ssh*" -o -name "*id_rsa*" \) -readable -print 2>/dev/null \
    | grep -vE '/usr/(lib|share|bin)|/var/(lib|cache|log)' \
    | grep -vE 'cloud/|debconf.conf|fwupd/|hdparm.conf|iscsi/|libblockdev/|lvm/|modprobe.d/|overlayroot.conf|pam.d/|polkit-1/|rsyslog.d/|security/|sos/|sudo.conf|sudo_logsrvd.conf|sysctl.d/|vmware-tools/|sshd-keygen|tpm2-tss/fapi-profiles/' \
    | sort -u)

FOUND_SENSITIVE=0
if [ -n "$SENSITIVE_FILES" ]; then
    while read -r f; do
        if grep -qE "$CREDENTIAL_TERMS" "$f" 2>/dev/null; then
            item INFO "$f (Possible Credentials - Verify Manually)"
            FOUND_SENSITIVE=1
        fi
    done <<< "$SENSITIVE_FILES"
fi

if [ "$FOUND_SENSITIVE" -eq 0 ]; then
    item PASS "No obvious credential files detected"
fi

section "0x10 │ Data Exfiltration Opportunities"

LOOT_PATTERNS=" -name *.bak -o -name *.zip -o -name *.tar -o -name *.tar.gz -o -name *.sql -o -name *.kdbx -o -name .env -o -name web.config -o -name settings.py -o -name config.php -o -name database.yml -o -name config.py -o -name *.key -o -name id_rsa -o -name *.pem -o -name *credentials* -o -name *secret* -o -name .mysql_history "

LOOT_FILES=$(find / $EXCLUDE_PATHS -path /home -prune -o -readable -type f \( $LOOT_PATTERNS \) -print 2>/dev/null \
    | grep -vE '/snap/|/usr/share/doc|/usr/share/man|/etc/pki/|/etc/ssl/certs/|/etc/pollinate/|/usr/share/bash-completion/|/usr/share/dns/root.key|/usr/share/fwupd/|/usr/share/usb_modeswitch/|/usr/share/polkit-1/|/etc/.resolv.conf.systemd-resolved.bak' \
    | sort -u)

FOUND_LOOT=0
if [ -n "$LOOT_FILES" ]; then
    while read -r f; do
        item INFO "$f (Potential Sensitive Data)"
        FOUND_LOOT=1
    done <<< "$LOOT_FILES"
fi

if [ "$FOUND_LOOT" -eq 0 ]; then
    item PASS "No common loot files detected"
fi

section "0x11 │ Group Permission Analysis"

GNAMES=$(id -Gn 2>/dev/null | tr ' ' '|')
FOUND_GWWF=0

if [ -n "$GNAMES" ]; then
    GWWF=$(find /etc /var/www /opt -path /home -prune -o -type f -perm -0020 2>/dev/null | xargs -r ls -ld 2>/dev/null)
    
    if [ -n "$GWWF" ]; then
        while read -r line; do
            GROUP_OWNER=$(echo "$line" | awk '{print $4}')
            FILE_PATH=$(echo "$line" | awk '{print $NF}')
            
            if echo "$GNAMES" | grep -qE "(^|\|)$GROUP_OWNER(\||$)"; then
                item HIGH "Group-Writable: $FILE_PATH (Group: $GROUP_OWNER)"
                FOUND_GWWF=1
            fi
        done <<< "$GWWF"
    fi
fi

if [ "$FOUND_GWWF" -eq 0 ]; then
    item PASS "No critical group-writable files found"
fi

section "0x12 │ Filesystem Mount Security"

RISKY_FS_TYPES='nfs|cifs|smb|squashfs|fuse'
EXCLUDED_MOUNTS='(boot|dev|proc|sys|run|tmp|snap)'

FSTAB_RISK=$(grep -E "$RISKY_FS_TYPES" /etc/fstab 2>/dev/null | grep -v 'nosuid,nodev' | grep -vE "$EXCLUDED_MOUNTS")
MOUNT_RISK=$(mount | grep -E "$RISKY_FS_TYPES" | grep -v 'nosuid,nodev' | grep -vE "$EXCLUDED_MOUNTS")

FOUND_MOUNT=0
if [ -n "$FSTAB_RISK" ]; then
    item MEDIUM "FSTAB: Insecure mount options (Missing nosuid/nodev)"
    FOUND_MOUNT=1
fi
if [ -n "$MOUNT_RISK" ]; then
    item MEDIUM "Active Mount: Insecure options (Missing nosuid/nodev)"
    FOUND_MOUNT=1
fi

if [ "$FOUND_MOUNT" -eq 0 ]; then
    item PASS "All mounts have secure restrictions"
fi

section "0x13 │ SSH Key Management Audit"

CURRENT_USER=$(id -un)
FOUND_SSH=0

for HOME_DIR in /home/*; do
    USER=$(basename "$HOME_DIR")
    
    if [ "$USER" != "$CURRENT_USER" ] && [ -d "$HOME_DIR/.ssh" ]; then
        AUTH_KEYS="$HOME_DIR/.ssh/authorized_keys"
        
        if [ -f "$AUTH_KEYS" ] && privsec_unprivileged_writable "$AUTH_KEYS"; then
            item HIGH "Writable authorized_keys: $AUTH_KEYS (User: $USER - SSH Key Injection)"
            FOUND_SSH=1
        fi
    fi
done

if [ "$FOUND_SSH" -eq 0 ]; then
    item PASS "No writable SSH authorized_keys files"
fi

section "0x14 │ Network Share Configuration"

SMB_CONF='/etc/samba/smb.conf'
FOUND_SMB=0

if [ -f "$SMB_CONF" ]; then
    WIDE_LINKS=$(grep -i 'wide links' "$SMB_CONF" 2>/dev/null | grep -v ';' | grep -i 'yes')
    if [ -n "$WIDE_LINKS" ]; then
        item HIGH "Samba Wide Links Enabled (Symlink Attack Vector)"
        FOUND_SMB=1
    fi

    GUEST_WRITE=$(grep -E 'guest ok\s*=\s*yes' -A 5 "$SMB_CONF" 2>/dev/null | grep -E 'writable\s*=\s*yes|writeable\s*=\s*yes' | head -n 1)
    if [ -n "$GUEST_WRITE" ]; then
        item MEDIUM "Guest Share Writable (File Injection Possible)"
        FOUND_SMB=1
    fi
    
    SMB_CREDS=$(find / -maxdepth 3 -name ".smbcredentials" -readable 2>/dev/null)
    if [ -n "$SMB_CREDS" ]; then
        item HIGH ".smbcredentials readable: $SMB_CREDS (Network Passwords)"
        FOUND_SMB=1
    fi
    
    if [ "$FOUND_SMB" -eq 0 ]; then
        item PASS "Samba configuration secure"
    fi
else
    item PASS "Samba not configured"
fi



# Additional read-only software version assessments
section "0x15 │ React2Shell - Installed Application Versions"
if command -v python3 >/dev/null 2>&1; then
    while IFS='|' read -r status description; do
        case "$status" in
            HIGH|MEDIUM|PASS|INFO) item "$status" "$description" ;;
        esac
    done < <(python3 - <<'PYREACT'
import json, os, re
from pathlib import Path
roots = ['/var/www', '/opt', '/srv', '/home']
packages = {'next', 'react-server-dom-webpack', 'react-server-dom-parcel', 'react-server-dom-turbopack'}
found = set()
def numeric(v):
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:[-+]([^\s]+))?$', str(v))
    return (int(m[1]), int(m[2]), int(m[3]), m[4]) if m else None
def check(name, version, path):
    k = (name, version, path)
    if k in found: return
    found.add(k)
    v = numeric(version)
    if not v:
        print(f'INFO|{name} {version} at {path}: non-exact version; cannot assess')
        return
    major, minor, patch, pre = v
    if pre:
        print(f'INFO|{name} {version} at {path}: prerelease; manual advisory comparison required')
        return
    vulnerable = False
    if name == 'next':
        fixes = {(15,0):5,(15,1):9,(15,2):6,(15,3):6,(15,4):8,(15,5):7,(16,0):7}
        if major in (15,16):
            vulnerable = patch < fixes[(major,minor)] if (major,minor) in fixes else (major==15 and minor<6) or (major==16 and minor==0)
            if (major==15 and minor>=6) or (major==16 and minor>=1): vulnerable=False
    else:
        vulnerable = (major,minor,patch) in {(19,0,0),(19,1,0),(19,1,1),(19,2,0)}
    if vulnerable: print(f'MEDIUM|React2Shell CVE-2025-55182: {name} {version} at {path} potentially affected')
    else: print(f'INFO|{name} {version} at {path}: not in known stable React2Shell affected set (other CVEs not assessed)')
for root in roots:
    if not os.path.isdir(root): continue
    for directory, dirs, files in os.walk(root):
        depth = len(Path(directory).relative_to(root).parts)
        dirs[:] = [d for d in dirs if d not in ('.git','.cache','vendor','.next','dist','build') and (d!='node_modules' or depth < 5)] if depth < 6 else []
        if depth > 6: continue
        if 'package-lock.json' in files:
            try:
                with open(os.path.join(directory,'package-lock.json')) as f: data=json.load(f)
                for key, value in data.get('packages',{}).items():
                    name = key.rsplit('node_modules/',1)[-1]
                    if name in packages and isinstance(value,dict) and value.get('version'): check(name,str(value['version']),directory)
            except (OSError,ValueError,TypeError): pass
        if 'package.json' in files and '/node_modules/' in directory:
            name = directory.rsplit('/node_modules/',1)[-1]
            if name in packages:
                try:
                    with open(os.path.join(directory,'package.json')) as f: data=json.load(f)
                    if data.get('version'): check(name,str(data['version']),directory)
                except (OSError,ValueError,TypeError): pass
if not found: print('INFO|No exact installed React Server Components / Next.js versions found in common paths')
PYREACT
)
else
    item INFO "Python3 unavailable: React2Shell package discovery skipped"
fi

section "0x16 │ PHP2Shell - Installed PHP Packages"
PHP_FOUND=0
if command -v dpkg-query >/dev/null 2>&1; then
    while IFS='|' read -r pkg version; do
        [ -n "$pkg" ] || continue
        PHP_FOUND=1
        fixed=""
        case "${VERSION_ID:-}:$pkg" in
            22.04:php8.1*) fixed="8.1.2-1ubuntu2.28" ;;
            24.04:php8.3*) fixed="8.3.6-0ubuntu0.24.04.13" ;;
            26.04:php8.5*) fixed="8.5.4-0ubuntu1.5" ;;
            26.10:php8.5*) fixed="8.5.9-0ubuntu2.1" ;;
        esac
        if [ -n "$fixed" ] && command -v dpkg >/dev/null 2>&1; then
            if dpkg --compare-versions "$version" lt "$fixed"; then
                item HIGH "PHP2Shell CVE-2026-109618/109619: $pkg $version below Ubuntu fix $fixed"
            else
                item PASS "PHP2Shell: $pkg $version meets Ubuntu fix $fixed"
            fi
        else
            item INFO "PHP2Shell: $pkg $version - distro-specific backport status not verified"
        fi
    done < <(dpkg-query -W -f='${binary:Package}|${Version}\n' 'php[0-9]*' 'libapache2-mod-php[0-9]*' 2>/dev/null | grep -E '^(php[0-9]+\.[0-9]+|libapache2-mod-php[0-9]+\.[0-9]+)(:|\||-)' | sort -u)
fi
if [ "$PHP_FOUND" -eq 0 ]; then item INFO "No versioned PHP Debian packages detected; custom/container runtimes not assessed"; fi

section "0x17 │ Security Updates - Kernel, Apache, Nginx and System"
if command -v dpkg-query >/dev/null 2>&1; then
    for pkg in apache2 nginx nginx-core nginx-full openssh-server openssl sudo policykit-1 polkitd libc6 curl libcurl4 samba docker.io containerd runc; do
        installed=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null) || continue
        [ -n "$installed" ] || continue
        item INFO "$pkg installed: $installed (CVE-specific patch status not established)"
        if command -v apt-cache >/dev/null 2>&1; then
            candidate=$(apt-cache policy "$pkg" 2>/dev/null | awk '/Candidate:/{print $2;exit}')
            if [ -n "$candidate" ] && [ "$candidate" != '(none)' ] && dpkg --compare-versions "$candidate" gt "$installed"; then
                item MEDIUM "$pkg: newer repository candidate $candidate available (not necessarily security-related)"
            fi
        fi
    done
    item INFO "Running kernel: $(uname -r); package fixes and livepatch state require vendor advisory correlation"
    if command -v dpkg-query >/dev/null 2>&1; then
        running_pkg=$(dpkg-query -W -f='${Version}' "linux-image-$(uname -r)" 2>/dev/null || true)
        [ -n "$running_pkg" ] && item INFO "Running kernel package version: $running_pkg"
    fi
else
    item INFO "dpkg unavailable: package-version audit requires distribution-specific implementation"
fi

OVAL_ASSESSMENT_COMPLETE=false
section "0x18 │ Ubuntu Security Advisories - Canonical OVAL"

if [ -r /etc/os-release ]; then . /etc/os-release; fi
if [ "${ID:-}" != "ubuntu" ]; then
    item INFO "Canonical OVAL: Unsupported distribution (${ID:-unknown}); Ubuntu-only feed"
elif ! command -v oscap >/dev/null 2>&1; then
    item INFO "Canonical OVAL: OpenSCAP unavailable; install with sudo ./privsec.sh --openscap"
elif ! command -v python3 >/dev/null 2>&1; then
    item INFO "Canonical OVAL: Python3 unavailable; cannot validate and parse XML"
elif ! command -v curl >/dev/null 2>&1; then
    item INFO "Canonical OVAL: curl unavailable; cannot retrieve official feed"
else
    OVAL_RELEASE="${VERSION_CODENAME:-}"
    if [[ ! "$OVAL_RELEASE" =~ ^[a-z]+$ ]]; then
        item INFO "Canonical OVAL: Cannot determine Ubuntu release codename"
    else
        OVAL_CACHE="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/privsec/oval"
        if ! mkdir -p "$OVAL_CACHE" 2>/dev/null; then
            OVAL_CACHE="$(mktemp -d /tmp/privsec-oval.XXXXXXXX)"
        fi
        OVAL_FILE="$OVAL_CACHE/com.ubuntu.${OVAL_RELEASE}.usn.oval.xml"
        OVAL_URL="https://security-metadata.canonical.com/oval/com.ubuntu.${OVAL_RELEASE}.usn.oval.xml.bz2"
        OVAL_REFRESH=1
        if [ -s "$OVAL_FILE" ] && [ -n "$(find "$OVAL_FILE" -mmin -1440 -print 2>/dev/null)" ]; then
            OVAL_REFRESH=0
        fi
        if [ "$OVAL_REFRESH" -eq 1 ]; then
            OVAL_TMP="$(mktemp "$OVAL_CACHE/.oval.XXXXXXXX")"
            OVAL_XML="$(mktemp "$OVAL_CACHE/.xml.XXXXXXXX")"
            OVAL_ERR="$(mktemp "$OVAL_CACHE/.curl.XXXXXXXX")"
            OVAL_HTTP="$(curl --silent --show-error --location --retry 2 --connect-timeout 10 --max-time 180 --output "$OVAL_TMP" --write-out '%{http_code}' "$OVAL_URL" 2>"$OVAL_ERR")"
            OVAL_CURL_RC=$?
            OVAL_FORMAT="unknown"
            if [ "$OVAL_CURL_RC" -eq 0 ] && [ "$OVAL_HTTP" = "200" ] && [ -s "$OVAL_TMP" ]; then
                OVAL_FORMAT=$(python3 - "$OVAL_TMP" "$OVAL_XML" <<'PYDECOMP'
import sys, bz2, gzip, shutil
source, target = sys.argv[1:]
with open(source, 'rb') as f:
    header = f.read(3)
try:
    if header.startswith(b'BZh'):
        with bz2.open(source, 'rb') as inp, open(target, 'wb') as out:
            shutil.copyfileobj(inp, out)
        print('bzip2')
    elif header.startswith(b'\x1f\x8b'):
        with gzip.open(source, 'rb') as inp, open(target, 'wb') as out:
            shutil.copyfileobj(inp, out)
        print('gzip')
    else:
        shutil.copyfile(source, target)
        print('plain')
except (OSError, EOFError, ValueError) as exc:
    print('invalid:' + str(exc)[:110])
PYDECOMP
                )
                if python3 - "$OVAL_XML" <<'PYOVALVALID'
import sys
import xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
    valid = root.tag.rsplit('}', 1)[-1] == 'oval_definitions'
    sys.exit(0 if valid else 1)
except (ET.ParseError, OSError):
    sys.exit(1)
PYOVALVALID
                then
                    mv -f "$OVAL_XML" "$OVAL_FILE"
                    item INFO "Canonical OVAL: Valid feed downloaded (HTTP 200; format=$OVAL_FORMAT; release=$OVAL_RELEASE)"
                else
                    OVAL_TYPE="$(file -b "$OVAL_TMP" 2>/dev/null | cut -c1-90)"
                    item INFO "Canonical OVAL: HTTP 200 but feed could not be validated (format=$OVAL_FORMAT; type=${OVAL_TYPE:-unknown}; release=$OVAL_RELEASE)"
                fi
            else
                OVAL_ERROR="$(head -n 1 "$OVAL_ERR" | cut -c1-160)"
                if [ "$OVAL_CURL_RC" -ne 0 ]; then
                    item INFO "Canonical OVAL: Download failed (curl exit=$OVAL_CURL_RC; HTTP=${OVAL_HTTP:-unknown}; ${OVAL_ERROR:-network error})"
                else
                    item INFO "Canonical OVAL: Feed unavailable (HTTP=${OVAL_HTTP:-unknown}; release=$OVAL_RELEASE); Canonical may not publish this feed"
                fi
            fi
            rm -f "$OVAL_TMP" "$OVAL_XML" "$OVAL_ERR"
        fi
        if [ -s "$OVAL_FILE" ] && python3 - "$OVAL_FILE" <<'PYOVALVALID'
import sys
import xml.etree.ElementTree as ET
try:
    root = ET.parse(sys.argv[1]).getroot()
    sys.exit(0 if root.tag.rsplit('}', 1)[-1] == 'oval_definitions' else 1)
except (ET.ParseError, OSError):
    sys.exit(1)
PYOVALVALID
        then
            OVAL_AGE_HOURS="$(( ($(date +%s) - $(stat -c %Y "$OVAL_FILE" 2>/dev/null || date +%s)) / 3600 ))"
            item INFO "Canonical OVAL: Feed age ${OVAL_AGE_HOURS}h; release=$OVAL_RELEASE"
            if [ "$OVAL_AGE_HOURS" -gt 168 ]; then
                item INFO "Canonical OVAL: WARNING - feed older than 7 days; results may be outdated"
            fi
            OVAL_WORK="$(mktemp -d /tmp/privsec-oval-scan.XXXXXXXX)"
            oscap oval eval --results "$OVAL_WORK/results.xml" "$OVAL_FILE" > "$OVAL_WORK/oscap.log" 2>&1
            OVAL_RC=$?
            if [ "$OVAL_RC" -eq 0 ] && [ -s "$OVAL_WORK/results.xml" ]; then
                OVAL_LINES="$OVAL_WORK/findings.tsv"
                if python3 - "$OVAL_WORK/results.xml" "$OVAL_FILE" > "$OVAL_LINES" <<'PYOVAL'
import sys
import re
import xml.etree.ElementTree as ET

results_path, feed_path = sys.argv[1:]
ns = {
    'r': 'http://oval.mitre.org/XMLSchema/oval-results-5',
    'd': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
}

def clean(value):
    return re.sub(r'\s+', ' ', value or '').replace('|', '/').strip()

feed = ET.parse(feed_path).getroot()
metadata = {}
for definition in feed.findall('.//d:definitions/d:definition', ns):
    if definition.get('class', '').lower() not in ('patch', 'vulnerability'):
        continue
    ident = definition.get('id')
    if not ident:
        continue
    meta = definition.find('d:metadata', ns)
    if meta is None:
        continue
    title = clean(meta.findtext('d:title', default='', namespaces=ns)) or ident
    advisory = meta.find('d:advisory', ns)
    severity = clean(advisory.findtext('d:severity', default='', namespaces=ns) if advisory is not None else '')
    references = meta.findall('d:reference', ns)
    usns = []
    cves = []
    for ref in references:
        value = ' '.join((ref.get('ref_id', ''), ref.get('ref_url', '')))
        usns += re.findall(r'USN-\d+-\d+', value, re.I)
        cves += re.findall(r'CVE-\d{4}-\d{4,}', value, re.I)
    if advisory is not None:
        for cve in advisory.findall('d:cve', ns):
            cves += re.findall(r'CVE-\d{4}-\d{4,}', cve.text or '', re.I)
    metadata[ident] = (title, severity, sorted(set(usns)), sorted(set(cves)))

root = ET.parse(results_path).getroot()
seen = set()
found = 0
unknown = 0
evaluated = 0
for definition in root.findall('.//r:results/r:system/r:definitions/r:definition', ns):
    ident = definition.get('definition_id', '')
    if ident not in metadata or ident in seen:
        continue
    seen.add(ident)
    outcome = (definition.get('result') or '').lower()
    if outcome in ('unknown', 'error', 'not evaluated', 'not_evaluated'):
        unknown += 1
        continue
    if outcome not in ('true', 'false'):
        unknown += 1
        continue
    evaluated += 1
    if outcome != 'true':
        continue
    title, severity, usns, cves = metadata[ident]
    sev = severity.lower()
    # Do not label an advisory CRITICAL without explicit vendor severity.
    if sev in ('critical', 'high'):
        level = 'HIGH'
    elif sev in ('medium', 'moderate', 'low', 'negligible'):
        level = 'MEDIUM' if sev in ('medium', 'moderate') else 'INFO'
    else:
        level = 'INFO'
    label = ', '.join(usns[:3]) if usns else ident
    cve_text = ', '.join(cves[:6]) if cves else 'not specified in OVAL metadata'
    print('FINDING\t{}\t{}'.format(level, clean('{} -- {} | severity: {} | CVEs: {}'.format(label, title, severity or 'not specified', cve_text))[:450]))
    found += 1
print('COUNT\t' + str(found))
print('UNKNOWN\t' + str(unknown))
print('EVALUATED\t' + str(evaluated))
print('AVAILABLE\t' + str(len(metadata)))
PYOVAL
                then
                    OVAL_COUNT=0; OVAL_SHOWN=0; OVAL_UNKNOWN=0; OVAL_EVALUATED=0; OVAL_AVAILABLE=0
                    while IFS=$'\t' read -r kind level message; do
                        case "$kind" in
                            COUNT) OVAL_COUNT="$level" ;;
                            UNKNOWN) OVAL_UNKNOWN="$level" ;;
                            EVALUATED) OVAL_EVALUATED="$level" ;;
                            AVAILABLE) OVAL_AVAILABLE="$level" ;;
                            FINDING)
                                if [ "$OVAL_SHOWN" -lt 30 ]; then
                                    item "$level" "Canonical OVAL (applicable security advisory): $message"
                                    OVAL_SHOWN=$((OVAL_SHOWN + 1))
                                fi ;;
                        esac
                    done < "$OVAL_LINES"
                    if [ "$OVAL_EVALUATED" -gt 0 ] && [ "$OVAL_UNKNOWN" -eq 0 ] && [ "$OVAL_AGE_HOURS" -le 168 ]; then
                        OVAL_ASSESSMENT_COMPLETE=true
                    fi
                    if [ "$OVAL_COUNT" -eq 0 ] && [ "$OVAL_ASSESSMENT_COMPLETE" = true ]; then
                        item PASS "Canonical OVAL: No applicable security advisories in evaluated feed (not a guarantee of no CVEs)"
                    elif [ "$OVAL_COUNT" -eq 0 ]; then
                        item INFO "Canonical OVAL: No confirmed applicable advisories; assessment incomplete (unknown=$OVAL_UNKNOWN; evaluated=$OVAL_EVALUATED; feed age=${OVAL_AGE_HOURS}h)"
                    fi
                    if [ "$OVAL_COUNT" -gt "$OVAL_SHOWN" ]; then
                        item INFO "Canonical OVAL: $((OVAL_COUNT - OVAL_SHOWN)) additional applicable advisories omitted (first 30 shown)"
                    fi
                    [ "$OVAL_UNKNOWN" -gt 0 ] && item INFO "Canonical OVAL: $OVAL_UNKNOWN security definitions could not be evaluated conclusively"
                    [ "$OVAL_EVALUATED" -eq 0 ] && item INFO "Canonical OVAL: No security definitions evaluated; assessment inconclusive"
                    item INFO "Canonical OVAL: $OVAL_COUNT applicable security advisories; $OVAL_EVALUATED evaluated; $OVAL_AVAILABLE security definitions; feed release=$OVAL_RELEASE"
                    item INFO "Canonical OVAL: Findings without official severity are informational, not automatically critical"
                else
                    item INFO "Canonical OVAL: Could not parse OpenSCAP results; assessment inconclusive"
                fi
            else
                OVAL_LOG="$(tail -n 3 "$OVAL_WORK/oscap.log" 2>/dev/null | tr '\n' ' ' | cut -c1-220)"
                item INFO "Canonical OVAL: Evaluation failed or incomplete (exit=$OVAL_RC; ${OVAL_LOG:-check OpenSCAP/feed compatibility})"
            fi
            rm -rf "$OVAL_WORK"
        else
            item INFO "Canonical OVAL: No valid security feed available for $OVAL_RELEASE; CVE patch status remains unknown"
        fi
    fi
fi

section "0x19 │ Dirty Frag - Kernel Package Assessment"

if [ -r /etc/os-release ]; then . /etc/os-release; fi
DIRTY_RUNNING="$(uname -r)"
DIRTY_PKG=""
if command -v dpkg-query >/dev/null 2>&1; then
    DIRTY_PKG="$(dpkg-query -W -f='${Version}' "linux-image-${DIRTY_RUNNING}" 2>/dev/null || true)"
fi
DIRTY_FIXED=""
DIRTY_FLAVOUR=""
case "${ID:-}:${VERSION_ID:-}:${DIRTY_RUNNING}" in
    ubuntu:18.04:4.15.0-*) DIRTY_FIXED='4.15.0-251.263'; DIRTY_FLAVOUR='4.15' ;;
    ubuntu:18.04:5.4.0-*) DIRTY_FIXED='5.4.0-231.251~18.04.1'; DIRTY_FLAVOUR='5.4 HWE' ;;
    ubuntu:20.04:5.4.0-*) DIRTY_FIXED='5.4.0-231.251'; DIRTY_FLAVOUR='5.4' ;;
    ubuntu:20.04:5.15.0-*) DIRTY_FIXED='5.15.0-181.191~20.04.1'; DIRTY_FLAVOUR='5.15 HWE' ;;
    ubuntu:22.04:5.15.0-*) DIRTY_FIXED='5.15.0-181.191'; DIRTY_FLAVOUR='5.15' ;;
    ubuntu:22.04:6.8.0-*) DIRTY_FIXED='6.8.0-124.124~22.04.1'; DIRTY_FLAVOUR='6.8 HWE' ;;
    ubuntu:24.04:6.8.0-*) DIRTY_FIXED='6.8.0-124.124'; DIRTY_FLAVOUR='6.8' ;;
    ubuntu:24.04:6.17.0-*) DIRTY_FIXED='6.17.0-35.35~24.04.1'; DIRTY_FLAVOUR='6.17 HWE' ;;
    ubuntu:25.10:6.17.0-*) DIRTY_FIXED='6.17.0-35.35'; DIRTY_FLAVOUR='6.17' ;;
    ubuntu:26.04:7.0.0-*) DIRTY_FIXED='7.0.0-22.22'; DIRTY_FLAVOUR='7.0' ;;
esac
if [ -n "$DIRTY_FIXED" ] && [ -n "$DIRTY_PKG" ] && command -v dpkg >/dev/null 2>&1; then
    item INFO "Dirty Frag: running ${DIRTY_RUNNING}; package ${DIRTY_PKG}; Ubuntu ${VERSION_ID} (${DIRTY_FLAVOUR})"
    if dpkg --compare-versions "$DIRTY_PKG" lt "$DIRTY_FIXED"; then
        item HIGH "Dirty Frag CVE-2026-43284 / CVE-2026-43500: running kernel package below Canonical fix ${DIRTY_FIXED}"
    else
        item PASS "Dirty Frag CVE-2026-43284 / CVE-2026-43500: running Ubuntu kernel package meets Canonical fix ${DIRTY_FIXED}"
    fi
elif [ "${ID:-}" = ubuntu ] && { [ "${VERSION_ID:-}" = 14.04 ] || [ "${VERSION_ID:-}" = 16.04 ]; }; then
    item INFO "Dirty Frag: Canonical lists the original Ubuntu ${VERSION_ID} linux package as not affected; custom kernels not assessed"
else
    item INFO "Dirty Frag CVE-2026-43284 / CVE-2026-43500: inconclusive (kernel ${DIRTY_RUNNING}, package ${DIRTY_PKG:-unknown}); unsupported kernel flavour or distribution; use Canonical OVAL"
fi

section "0x1A │ Firewall - Allowed Ports & Rules"

if command -v ufw >/dev/null 2>&1; then
    UFW_STATUS=$(ufw status 2>/dev/null || true)
    if printf '%s\n' "$UFW_STATUS" | grep -qi '^Status: active'; then
        item INFO "UFW active - ALLOW rules (does not guarantee external reachability)"
        printf '%s\n' "$UFW_STATUS" | awk '
            /^To[[:space:]]+Action[[:space:]]+From/ { inrules=1; next }
            inrules && /^--/ { next }
            inrules && /ALLOW/ { print "    " $0 }
        ' | head -n 60
    else
        item INFO "UFW inactive or unavailable"
    fi
fi
if command -v nft >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    NFT_RULES=$(nft -a list ruleset 2>/dev/null || true)
    if [ -n "$NFT_RULES" ]; then
        item INFO "nftables - explicit ACCEPT rules with ports; Docker/FORWARD rules identified"
        printf '%s\n' "$NFT_RULES" | python3 -c '
import sys,re,shutil
width=max(68,shutil.get_terminal_size((100,24)).columns)
rows=[]; family=table=chain=""; hook=""
for raw in sys.stdin:
    line=raw.strip()
    m=re.match(r"table\s+(\S+)\s+(\S+)",line)
    if m: family,table=m.groups(); chain=""; hook=""; continue
    m=re.match(r"chain\s+(\S+)",line)
    if m: chain=m.group(1); hook=""; continue
    m=re.search(r"\bhook\s+(input|forward|output|prerouting|postrouting)\b",line)
    if m: hook=m.group(1)
    if not re.search(r"\baccept\b",line) or "policy accept" in line: continue
    pm=re.search(r"\b(tcp|udp)\s+dport\s+(\{[^}]+\}|[0-9]+(?:-[0-9]+)?)",line)
    if not pm: continue
    proto,port=pm.groups()
    dst=re.search(r"\b(?:ip|ip6)\s+daddr\s+(\S+)",line)
    dest=dst.group(1) if dst else "*"
    scope="DOCKER/FWD" if "DOCKER" in chain.upper() or hook=="forward" else (hook.upper() if hook else "CHAIN")
    rows.append((scope,proto.upper(),port,dest,chain))
if rows:
    cw=max(14,min(32,width-57))
    print("    {:<11} {:<5} {:<14} {:<19} {}".format("CONTEXTO","PROTO","PORTA","DESTINO","CHAIN"))
    print("    " + "─"*min(width-6,95))
    for scope,proto,port,dest,chain in rows[:80]:
        print("    {:<11.11} {:<5} {:<14.14} {:<19.19} {}".format(scope,proto,port,dest,chain[:cw]))
    if len(rows)>80: print("    ... mais {} regras omitidas".format(len(rows)-80))
else:
    print("    No explicit TCP/UDP ACCEPT rules with ports found")
'
        item INFO "Default policies, NAT and chained rules require additional analysis; this is not a list of Internet-exposed ports"
    else
        item INFO "nftables: no accessible rules"
    fi
elif command -v iptables >/dev/null 2>&1; then
    item INFO "iptables - INPUT rules (ACCEPT does not imply external reachability)"
    iptables -S INPUT 2>/dev/null | grep -E '(^-P INPUT| -j ACCEPT)' | head -n 50 | sed 's/^/    /' || true
else
    item INFO "No firewall inspection tool available (ufw/nft/iptables)"
fi

section "0x1B │ Listening Ports & Active Connections"
if command -v ss >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
    SS_DATA=$(ss -H -tunap 2>/dev/null || true)
    if [ -n "$SS_DATA" ]; then
        printf '%s\n' "$SS_DATA" | python3 -c '
import sys,re,os,shutil
width=max(66,shutil.get_terminal_size((100,24)).columns)
listening=[]; active=[]; other=[]
for line in sys.stdin:
    parts=line.split(None,6)
    if len(parts)<6: continue
    proto,state,recv,send,local,peer=parts[:6]
    detail=parts[6] if len(parts)>6 else ""
    matches=re.findall(r"\(\"([^\"]+)\",pid=(\d+)",detail)
    if not matches:
        matches=[("?",p) for p in re.findall(r"\bpid=(\d+)",detail)]
    if not matches: matches=[("-","-")]
    for name,pid in matches:
        binary="-"
        if pid.isdigit():
            try: binary=os.readlink("/proc/"+pid+"/exe")
            except OSError: binary="unavailable"
        row=(proto.upper(),state,local,peer,pid,name,binary)
        if state in ("LISTEN","UNCONN"): listening.append(row)
        elif state in ("ESTAB","ESTABLISHED"): active.append(row)
        else: other.append(row)

def show(title,rows,limit):
    print("\n    {} ({})".format(title,len(rows)))
    if not rows:
        print("    Nenhum registo encontrado")
        return
    # Narrow terminals: show the binary on a second line so columns never overlap.
    wide=width>=136
    if wide:
        localw=26; remotew=26; procw=17; binw=max(12,width-98)
        print("    {:<5} {:<11} {:<26} {:<26} {:<7} {:<17} {}".format("PROTO","STATE","LOCAL","REMOTE","PID","PROCESS","BINARY"))
    else:
        localw=max(18,min(30,(width-32)//2)); remotew=localw
        print("    {:<5} {:<11} {:<{w}} {:<{w}} {}".format("PROTO","ESTADO","LOCAL","REMOTO","PID / PROCESSO",w=localw))
    print("    " + "─"*min(width-6,132))
    for proto,state,local,peer,pid,name,binary in rows[:limit]:
        if wide:
            print("    {:<5.5} {:<11.11} {:<26.26} {:<26.26} {:<7.7} {:<17.17} {}".format(proto,state,local,peer,pid,name,binary[:binw]))
        else:
            print("    {:<5.5} {:<11.11} {:<{w}.{w}} {:<{w}.{w}} {} {}".format(proto,state,local,peer,pid,name,w=localw))
            if binary!="-": print("      ↳ Binary: {}".format(binary[:max(12,width-18)]))
    if len(rows)>limit: print("    ... {} registos adicionais omitidos".format(len(rows)-limit))

# Defensive reverse-shell triage: correlations, not proof of compromise.
def proc_details(pid):
    try:
        raw=open("/proc/%s/cmdline"%pid,"rb").read(4096)
        cmd=raw.replace(b"\0",b" ").decode("utf-8","replace").strip()
    except OSError: cmd="unavailable"
    try:
        data=open("/proc/%s/status"%pid).read()
        parent=re.search(r"^PPid:\s*(\d+)",data,re.M)
        ppid=parent.group(1) if parent else "?"
    except OSError: ppid="?"
    try:
        parent_cmd=open("/proc/%s/comm"%ppid).read().strip()
    except OSError: parent_cmd="?"
    return cmd,ppid,parent_cmd

def remote_ip(endpoint):
    host=endpoint.rsplit(":",1)[0].strip("[]")
    if "%" in host: host=host.split("%",1)[0]
    try:
        import ipaddress
        ip=ipaddress.ip_address(host)
        return ip,not (ip.is_loopback or ip.is_unspecified or ip.is_link_local)
    except ValueError: return None,False

shell_names={"sh","bash","dash","zsh","ksh","fish","busybox","nc","ncat","netcat","socat","python","python3","perl","php","ruby","node","openssl"}
seen=set(); suspects=[]
for proto,state,local,peer,pid,name,binary in active:
    if proto!="TCP" or not pid.isdigit(): continue
    key=(pid,local,peer)
    if key in seen: continue
    seen.add(key)
    ip,nonlocal_ip=remote_ip(peer)
    if not nonlocal_ip: continue
    cmd,ppid,parent_cmd=proc_details(pid)
    executable=os.path.basename(binary).lower()
    short=name.lower()
    is_shell=short in shell_names or executable in shell_names or any(short.startswith(x) for x in ("python3.","php", "node"))
    parent_shell=parent_cmd.lower() in shell_names
    hints=[]
    if is_shell: hints.append("interpreter/tool with TCP connection")
    if parent_shell and is_shell: hints.append("parent process is also an interpreter")
    if re.search(r"/dev/tcp/|/dev/udp/|bash\s+-i|sh\s+-i|pty\.spawn|socket\.connect|subprocess|dup2\s*\(",cmd,re.I):
        hints.append("argumentos potencialmente associados a shell remota")
    if hints:
        suspects.append((pid,name,local,peer,binary,ppid,parent_cmd,cmd,hints))

print("\n    POTENTIAL REVERSE SHELL TRIAGE ({})".format(len(suspects)))
print("    Heuristic analysis of established TCP connections; does not confirm intrusion")
if suspects:
    for pid,name,local,peer,binary,ppid,parent_cmd,cmd,hints in suspects[:40]:
        print("    [REVER] PID {} | {} | {} -> {}".format(pid,name,local,peer))
        print("      Binary: {}".format(binary))
        print("      Parent: {} (PID {}) | Indicators: {}".format(parent_cmd,ppid,"; ".join(hints)))
        print("      Comando: {}".format(cmd[:max(40,min(width-20,150))]))
    if len(suspects)>40: print("    ... {} additional processes omitted".format(len(suspects)-40))
else:
    print("    No heuristic indicators found in visible connections")
print("    NOTE: reverse shells may use legitimate binaries or disguised processes;")
print("    absence of indicators does not guarantee the system is uncompromised")

show("LISTENING PORTS (TCP/UDP)",listening,100)
show("ESTABLISHED CONNECTIONS",active,100)
if other: show("OTHER STATES",other,35)
print("\n    Total: {} listening | {} established | {} other states".format(len(listening),len(active),len(other)))
'
        item INFO "Processes may own multiple sockets; binary visibility depends on permissions"
    else
        item INFO "ss returned no sockets or permissions are insufficient"
    fi
else
    item INFO "Connection inventory requires ss and python3"
fi

scan_progress "$SCAN_TOTAL_SECTIONS" "Audit completed"
progress_restore_terminal

echo -e "\n${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
printf "${CYAN}║ ${WHITE}${BOLD}%-75s${RESET}${CYAN} ║${RESET}\n" "AUDIT COMPLETE - EXECUTIVE SUMMARY"
echo -e "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"

TOTAL_FINDINGS=$((HIGH + MEDIUM + PASS + INFO))
HIGH_FINDINGS=$HIGH
ACTIONABLE_FINDINGS=$((HIGH + MEDIUM))

if [ "$TOTAL_FINDINGS" -gt 0 ]; then
    HIGH_PERCENT=$(awk "BEGIN {printf \"%.1f\", ($HIGH/$TOTAL_FINDINGS)*100}")
    MEDIUM_PERCENT=$(awk "BEGIN {printf \"%.1f\", ($MEDIUM/$TOTAL_FINDINGS)*100}")
    INFO_PERCENT=$(awk "BEGIN {printf \"%.1f\", ($INFO/$TOTAL_FINDINGS)*100}")
    PASS_PERCENT=$(awk "BEGIN {printf \"%.1f\", ($PASS/$TOTAL_FINDINGS)*100}")
else
    HIGH_PERCENT="0.0"
    MEDIUM_PERCENT="0.0"
    INFO_PERCENT="0.0"
    PASS_PERCENT="0.0"
fi

echo -e "${WHITE}╔═══════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${WHITE}║                                                                           ║${RESET}"
printf "${WHITE}║  ${RED}${BOLD}●${RESET} ${RED}CRITICAL${RESET}       ${RED}${BOLD}%3d${RESET} findings   ${DIM}│${RESET} ${RED}%5s%%${RESET} of total                  ${WHITE}      ║${RESET}\n" "$HIGH" "$HIGH_PERCENT"
printf "${WHITE}║  ${YELLOW}${BOLD}◐${RESET} ${YELLOW}MEDIUM${RESET}         ${YELLOW}${BOLD}%3d${RESET} findings   ${DIM}│${RESET} ${YELLOW}%5s%%${RESET} of total                  ${WHITE}      ║${RESET}\n" "$MEDIUM" "$MEDIUM_PERCENT"
printf "${WHITE}║  ${CYAN}${BOLD}ℹ${RESET} ${CYAN}INFORMATIONAL${RESET}  ${CYAN}${BOLD}%3d${RESET} findings   ${DIM}│${RESET} ${CYAN}%5s%%${RESET} of total                  ${WHITE}      ║${RESET}\n" "$INFO" "$INFO_PERCENT"
printf "${WHITE}║  ${GREEN}${BOLD}○${RESET} ${GREEN}PASS${RESET}           ${GREEN}${BOLD}%3d${RESET} findings   ${DIM}│${RESET} ${GREEN}%5s%%${RESET} of total                  ${WHITE}      ║${RESET}\n" "$PASS" "$PASS_PERCENT"
echo -e "${WHITE}║                                                                           ║${RESET}"
echo -e "${WHITE}╟───────────────────────────────────────────────────────────────────────────╢${RESET}"
echo -e "${WHITE}║                                                                           ║${RESET}"
printf "${WHITE}║  ${BOLD}Total Findings:${RESET}        ${WHITE}${BOLD}%3d${RESET}                                            ${WHITE}   ║${RESET}\n" "$TOTAL_FINDINGS"
printf "${WHITE}║  ${BOLD}High-Risk Issues:${RESET}      ${RED}${BOLD}%3d${RESET} ${DIM}(Review and Prioritize)${RESET}           ${WHITE}            ║${RESET}\n" "$HIGH_FINDINGS"
echo -e "${WHITE}║                                                                           ║${RESET}"
echo -e "${WHITE}╚═══════════════════════════════════════════════════════════════════════════╝${RESET}"

echo -e "\n${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
printf "${CYAN}║ ${WHITE}${BOLD}%-75s${RESET}${CYAN} ║${RESET}\n" "RECOMMENDATIONS"
echo -e "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"

if [ "$HIGH" -gt 0 ]; then
    echo -e "  ${RED}${BOLD}[!]${RESET} ${RED}URGENT:${RESET} $HIGH high-risk findings require review and remediation"
    echo -e "  ${DIM}    → Review and fix all HIGH severity findings first${RESET}\n"
fi

if [ "$MEDIUM" -gt 0 ]; then
    echo -e "  ${YELLOW}${BOLD}[◐]${RESET} ${YELLOW}WARNING:${RESET} $MEDIUM medium-risk issues need investigation"
    echo -e "  ${DIM}    → Manual analysis recommended for validation${RESET}\n"
fi

if [ "$ACTIONABLE_FINDINGS" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}[✓]${RESET} ${GREEN}GOOD:${RESET} No high- or medium-risk findings detected"
    if [ "$OVAL_ASSESSMENT_COMPLETE" = true ]; then
        echo -e "  ${DIM}    → No findings in completed checks; other vulnerabilities may exist${RESET}\n"
    else
        echo -e "  ${YELLOW}    → Canonical OVAL assessment incomplete; CVE status remains unverified${RESET}\n"
    fi
fi

echo -e "${GRAY}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
printf "${GRAY}║ Scan completed: %-62s${RESET}\n" "$(date '+%Y-%m-%d %H:%M:%S')                                         ║"
echo -e "${GRAY}║ Report generated by PRIVSEC v3.0                                            ║${RESET}"
echo -e "${GRAY}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"

if [ "$RUN_LINPEAS" = true ]; then
    echo -e "\n${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
    printf "${CYAN}║ ${WHITE}${BOLD}%-75s${RESET}${CYAN} ║${RESET}\n" "EXECUTING LINPEAS"
    echo -e "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"
    
    curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
fi
