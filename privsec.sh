#!/bin/bash

#  PRIVSEC - Privilege Escalation Security Audit Tool
#  Version: 2.0
#  Author: Syrus

RUN_LINPEAS=false

for arg in "$@"; do
    case "$arg" in
        --linpeas)
            RUN_LINPEAS=true
            ;;
        -h|--help)
            echo "PRIVSEC - Privilege Escalation Security Audit Tool v2.0"
            echo ""
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --linpeas        Run LinPEAS after PRIVSEC scan"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "Examples:"
            echo "  sudo $0"
            echo "  sudo $0 --linpeas"
            echo ""
            exit 0
            ;;
    esac
done

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
    echo -e "  ║   ${YELLOW}Privilege Escalation Security Audit Tool ${DIM}v2.0${RESET}${CYAN}                       ║"
    echo -e "  ║   ${GRAY}Automated Security Assessment & Vulnerability Analysis${CYAN}              ║"
    echo -e "  ║                                                                       ║"
    echo -e "  ╚═══════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "  ${GRAY}Scan initiated: ${WHITE}$(date '+%Y-%m-%d %H:%M:%S')${RESET}\n"
}

section() {
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
            item MEDIUM "Unusual SUID: $f (Manual Analysis Required)"
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
WWF=$(find $CRITICAL_WW_PATHS -type f -writable 2>/dev/null | grep -v "/snap/")

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

if [ -r /etc/shadow ] && [ "$(id -u)" -ne 0 ]; then
    item HIGH "/etc/shadow readable by user (Permission Failure)"
else
    item PASS "/etc/shadow → $SHADOW"
fi

if [ -w /etc/passwd ]; then
    item HIGH "/etc/passwd writable (Critical Permission Failure)"
else
    item MEDIUM "/etc/passwd → $PASSWD (Readable - Expected)"
fi

section "0x08 │ Cron Jobs Security"

CRON_FILES=$(grep -R "." /etc/cron* /var/spool/cron/crontabs 2>/dev/null | cut -d: -f1 | sort -u)
FOUND_CRON=0

for c in $CRON_FILES; do
    if [ -w "$c" ]; then
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

        if [ -f "$FILE" ] && [ -w "$FILE" ]; then
            item HIGH "Writable Service: $FILE (Root Vector Possible)"
            FOUND_SYSTEMD=1
        elif [ ! -f "$FILE" ] && [ -w "$FILE" ]; then
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
    if [ -d "$d" ] && [ -w "$d" ]; then
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
    | grep -vE 'cloud/|debconf.conf|fwupd/|hdparm.conf|iscsi/|libblockdev/|lvm/|modprobe.d/|overlayroot.conf|pam.d/|polkit-1/|rsyslog.d/|security/|sos/|sudo.conf|sudo_logsrvd.conf|sysctl.d/|vmware-tools/|sshd-keygen' \
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
    | grep -vE '/snap/|/usr/share/doc|/usr/share/man|/etc/pki/|/etc/ssl/certs/|/etc/pollinate/|/usr/share/bash-completion/' \
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
        
        if [ -f "$AUTH_KEYS" ] && [ -w "$AUTH_KEYS" ]; then
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

echo -e "\n${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
printf "${CYAN}║ ${WHITE}${BOLD}%-75s${RESET}${CYAN} ║${RESET}\n" "AUDIT COMPLETE - EXECUTIVE SUMMARY"
echo -e "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"

TOTAL_FINDINGS=$((HIGH + MEDIUM + PASS + INFO))
CRITICAL_FINDINGS=$((HIGH + MEDIUM))

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
printf "${WHITE}║  ${BOLD}Critical Issues:${RESET}       ${RED}${BOLD}%3d${RESET} ${DIM}(Require Immediate Attention)${RESET}           ${WHITE}      ║${RESET}\n" "$CRITICAL_FINDINGS"
echo -e "${WHITE}║                                                                           ║${RESET}"
echo -e "${WHITE}╚═══════════════════════════════════════════════════════════════════════════╝${RESET}"

echo -e "\n${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
printf "${CYAN}║ ${WHITE}${BOLD}%-75s${RESET}${CYAN} ║${RESET}\n" "RECOMMENDATIONS"
echo -e "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"

if [ "$HIGH" -gt 0 ]; then
    echo -e "  ${RED}${BOLD}[!]${RESET} ${RED}URGENT:${RESET} $HIGH critical vulnerabilities require immediate remediation"
    echo -e "  ${DIM}    → Review and fix all HIGH severity findings first${RESET}\n"
fi

if [ "$MEDIUM" -gt 0 ]; then
    echo -e "  ${YELLOW}${BOLD}[◐]${RESET} ${YELLOW}WARNING:${RESET} $MEDIUM medium-risk issues need investigation"
    echo -e "  ${DIM}    → Manual analysis recommended for validation${RESET}\n"
fi

if [ "$CRITICAL_FINDINGS" -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}[✓]${RESET} ${GREEN}GOOD:${RESET} No critical security issues detected"
    echo -e "  ${DIM}    → System appears to have proper security hardening${RESET}\n"
fi

echo -e "${GRAY}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
printf "${GRAY}║ Scan completed: %-62s${RESET}\n" "$(date '+%Y-%m-%d %H:%M:%S')                                         ║"
echo -e "${GRAY}║ Report generated by PRIVSEC v2.0                                            ║${RESET}"
echo -e "${GRAY}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"

if [ "$RUN_LINPEAS" = true ]; then
    echo -e "\n${CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
    printf "${CYAN}║ ${WHITE}${BOLD}%-75s${RESET}${CYAN} ║${RESET}\n" "EXECUTING LINPEAS"
    echo -e "${CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}\n"
    
    curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
fi