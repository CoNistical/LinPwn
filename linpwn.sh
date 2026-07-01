#!/usr/bin/env bash

# Function to print ASCII art
ascii_art() {
    # Set the purple color for the ASCII art
    echo -e "\e[1;35m"
cat << "EOF"
██╗     ██╗███╗   ██╗██████╗ ██╗    ██╗███╗   ██╗
██║     ██║████╗  ██║██╔══██╗██║    ██║████╗  ██║
██║     ██║██╔██╗ ██║██████╔╝██║ █╗ ██║██╔██╗ ██║
██║     ██║██║╚██╗██║██╔═══╝ ██║███╗██║██║╚██╗██║
███████╗██║██║ ╚████║██║     ╚███╔███╔╝██║ ╚████║
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
EOF
    # Reset the color for the script title
    echo -e "\e[0m"
    echo -e "  Linux Privilege Escalation Script"
}

# Define colors
C=$(printf '\033')
SED_RED="${C}[1;31m&${C}[0m"

# test if sed supports -E or -r
E=E
echo | sed -${E} 's/o/a/' 2>/dev/null
if [ $? -ne 0 ] ; then
	echo | sed -r 's/o/a/' 2>/dev/null
	if [ $? -eq 0 ] ; then
		E=r
	else
        echo -e "\e[1;33mWARNING: No suitable option found for extended regex with sed. Continuing but the results might be unreliable.\e[0m"
	fi
fi

# Color palette + section helpers (so functions don't repeat raw ANSI codes).
# Roll these out across the other functions to shed most of the boilerplate:
#   sec "Title"   -> two blank lines, blue header, green top rule
#   endsec        -> green bottom rule
RED=$'\e[1;31m'; GRN=$'\e[1;32m'; YEL=$'\e[1;33m'; BLU=$'\e[1;34m'; CYN=$'\e[1;36m'; RST=$'\e[0m'
RULE="${GRN}--------------------------------------------------------------------------${RST}"
sec()    { printf '\n\n%s[+] %s%s\n%s\n' "$BLU" "$1" "$RST" "$RULE"; }
endsec() { printf '%s\n' "$RULE"; }

# Set Up Summary Variables
os_info_summary=""
user_info_summary=""
sudo_priv_summary="No unusual sudo privileges detected."
doas_summary="No doas configuration found."
python_libhijack_summary="No Python library hijacking opportunities found."
suid_summary="No SUID binaries detected."
sgid_summary="No SGID binaries detected."
cron_summary="No writable cron jobs or misconfigurations detected."
capabilities_summary="No dangerous file capabilities detected."
screen_summary="Screen not vulnerable or not installed."
writable_files_summary="No writable critical files or directories detected."
interesting_files_summary="No interesting files detected."
ssh_keys_summary="No SSH private keys found."
docker_summary="Not running in a Docker container."
env_vars_summary="No sensitive environment variables detected."
systemd_summary="No writable systemd files or misconfigurations detected."
copy-fail_summary="copy-fail not vulnerable or not installed."
pwnkit_summary="PwnKit check not performed."
cve_2017_16995_summary="CVE-2017-16995 check not performed."
cve_2026_24061_summary="CVE-2026-24061 check not performed."
dirty_pipe_summary="Dirty Pipe check not performed."
dirty_cow_summary="Dirty COW check not performed."
netfilter_summary="Netfilter vulnerability check not performed."
backup_files_summary="No interesting files found in backup directories."
editor_artifacts_summary="No editor artifacts found."

version_lt() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

find_prune_expr=(
    -path /proc -o
    -path /sys -o
    -path /dev -o
    -path /run -o
    -path /tmp -o
    -path /nix -o
    -path /snap -o
    -path /var/lib/docker -o
    -path /var/lib/containerd -o
    -path '*/linux-headers*'
)

# Function to detect if running inside a Docker container
detect_docker_container() {
    docker_detected=0

    # Check for /.dockerenv file
    if [ -f /.dockerenv ]; then
        echo -e "\e[1;33m[!] Detected: /.dockerenv file exists (Docker container environment)\e[0m"
        docker_detected=1
    fi

    # Check for 'docker' in cgroup
    if grep -q docker /proc/1/cgroup 2>/dev/null; then
        echo -e "\e[1;33m[!] Detected: 'docker' found in /proc/1/cgroup (Docker container environment)\e[0m"
        docker_detected=1
    fi

    # Check for 'containerd' in cgroup (alternative to detect container runtimes)
    if grep -q containerd /proc/1/cgroup 2>/dev/null; then
        echo -e "\e[1;33m[!] Detected: 'containerd' found in /proc/1/cgroup (Docker container environment)\e[0m"
        docker_detected=1
    fi

    # Check for any environment variable indicating Docker
    if [ -n "$DOCKER_CONTAINER" ]; then
        echo -e "\e[1;33m[!] Detected: DOCKER_CONTAINER environment variable set\e[0m"
        docker_detected=1
    fi

    # Suggest deepce if inside a container
    if [ $docker_detected -eq 1 ]; then
        echo -e "\n\e[1;36m[+] Suggestion: Consider running \e[1;34mdeepce\e[0m (\e[4mhttps://github.com/stealthcopter/deepce\e[0m) to investigate container breakout potential.\e[0m"

        # docker container was detected. Add to summary
        docker_summary="Running inside a Docker container."
    fi
}

check_if_root() {
    if [ "$(id -u)" -eq 0 ] || [ "$(id -ru)" -eq 0 ]; then
        # If root, check if inside a Docker container
        detect_docker_container

        echo -e "\n\e[1;36m[+] Suggestion: As root, consider using the following tools for credential dumping:\e[0m"
        echo -e "    \e[1;34m- mimipenguin\e[0m (\e[4mhttps://github.com/huntergregal/mimipenguin\e[0m)"
        echo -e "    \e[1;34m- LaZagne.py\e[0m (\e[4mhttps://github.com/AlessandroZ/LaZagne\e[0m)"

        # If not inside a container, display a simple root message and exit
        if [ "$docker_detected" -eq 0 ]; then
            echo -e "\e[1;31m[-] You are already running as root (UID or EUID). Exiting...\e[0m"
        fi

        # Exit script since privilege escalation is unnecessary as root
        exit 0
    fi
}

# Function to highlight specific groups and provide abuse information
highlight_groups() {
    local group=$1
    case "$group" in
        wheel)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Wheel Group:\e[0m Allows users to execute commands as root via sudo."
            echo -e "    \e[1;36m[-> HackTricks]:\e[0m https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#wheel-group"
            ;;
        docker)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Docker Group:\e[0m Can run Docker containers as root, leading to privilege escalation."
            echo -e "    \e[1;36m[-> HackTricks]:\e[0m https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#docker-group"
            ;;
        lxd)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] LXD Group:\e[0m Can create privileged containers, leading to root access."
            echo -e "    \e[1;36m[-> HackTricks]:\e[0m https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation.html"
            ;;
        sudo)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Sudo Group:\e[0m Allows running commands as root if misconfigured."
            echo -e "    \e[1;36m[-> HackTricks]:\e[0m https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#sudoadmin-groups"
            ;;
        libvirt)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Libvirt Group:\e[0m Can control virtual machines, possibly leading to privilege escalation."
            echo -e "    \e[1;36m[-> Medium]:\e[0m https://medium.com/@alinuxadmin/arbitrary-file-read-write-and-rce-using-libvirt-ebc239dcbd8d"
            ;;
        kvm)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] KVM Group:\e[0m Has access to virtual machine control, potential escalation risk."
            ;;
        disk)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Disk Group:\e[0m Allows direct disk access, enabling password or file extraction."
            echo -e "    \e[1;36m[-> HackTricks]:\e[0m https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#disk-group"
            ;;
        www-data|apache|nginx)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Web Server Group:\e[0m Common for web service users, may lead to web-based privilege escalation."
            ;;
        shadow)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Shadow Group:\e[0m Can read /etc/shadow, enabling password hash extraction."
            echo -e "    \e[1;36m[-> HackTricks]:\e[0m https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#shadow-group"
            ;;
        root)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Root Group:\e[0m Full system control. Check if it is misconfigured."
            ;;
        staff)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Staff Group:\e[0m Allows users to add local modifications to the system (/usr/local) without needing root privileges (note that executables in /usr/local/bin are in the PATH variable of any user, and they may \"override\" the executables in /bin and /usr/bin with the same name)."
            echo -e "    \e[1;36m[-> HackTricks]:\e[0m https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#staff-group"
            ;;
        adm)
            echo -e "\e[1;31m$group\e[0m"
            echo -e "    \e[1;33m[!] Adm Group:\e[0m Can read logs, useful for privilege escalation via credential leaks."
            echo -e "    \e[1;36m[-> HackTricks]:\e[0m https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#adm-group"
            ;;
        *)
            echo "$group"  # Default color for other groups
            ;;
    esac
}


# Function to display OS information
os_info() {
    echo -e "\n\n\e[1;34m[+] Gathering OS Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    kernel_version=$(uname -r)
    architecture=$(uname -m)
    hostname=$(hostname)
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        distro_name="$NAME"
        distro_version="$VERSION"
    else
        distro_name="Unknown"
        distro_version="Unknown"
    fi

    echo -e "\e[1;33mKernel Version:\e[0m $kernel_version"
    echo -e "\e[1;33mDistro Name:\e[0m $distro_name"
    echo -e "\e[1;33mDistro Version:\e[0m $distro_version"
    echo -e "\e[1;33mArchitecture:\e[0m $architecture"
    echo -e "\e[1;33mHostname:\e[0m $hostname"

    os_info_summary="Kernel: $kernel_version, Distro: $distro_name $distro_version, Arch: $architecture, Hostname: $hostname"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check if the machine is domain joined
check_ad_integration() {
    echo -e "\n\n\e[1;34m[+] Checking for Active Directory Integration\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Check if machine is domain joined using realm
    if command -v realm >/dev/null 2>&1; then
        realm_list=$(realm list 2>/dev/null)
        if echo "$realm_list" | grep -q "configured: kerberos-member"; then
            echo -e "\e[1;33m[!] This machine is domain-joined (Active Directory detected):\e[0m"
            echo "$realm_list" | sed 's/^/    /'

            # Suggest using Linikatz if root
            if [ "$(id -u)" -eq 0 ]; then
                echo -e "\n\e[1;36m[+] Suggestion: As root, use \e[1;34mLinikatz\e[0m to dump secrets from Active Directory:\e[0m"
                echo -e "    \e[4mhttps://github.com/Orange-Cyberdefense/LinikatzV2\e[0m"
            fi
        else
            echo -e "\e[1;32m[+] No Active Directory integration detected.\e[0m"
        fi
    else
        echo -e "\e[1;31m[-] 'realm' command not found. Unable to check for AD integration.\e[0m"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display current user and group memberships
user_info() {
    echo -e "\n\n\e[1;34m[+] Gathering User Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    current_user=$(whoami)
    uid=$(id -u)
    gid=$(id -g)
    primary_group=$(id -gn)

    echo -e "\e[1;33mCurrent User:\e[0m $current_user"
    echo -e "\e[1;33mUser ID (UID):\e[0m $uid"
    echo -e "\e[1;33mGroup ID (GID):\e[0m $gid"
    echo -e "\e[1;33mPrimary Group:\e[0m $primary_group"

    # Properly format group memberships
    echo -e "\e[1;33mGroup Memberships:\e[0m"
    group_memberships=$(id -Gn | tr ' ' '\n' | while IFS= read -r group; do
        highlight_groups "$group"
    done)
    echo -e "$group_memberships"

    # Store formatted data for summary
    user_info_summary="User: $current_user (UID: $uid, GID: $gid)\nPrimary Group: $primary_group\nGroups: $(id -Gn | tr ' ' ', ')"

    echo -e "\n\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display logged in users and last login information
logged_users_info() {
    echo -e "\n\n\e[1;34m[+] Gathering Logged In Users and Last Login Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    echo -e "\e[1;33mLast Login Information:\e[0m"
    if command -v lastlog >/dev/null; then
        lastlog | grep -v "Never logged in" | awk '{print $1 " - " $3 " " $4 " " $5 " " $6 " " $7 " " $8 " " $9}'
    else
        echo -e "\e[1;31mCommand lastlog not available, cannot check last login information\e[0m"
    fi

    # Add some spacing
    echo -e "\n"

    echo -e "\e[1;33mCurrently Logged In Users:\e[0m"
    if command -v w >/dev/null; then
        w
    else
        echo -e "\e[1;31mCommand w not available, cannot check currently logged in users\e[0m"
    fi
    # Store formatted data for summary
    if command -v lastlog >/dev/null && command -v w >/dev/null; then
        logged_users_summary="Last Logins: $(lastlog | grep -v "Never logged in" | wc -l) users; Current Users: $(w -h | wc -l)"
    else
        logged_users_summary="Commands not available"
    fi
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check and highlight sudo permissions
sudo_check() {
    echo -e "\n\n\e[1;34m[+] Checking Sudo Privileges\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    # Initialize the summary variable
    sudo_priv_summary="No unusual sudo privileges detected."
    # Check if sudo is installed
    if ! command -v sudo >/dev/null 2>&1; then
        echo -e "\e[1;31m[-] Sudo is not installed on this system.\e[0m"
        sudo_priv_summary="Sudo is not installed."
        echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
        return
    fi
    # Get and display sudo version number
    sudo_version=$(sudo --version | head -n 1 | awk '{print $3}')
    echo -e "\e[1;33m[!] Sudo Version:\e[0m $sudo_version"

    # Function for version less than comparison (using sort -V)
    verlt() {
        [ "$1" = "$2" ] && return 1 || [ "$1" = "$(echo -e "$1\n$2" | sort -V | head -n1)" ]
    }

    # Check for known vulnerabilities
    echo -e "\n\e[1;34m[+] Checking for Known Sudo Vulnerabilities\e[0m"
    vuln_detected=false
    vuln_summary=""

    # CVE-2019-14287 (Sudo Policy Bypass)
    if verlt "$sudo_version" "1.8.28"; then
        echo -e "\e[1;31m[!] Vulnerable to CVE-2019-14287: Sudo Policy Bypass.\e[0m"
        echo -e "    Affected versions: < 1.8.28"
        echo -e "    This allows bypassing restrictions to run commands as root using -u#-1 or similar."
        echo -e "    Affected examples: Versions prior to 1.8.28 on various distributions."
        vuln_detected=true
        vuln_summary="${vuln_summary}${vuln_summary:+ }CVE-2019-14287"
    fi

    # CVE-2021-3156 (Heap-based Buffer Overflow - Baron Samedit)
    if verlt "$sudo_version" "1.9.5p2"; then
        echo -e "\e[1;31m[!] Potentially vulnerable to CVE-2021-3156: Heap-based Buffer Overflow.\e[0m"
        echo -e "    Affected versions: Legacy 1.7.7 to 1.8.31p2, Stable 1.9.0 to 1.9.5p1"
        echo -e "    This allows privilege escalation via sudoedit."
        echo -e "    Affected examples:"
        echo -e "      - 1.8.31 (Ubuntu 20.04)"
        echo -e "      - 1.8.27 (Debian 10)"
        echo -e "      - 1.9.2 (Fedora 33)"
        echo -e "      - and others"
        vuln_detected=true
        vuln_summary="${vuln_summary}${vuln_summary:+ }CVE-2021-3156"
    fi

    # CVE-2023-22809 (sudoedit arbitrary file edit)
    if verlt "$sudo_version" "1.9.12p2"; then
        echo -e "\e[1;31m[!] Vulnerable to CVE-2023-22809: sudoedit can edit arbitrary files.\e[0m"
        echo -e "    Affected versions: 1.8.0 to 1.9.12p1"
        echo -e "    Allows malicious users with sudoedit privileges to edit arbitrary files, potentially leading to privilege escalation."
        vuln_detected=true
        vuln_summary="${vuln_summary}${vuln_summary:+ }CVE-2023-22809"
    fi

    # CVE-2025-32462 (Policy-Check Flaw)
    if ! verlt "$sudo_version" "1.8.8" && verlt "$sudo_version" "1.9.17p1"; then
        echo -e "\e[1;31m[!] Vulnerable to CVE-2025-32462: Policy-Check Flaw.\e[0m"
        echo -e "    Affected versions: 1.8.8 through 1.9.17"
        echo -e "    Allows unauthorized users to gain elevated privileges in certain configurations."
        vuln_detected=true
        vuln_summary="${vuln_summary}${vuln_summary:+ }CVE-2025-32462"
    fi

    # CVE-2025-32463 (Chroot Privilege Escalation)
    if ! verlt "$sudo_version" "1.9.14" && verlt "$sudo_version" "1.9.17p1"; then
        echo -e "\e[1;31m[!] Vulnerable to CVE-2025-32463: Chroot Privilege Escalation.\e[0m"
        echo -e "    Affected versions: 1.9.14 to 1.9.17 (including p-revisions)"
        echo -e "    Allows local users to obtain root access by tricking sudo into loading arbitrary shared objects or configs."
        vuln_detected=true
        vuln_summary="${vuln_summary}${vuln_summary:+ }CVE-2025-32463"
    fi

    if ! $vuln_detected; then
        echo -e "\e[1;32m[-] No known sudo vulnerabilities detected for this version.\e[0m"
    fi

    # Update summary if vulnerabilities detected
    if $vuln_detected; then
        sudo_priv_summary="${sudo_priv_summary} Potential vulnerabilities: ${vuln_summary}. Review and patch immediately."
    fi

    # Check if the user can run `sudo -l` without a password
    sudo_output=$(sudo -n -l 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "\e\n[1;33m[!] User can run the following \e[1;31msudo\e[0m \e[1;33mcommands without a password:\e[0m"
        # Update the summary
        sudo_priv_summary="User has sudo privileges without a password. Review needed. ${vuln_summary:+Potential vulnerabilities: ${vuln_summary}. }"
        # Process the output line by line and highlight critical elements
        while IFS= read -r line; do
            # Highlight critical elements using printf with proper ANSI codes
            line=$(echo "$line" | sed \
                -e 's/ALL/\x1b[1;31mALL\x1b[0m/g' \
                -e 's/NOPASSWD/\x1b[1;31mNOPASSWD\x1b[0m/g' \
                -e 's/SETENV/\x1b[1;33mSETENV\x1b[0m/g' \
                -e 's/env_keep/\x1b[1;31menv_keep\x1b[0m/g' \
                -e 's/passwd_timeout=0/\x1b[1;35mpasswd_timeout=0\x1b[0m/g')
            # Print the highlighted line with proper indentation
            printf " %b\n" "$line"
        done <<< "$sudo_output"
    else
        echo -e "\e[1;31m[-] User cannot run sudo commands without a password.\e[0m"
    fi
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check doas configuration
doas_check() {
    echo -e "\n\n\e[1;34m[+] Checking Doas Configuration\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    doas_summary="No doas configuration found."

    # Check if doas is installed
    if ! command -v doas >/dev/null 2>&1; then
        echo -e "\e[1;31m[-] Doas is not installed on this system.\e[0m"
        doas_summary="Doas is not installed."
        echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
        return
    fi

    # Check if doas.conf exists
    if [ ! -f /etc/doas.conf ]; then
        echo -e "\e[1;31m[-] /etc/doas.conf does not exist.\e[0m"
        doas_summary="Doas installed but no config file found."
        echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
        return
    fi

    # Check if we can read the config
    if [ ! -r /etc/doas.conf ]; then
        echo -e "\e[1;31m[-] Cannot read /etc/doas.conf (permission denied).\e[0m"
        doas_summary="Doas config exists but not readable."
        echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
        return
    fi

    echo -e "\e[1;33m[!] Found /etc/doas.conf - Analyzing rules:\e[0m\n"

    # Read and process doas.conf
    while IFS= read -r line || [ -n "$line" ]; do
        # Skip empty lines and comments
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        # Highlight the line
        highlighted=$(echo "$line" | sed \
            -e 's/\bpermit\b/\x1b[1;32mpermit\x1b[0m/g' \
            -e 's/\bdeny\b/\x1b[1;31mdeny\x1b[0m/g' \
            -e 's/\bnopass\b/\x1b[1;31mnopass\x1b[0m/g' \
            -e 's/\bpersist\b/\x1b[1;33mpersist\x1b[0m/g' \
            -e 's/\bkeeepenv\b/\x1b[1;33mkeepenv\x1b[0m/g' \
            -e 's/\bsetenv\b/\x1b[1;33msetenv\x1b[0m/g' \
            -e 's/\bas root\b/\x1b[1;35mas root\x1b[0m/g' \
            -e 's/\bcmd\b/\x1b[1;36mcmd\x1b[0m/g')
        printf "    %b\n" "$highlighted"

        # Check for dangerous configurations
        if echo "$line" | grep -qE "permit.*nopass.*as root.*cmd"; then
            cmd_allowed=$(echo "$line" | sed -n 's/.*cmd \([^ ]*\).*/\1/p')
            echo -e "\n    \e[1;33m[!] EXPLOITATION POTENTIAL:\e[0m"
            echo -e "        \e[1;37m→ User can run '$cmd_allowed' as root without password\e[0m"
            echo -e "        \e[1;37m→ Check GTFOBins for: https://gtfobins.github.io/gtfobins/${cmd_allowed##*/}/\e[0m"
            echo -e "        \e[1;37m→ Try: doas $cmd_allowed\e[0m\n"
            doas_summary="Doas nopass rule found for command: $cmd_allowed. Review needed."
        fi

        if echo "$line" | grep -qE "permit.*nopass.*as root$" && ! echo "$line" | grep -q "cmd"; then
            echo -e "\n    \e[1;31m[!!!] CRITICAL: User can run ANY command as root without password!\e[0m"
            echo -e "        \e[1;37m→ Direct root access: doas -s\e[0m"
            echo -e "        \e[1;37m→ Or simply: doas su -\e[0m\n"
            doas_summary="CRITICAL: Unrestricted nopass root access via doas! Review needed."
        fi

        if echo "$line" | grep -qE "keepenv|setenv"; then
            echo -e "    \e[1;33m[!] Environment variables preserved - check for LD_PRELOAD/PATH hijacking\e[0m\n"
        fi

    done < /etc/doas.conf

    # Try running doas to see what we can actually do
    echo -e "\n\e[1;34m[+] Testing doas access:\e[0m"
    if doas -C /etc/doas.conf id >/dev/null 2>&1; then
        echo -e "    \e[1;32m[+] Current user has valid doas permissions\e[0m"
        # Only update summary if not already set to something more critical
        if [ "$doas_summary" = "No doas configuration found." ]; then
            doas_summary="User has valid doas permissions. Review needed."
        fi
    else
        echo -e "    \e[1;31m[-] Current user has no direct doas permissions or config check failed\e[0m"
        if [ "$doas_summary" = "No doas configuration found." ]; then
            doas_summary="Doas config found but current user has no permissions."
        fi
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display user's PATH and highlight non-normal entries
path_info() {
    echo -e "\n\n\e[1;34m[+] Gathering PATH Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    current_path="$PATH"
    echo -e "\e[1;33mCurrent PATH:\e[0m $current_path"
    echo -e "\e[1;33mPATH Entries:\e[0m"
    IFS=':' read -r -a path_array <<< "$PATH"
    for dir in "${path_array[@]}"; do
        if [ -z "$dir" ]; then
            echo -e "\e[1;31m(Empty entry - non-normal)\e[0m"
        elif [ "$dir" = "." ]; then
            echo -e "\e[1;31m$dir (Current directory - non-normal)\e[0m"
        elif [ -d "$dir" ] && [ -w "$dir" ]; then
            echo -e "\e[1;31m$dir (Writable - non-normal)\e[0m"
        else
            echo "$dir"
        fi
    done
    # Store formatted data for summary
    path_info_summary="PATH: $current_path\nNon-normal entries: $(IFS=':'; for dir in "${path_array[@]}"; do if [ -z "$dir" ] || [ "$dir" = "." ] || ([ -d "$dir" ] && [ -w "$dir" ]); then echo -n "$dir, "; fi; done | sed 's/, $//')"
    echo -e "\n\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check for Python library hijacking opportunities
python_libhijack_check() {
    echo -e "\n\n\e[1;34m[+] Checking Python Library Hijacking\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    python_libhijack_summary="No Python library hijacking opportunities found."

    # Find available Python interpreters
    local python_bins=()
    for pybin in python3 python python2; do
        if command -v "$pybin" >/dev/null 2>&1; then
            python_bins+=("$pybin")
        fi
    done

    if [ ${#python_bins[@]} -eq 0 ]; then
        echo -e "\e[1;31m[-] No Python interpreter found on this system.\e[0m"
        python_libhijack_summary="No Python interpreter installed."
        echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
        return
    fi

    local writable_found=false
    local writable_paths=()

    for pybin in "${python_bins[@]}"; do
        echo -e "\e[1;33m[*] Checking $pybin sys.path:\e[0m"

        # Get sys.path from Python
        local sys_path
        sys_path=$("$pybin" -c "import sys; print('\\n'.join(sys.path))" 2>/dev/null)

        if [ -z "$sys_path" ]; then
            echo -e "    \e[1;31m[-] Could not retrieve sys.path\e[0m"
            continue
        fi

        local path_index=0
        while IFS= read -r pypath; do
            if [ -z "$pypath" ]; then
                echo -e "    \e[1;33m[$path_index] '' (empty = current directory)\e[0m"
                echo -e "        \e[1;31m[!] HIJACK POTENTIAL: Import from current working directory\e[0m"
                echo -e "        \e[1;37m→ If a script runs from a writable directory, place malicious .py file there\e[0m"
                writable_found=true
                writable_paths+=("cwd (empty path)")
            elif [ -d "$pypath" ]; then
                if [ -w "$pypath" ]; then
                    echo -e "    \e[1;31m[$path_index] $pypath (WRITABLE)\e[0m"
                    echo -e "        \e[1;31m[!] HIJACK POTENTIAL: Can write malicious Python modules here\e[0m"
                    echo -e "        \e[1;37m→ Create a .py file matching an imported module name to hijack imports\e[0m"
                    echo -e "        \e[1;37m→ Example: echo 'import os;os.system(\"/bin/bash\")' > $pypath/requests.py\e[0m"
                    writable_found=true
                    writable_paths+=("$pypath")
                else
                    echo -e "    [$path_index] $pypath"
                fi
            else
                echo -e "    [$path_index] $pypath (does not exist)"
                # Check if parent is writable - could create the directory
                local parent_dir
                parent_dir=$(dirname "$pypath")
                if [ -d "$parent_dir" ] && [ -w "$parent_dir" ]; then
                    echo -e "        \e[1;33m[!] Parent directory writable - could create this path\e[0m"
                    writable_found=true
                    writable_paths+=("$pypath (creatable)")
                fi
            fi
            ((path_index++))
        done <<< "$sys_path"
        echo ""
    done

    # Update summary
    if $writable_found; then
        python_libhijack_summary="Writable Python paths found: ${writable_paths[*]}. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display shell history and history files
history_info() {
    echo -e "\n\n\e[1;34m[+] Gathering Shell History Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    echo -e "\e[1;33mCurrent Shell History:\e[0m"
    if [ -f ~/.bash_history ]; then
        cat ~/.bash_history
    else
        history
    fi
    # Add some spacing
    echo -e "\n"
    echo -e "\e[1;33mHistory Files Found:\e[0m"
    history_files=0
    while IFS= read -r -d '' file; do
        history_files=$((history_files + 1))
        if [ -r "$file" ]; then
            echo -e "\e[1;31m$file (Readable):\e[0m"
            cat "$file"
            # Add some spacing
            echo -e "\n"
        else
            echo "$file (Not readable)"
            # Add some spacing
            echo -e "\n"
        fi
    done < <(find / \( "${find_prune_expr[@]}" \) -prune -o -type f -name "*_history*" -print0 2>/dev/null)
    # Store formatted data for summary
    history_summary="Current history entries: $(history | wc -l); Found files: $history_files"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display editor artifacts that may contain sensitive information
editor_artifacts_info() {
    echo -e "\n\n\e[1;34m[+] Gathering Editor Artifact Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    echo -e "\e[1;33mNote:\e[0m These files can contain command/search history, recently opened files, and other sensitive content."

    local -a search_roots=()
    local -a candidates=()
    local -a sample_files=()
    local root
    local rel
    local file_path
    local found_any=false
    local found_count=0
    local readable_count=0

    # Common editor artifact paths relative to a user's home directory
    candidates=(
        ".viminfo"
        ".vim/viminfo"
        ".config/nvim/shada/main.shada"
        ".local/state/nvim/shada/main.shada"
        ".local/share/nvim/shada/main.shada"
        ".nano_history"
        ".lesshst"
        ".emacs.d/recentf"
        ".emacs.d/.recentf"
        ".emacs.d/places"
        ".emacs.d/bookmarks"
        ".config/Code/User/settings.json"
        ".config/Code/User/keybindings.json"
        ".config/VSCodium/User/settings.json"
        ".config/VSCodium/User/keybindings.json"
    )

    # Search current user, then common locations for other users
    if [ -n "$HOME" ] && [ -d "$HOME" ]; then
        search_roots+=("$HOME")
    fi
    if [ -d /root ]; then
        search_roots+=("/root")
    fi
    for root in /home/*; do
        if [ -d "$root" ]; then
            search_roots+=("$root")
        fi
    done

    for root in "${search_roots[@]}"; do
        for rel in "${candidates[@]}"; do
            file_path="$root/$rel"
            if [ -e "$file_path" ]; then
                found_any=true
                found_count=$((found_count + 1))
                if [ "${#sample_files[@]}" -lt 10 ]; then
                    sample_files+=("$file_path")
                fi
                if [ -r "$file_path" ]; then
                    readable_count=$((readable_count + 1))
                    echo -e "\e[1;31m$file_path (Readable):\e[0m"
                    if [[ "$file_path" == *.shada ]]; then
                        if command -v strings >/dev/null 2>&1; then
                            strings -a "$file_path" 2>/dev/null
                        else
                            cat "$file_path" 2>/dev/null
                        fi
                    else
                        cat "$file_path" 2>/dev/null
                    fi
                    echo -e "\n"
                else
                    echo -e "\e[1;33m$file_path (Not readable)\e[0m"
                    echo -e "\n"
                fi
            fi
        done
    done

    if ! $found_any; then
        echo -e "\e[1;31m[-] No common editor artifact files found in $HOME, /root, or /home/*.\e[0m"
        editor_artifacts_summary="No editor artifacts found."
    elif [ "$readable_count" -gt 0 ]; then
        editor_artifacts_summary="Review needed: Found ${found_count} editor artifact file(s) (${readable_count} readable). Examples: $(IFS=', '; echo "${sample_files[*]}")"
    else
        editor_artifacts_summary="Found ${found_count} editor artifact file(s), none readable. Examples: $(IFS=', '; echo "${sample_files[*]}")"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display /etc/hosts contents
hosts_file() {
    sec "/etc/hosts"
    if [ -r /etc/hosts ]; then
        grep -Ev '^[[:space:]]*(#|$)' /etc/hosts | while IFS= read -r line; do
            if [[ $line =~ ^(127\.|::1) ]]; then
                echo "    $line"
            else
                echo -e "    ${RED}${line}  (non-local)${RST}"
            fi
        done
    else
        echo -e "    ${RED}/etc/hosts not readable${RST}"
    fi
    endsec
}

# Function to display network interfaces and IP addresses
network_interfaces() {
    sec "Network Interfaces / IP Addresses"
    if command -v ip >/dev/null 2>&1; then
        ip -brief addr show | while read -r iface _state addr _; do
            echo -e "    ${YEL}${iface}${RST} -> ${addr:-No IP assigned}"
        done
    elif command -v ifconfig >/dev/null 2>&1; then
        ifconfig | awk '/^[a-z]/{i=$1} /inet /{print i, $2}' | while read -r iface ip; do
            echo -e "    ${YEL}${iface}${RST} -> $ip"
        done
    else
        echo -e "    ${RED}No interface tools (ip/ifconfig) found${RST}"
    fi
    endsec
}

# Function to display listening ports and associated processes.
# Keeps the BIND ADDRESS, which is the signal that matters:
#   0.0.0.0 / [::] / *  -> reachable from off-host
#   127.0.0.1 / [::1]   -> local-only; unfirewalled pivot/privesc target
listening_ports() {
    sec "Listening Ports and Associated Processes"
    local tool=""
    if command -v ss >/dev/null 2>&1; then tool=ss
    elif command -v netstat >/dev/null 2>&1; then tool=netstat; fi

    if [ -z "$tool" ]; then
        echo -e "    ${RED}No socket tools (ss/netstat) found${RST}"
        endsec; return
    fi
    [ "$(id -u)" -ne 0 ] && echo -e "    ${RED}(not root: process names may be hidden)${RST}"

    # Find the process field by signature so tcp/udp column drift doesn't matter:
    #   ss      -> proto $1, local $5, process starts with 'users:('
    #   netstat -> proto $1, local $4, program looks like '1234/sshd'
    local rows
    if [ "$tool" = ss ]; then
        rows=$(ss -tulnp 2>/dev/null | awk 'NR>1{p="-"; for(i=1;i<=NF;i++) if($i ~ /^users:/) p=$i; print $1, $5, p}')
    else
        rows=$(netstat -tulnp 2>/dev/null | awk '$1 ~ /^(tcp|udp)/{p="-"; for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\//) p=$i; print $1, $4, p}')
    fi

    if [ -z "$rows" ]; then
        echo -e "    ${GRN}No listening sockets found${RST}"
        endsec; return
    fi

    printf '%s\n' "$rows" | while read -r proto local proc; do
        [ -z "$proto" ] && continue
        case $local in
            0.0.0.0:*|\[::\]:*|\*:*) scope="${RED}external${RST}" ;;
            127.0.0.1:*|\[::1\]:*)   scope="${GRN}local-only${RST}" ;;
            *)                       scope="${YEL}other${RST}" ;;
        esac
        echo -e "    ${YEL}${proto}${RST}  ${local}  [${scope}]  ${proc}"
    done
    endsec
}

# Function to display routing table
routing_table() {
    sec "Routing Table"
    if command -v ip >/dev/null 2>&1; then ip route show | sed 's/^/    /'
    elif command -v route >/dev/null 2>&1; then route -n | sed 's/^/    /'
    else echo -e "    ${RED}No routing command available${RST}"; fi
    routing_summary=$( { command -v ip >/dev/null 2>&1 && ip route show || route -n 2>/dev/null; } | tr '\n' ';' )
    endsec
}

# Check current cmdline arguments
check_cmdline() {
    echo -e "\n\n\e[1;34m[+] Checking Current Command Line Arguments\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    if [ -r /proc/self/cmdline ]; then
        cmdline=$(tr '\0' ' ' < /proc/self/cmdline)
        echo -e "\e[1;33mCurrent Command Line:\e[0m $cmdline"
        cmdline_summary="Current Command Line: $cmdline"
    else
        echo -e "\e[1;31mCannot read /proc/self/cmdline\e[0m"
        cmdline_summary="Cannot read /proc/self/cmdline"
    fi
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Check environment variables for sensitive information
check_env_variables() {
    echo -e "\n\n\e[1;34m[+] Checking Environment Variables for Sensitive Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Define patterns to look for
    sensitive_patterns=("PASS" "PASSWORD" "TOKEN" "SECRET" "KEY" "AWS" "API" "DB" "CREDENTIAL" "CRED" "SQL")

    # Initialize the summary variable
    env_vars_summary="No sensitive information detected in environment variables."

    # Iterate through environment variables
    found_sensitive=0
    while IFS= read -r var; do
        for pattern in "${sensitive_patterns[@]}"; do
            if echo "$var" | grep -qi "$pattern"; then
                echo -e "\e[1;33m[!] Potential Sensitive Information:\e[0m $var"
                found_sensitive=1
                break
            fi
        done
    done < <(env)

    if [ $found_sensitive -eq 0 ]; then
        echo -e "\e[1;32m[+] No sensitive information detected in environment variables.\e[0m"
    else
        env_vars_summary="Sensitive environment variables detected. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# check SUID binaries
suid_check() {
    echo -e "\n\n\e[1;34m[+] Checking SUID Binaries\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Timeout for the SUID check (in seconds)
    timeout_duration=15

    # Find all SUID binaries with a timeout
    suid_binaries=$(timeout "$timeout_duration" find / \( "${find_prune_expr[@]}" \) -prune -o -type f -perm -4000 -print 2>/dev/null)
    
    # Check if the timeout occurred
    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] SUID check timed out after $timeout_duration seconds. Skipping...\e[0m"
    elif [ -z "$suid_binaries" ]; then
        echo -e "\e[1;31m[-] No SUID binaries found.\e[0m"
    else
        echo -e "\e[1;33m[!] SUID binaries found:\e[0m"

        suid_summary="SUID binaries detected. Review needed."

        # Highlight common dangerous SUID binaries
        while IFS= read -r binary; do
            binary_name=${binary##*/}
            case "$binary_name" in
                bash|sh|perl|python|python[0-9]*|ruby|lua|screen|tmux|zsh|dash|ksh|csh|tcsh|ash|fish)
                    echo -e "    \e[1;31m$binary\e[0m (Potentially dangerous: Interpreter)"
                    ;;
                passwd|chsh|chfn|newgrp)
                    echo -e "    \e[1;33m$binary\e[0m (Common, check for misconfigurations)"
                    ;;
                *)
                    echo -e "    $binary"
                    ;;
            esac
        done <<< "$suid_binaries"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Check SGID binaries
sgid_check() {
    echo -e "\n\n\e[1;34m[+] Checking SGID Binaries\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Timeout for the SGID check (in seconds)
    timeout_duration=15

    # Find all SGID binaries with a timeout
    sgid_binaries=$(timeout "$timeout_duration" find / \( "${find_prune_expr[@]}" \) -prune -o -type f -perm -2000 -print 2>/dev/null)
    
    # Check if the timeout occurred
    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] SGID check timed out after $timeout_duration seconds. Skipping...\e[0m"
    elif [ -z "$sgid_binaries" ]; then
        echo -e "\e[1;31m[-] No SGID binaries found.\e[0m"
    else
        echo -e "\e[1;33m[!] SGID binaries found:\e[0m"

        sgid_summary="SGID binaries detected. Review needed."

        # Highlight common dangerous SGID binaries
        while IFS= read -r binary; do
            binary_name=${binary##*/}
            case "$binary_name" in
                mail|write|wall|newgrp)
                    echo -e "    \e[1;31m$binary\e[0m (Potentially dangerous: Group access)"
                    ;;
                *)
                    echo -e "    $binary"
                    ;;
            esac
        done <<< "$sgid_binaries"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# check for cronjobs
cron_check() {
    echo -e "\n\n\e[1;34m[+] Checking Cron Jobs\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    # Initialize the summary variable as an array for accumulation
    cron_risks=()
    cron_summary="No writable cron jobs or misconfigurations detected."

    # Helper: analyze a PATH value using the same "non-normal" heuristics as path_info()
	    analyze_path_value() {
	        local path_value="$1"
	        local context_label="$2"
	        local indent="$3"
            local -a path_array=()
            local -a bad_entries=()
            local dir

	        if [ -z "$path_value" ]; then
	            echo -e "${indent}\e[1;31m[!] $context_label sets an empty PATH (non-normal)\e[0m"
	            cron_risks+=("Non-normal cron PATH in $context_label: empty PATH")
	            return
	        fi

        echo -e "${indent}\e[1;33m[!] PATH set in $context_label:\e[0m $path_value"
        echo -e "${indent}\e[1;33mPATH Entries:\e[0m"

        IFS=':' read -r -a path_array <<< "$path_value"
        for dir in "${path_array[@]}"; do
            if [ -z "$dir" ]; then
                echo -e "${indent}\e[1;31m(Empty entry - non-normal)\e[0m"
                bad_entries+=("(empty)")
            elif [ "$dir" = "." ]; then
                echo -e "${indent}\e[1;31m$dir (Current directory - non-normal)\e[0m"
                bad_entries+=(".")
            elif [ -d "$dir" ] && [ -w "$dir" ]; then
                echo -e "${indent}\e[1;31m$dir (Writable - non-normal)\e[0m"
                bad_entries+=("$dir")
            else
                echo -e "${indent}$dir"
            fi
        done

	        if [ ${#bad_entries[@]} -gt 0 ]; then
	            cron_risks+=("Non-normal cron PATH in $context_label: ${bad_entries[*]}")
	        fi
	    }

    # Helper: scan crontab-style text for PATH= / export PATH= lines and analyze them
    scan_cron_paths_from_stream() {
        local context_label="$1"
        local indent="$2"
        local line trimmed without_comment path_value
        local found_any=false

        while IFS= read -r line; do
            trimmed="${line#"${line%%[![:space:]]*}"}"
            [ -z "$trimmed" ] && continue
            [[ "$trimmed" == \#* ]] && continue

            without_comment="${trimmed%%\#*}"
            if [[ "$without_comment" =~ ^(export[[:space:]]+)?PATH[[:space:]]*=[[:space:]]*(\"[^\"]*\"|\'[^\']*\'|[^[:space:]]*) ]]; then
                path_value="${BASH_REMATCH[2]}"
                path_value="${path_value%"${path_value##*[![:space:]]}"}"

                # Strip surrounding single/double quotes
                if [[ "$path_value" =~ ^\"(.*)\"$ ]]; then
                    path_value="${BASH_REMATCH[1]}"
                elif [[ "$path_value" =~ ^\'(.*)\'$ ]]; then
                    path_value="${BASH_REMATCH[1]}"
                fi

                found_any=true
                analyze_path_value "$path_value" "$context_label" "$indent"
            fi
        done

        $found_any || true
    }

    # Helper function to check and display a single cron file/dir
    check_cron_item() {
        local item_path="$1"
        local item_type="$2"  # "file" or "dir"
        local indent="$3"

        if [ "$item_type" = "file" ] && [ -f "$item_path" ]; then
            echo -e "${indent}\e[1;33mContents of $item_path:\e[0m"
            cat "$item_path" | sed "s/^/${indent} /"
            if [ -r "$item_path" ]; then
                scan_cron_paths_from_stream "$item_path" "${indent} " < "$item_path"
            fi
            if [ -w "$item_path" ]; then
                echo -e "${indent}\e[1;31m[!] $item_path is writable! Potential security risk.\e[0m"
                cron_risks+=("$item_path is writable")
            else
                echo -e "${indent} \e[1;32m$item_path is not writable.\e[0m"
            fi
        elif [ "$item_type" = "dir" ] && [ -d "$item_path" ]; then
            local found_cron_file=false
            while IFS= read -r -d '' full_path; do
                local filename="${full_path##*/}"

                # Exclude certain files that are not actual cron jobs (like README, LICENSE, etc.)
                case "$filename" in
                    README|LICENSE|README.md|README.txt|apache2|nginx|httpd|apport|apt-compat|man-db|.placeholder|google-chrome|firefox|chromium|logrotate|dpkg|php)
                        continue
                        ;;
                esac

                found_cron_file=true
                echo -e "${indent}$full_path"
                if [ -f "$full_path" ]; then
                    cat "$full_path" | sed "s/^/${indent} /"
                    if [ -r "$full_path" ]; then
                        scan_cron_paths_from_stream "$full_path" "${indent} " < "$full_path"
                    fi
                    if [ -w "$full_path" ]; then
                        echo -e "${indent}\e[1;31m[!] $full_path is writable! Potential security risk.\e[0m"
                        cron_risks+=("$full_path is writable")
                    else
                        echo -e "${indent} \e[1;32m$full_path is not writable.\e[0m"
                    fi
                fi
                echo  # Spacing between files
            done < <(find "$item_path" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
            if ! $found_cron_file; then
                echo -e "${indent}\e[1;31mNo cron jobs found in $item_path\e[0m"
            fi
            # Check if the directory itself is writable
            if [ -w "$item_path" ]; then
                echo -e "${indent}\e[1;31m[!] Directory $item_path is writable! Potential security risk.\e[0m"
                cron_risks+=("$item_path directory is writable")
            fi
        else
            echo -e "${indent}\e[1;31m$item_path does not exist or is inaccessible.\e[0m"
        fi
    }

    # Check /etc/crontab
    echo -e "\e[1;33m[!] /etc/crontab:\e[0m"
    check_cron_item "/etc/crontab" "file" " "

    # Common cron directories to check (system-wide and user-specific)
    cron_dirs=(
        "/etc/cron.d"
        "/etc/cron.daily"
        "/etc/cron.hourly"
        "/etc/cron.monthly"
        "/etc/cron.weekly"
        "/var/spool/cron/crontabs"
    )

    # Check system-wide cron jobs
    echo -e "\n\e[1;33m[!] System-Wide Cron Jobs:\e[0m"
    for cron_dir in "${cron_dirs[@]}"; do
        check_cron_item "$cron_dir" "dir" " "
    done

    # Check user-specific cron jobs
    echo -e "\n\e[1;33m[!] User-Specific Cron Jobs:\e[0m"
    if command -v crontab >/dev/null 2>&1; then
        user_cron=$(crontab -l 2>/dev/null)
        if [ $? -eq 0 ] && [ -n "$user_cron" ]; then
            echo -e " \e[1;33mCrontab entries for $(whoami):\e[0m"
            echo "$user_cron" | sed 's/^/ /'
            scan_cron_paths_from_stream "crontab for $(whoami)" "  " <<< "$user_cron"
        else
            echo -e " \e[1;31mNo crontab entries for $(whoami).\e[0m"
        fi
    else
        echo -e " \e[1;31mCrontab is not installed or not available for this user.\e[0m"
    fi

    # Check for visible cron jobs in /var/log/syslog
    echo -e "\n\e[1;33m[!] Visible Cron Jobs from /var/log/syslog:\e[0m"
    syslog_cron=$(grep "CRON" /var/log/syslog 2>/dev/null | tail -n 20)  # Last 20 recent entries
    if [ -n "$syslog_cron" ]; then
        echo -e " \e[1;33mRecent CRON executions (from syslog):\e[0m"
        while IFS= read -r line; do
            # Highlight potential risks: e.g., non-root user or user-writable scripts
            if echo "$line" | grep -q "(root) CMD"; then
                echo -e " $line"  # Standard root cron
            else
                # Non-root or suspicious CMD (e.g., user script)
                echo -e " \e[1;31m$line\e[0m (Non-root or user-executable script - potential abuse vector)"
                cron_risks+=("Non-root cron execution detected in syslog")
            fi
        done <<< "$syslog_cron"
    else
        echo -e " \e[1;31mNo CRON entries found in /var/log/syslog.\e[0m"
    fi

    # Check for writable cron files (improved find with exclusions)
    echo -e "\n\e[1;33m[!] Writable Cron Files:\e[0m"
    writable_cron_found=false
    while IFS= read -r -d '' writable_cron_file; do
        if ! $writable_cron_found; then
            echo -e "\e[1;31m[!] Writable cron files detected! Potential security risk:\e[0m"
            cron_risks+=("Multiple writable cron files detected")
            writable_cron_found=true
        fi
        echo " $writable_cron_file"
    done < <(find /etc/cron* /var/spool/cron/ \( -path /proc -o -path /sys -o -path /nix -o -path /run \) -prune -o -type f -writable -print0 2>/dev/null)
    if ! $writable_cron_found; then
        echo -e " \e[1;31mNo writable cron files found.\e[0m"
    fi

    # Give user a hint to also check for cronjobs with pspy
    echo -e "\n\e[1;31m[!] Remember to also check for non-visible cronjobs using pspy!\e[0m"
    echo -e " \e[1;31m./pspy64 -pf -i 1000\e[0m"

    # Update summary based on accumulated risks
    if [ ${#cron_risks[@]} -gt 0 ]; then
        cron_summary="Risks detected: ${cron_risks[*]}. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# check file capabilities
capabilities_check() {
    echo -e "\n\n\e[1;34m[+] Checking Capabilities\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize the summary variable
    capabilities_summary="No dangerous file capabilities detected."

    # Timeout duration (in seconds)
    timeout_duration=15

    # Find files with capabilities using a timeout
    capabilities=$(timeout "$timeout_duration" getcap -r / 2>/dev/null)

    # Check if the timeout occurred
    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] Capabilities check timed out after $timeout_duration seconds. Skipping...\e[0m"
        capabilities_summary="Capabilities check timed out. Results incomplete."
    elif [ -z "$capabilities" ]; then
        echo -e "    \e[1;31mNo files with capabilities found.\e[0m"
    else
        echo -e "\e[1;33m[!] Files and their Capabilities:\e[0m"
        dangerous_found=0
        while IFS= read -r line; do
            # Highlight common dangerous capabilities
            if echo "$line" | grep -qE "(cap_setuid|cap_setgid|cap_dac_override|cap_net_admin|cap_net_raw|cap_sys_admin|cap_sys_chroot|cap_sys_ptrace|cap_sys_module)"; then
                echo -e "    \e[1;31m$line\e[0m (Potentially dangerous)"
                dangerous_found=1
            else
                echo -e "    $line"
            fi
        done <<< "$capabilities"

        if [ $dangerous_found -eq 1 ]; then
            capabilities_summary="Dangerous capabilities detected! Review needed."
        fi

    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

check_copy_fail_vuln() {
    # Detection-only check for "Copy Fail" (CVE-2026-31431):
    # algif_aead / authencesn AF_ALG local privilege escalation.
    # Read-only: no module loading, no mitigation changes, no exploitation.
    echo -e "\n\n\e[1;34m[+] Checking for Vulnerable Kernel: Copy Fail (CVE-2026-31431)\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    copy_fail_summary="Copy Fail (CVE-2026-31431) not detected / kernel appears patched."

    kernel_version=$(uname -r)
    echo -e "\e[1;33m[+] Kernel version:\e[0m $kernel_version"

    # strip distro suffix: 6.8.0-51-generic -> 6.8.0 ; 6.18.10-arch1-1 -> 6.18.10
    upstream="${kernel_version%%-*}"
    kmaj=$(echo "$upstream" | cut -d. -f1 | grep -oE '^[0-9]+'); kmaj=${kmaj:-0}
    kmin=$(echo "$upstream" | cut -d. -f2 | grep -oE '^[0-9]+'); kmin=${kmin:-0}
    kpat=$(echo "$upstream" | cut -d. -f3 | grep -oE '^[0-9]+'); kpat=${kpat:-0}

    # Enterprise distros backport the fix into their own version strings, so a raw
    # uname comparison is unreliable there -> defer to the vendor tracker.
    distro_id=""
    [ -r /etc/os-release ] && distro_id=$(. /etc/os-release; echo "${ID:-}")

    kernel_state="patched"   # patched | vulnerable | review | notaffected
    if [ "$kmaj" -lt 4 ] || { [ "$kmaj" -eq 4 ] && [ "$kmin" -lt 14 ]; }; then
        kernel_state="notaffected"                 # predates the 2017 regression (4.14)
    elif [ "$kmaj" -ge 7 ]; then
        kernel_state="patched"                     # mainline fix shipped in 7.0
    elif [ "$kmaj" -eq 6 ] && [ "$kmin" -eq 19 ]; then
        [ "$kpat" -lt 12 ] && kernel_state="vulnerable"
    elif [ "$kmaj" -eq 6 ] && [ "$kmin" -eq 18 ]; then
        [ "$kpat" -lt 22 ] && kernel_state="vulnerable"
    else
        kernel_state="review"                      # 4.14-6.17 / 6.x LTS: affected upstream, distros backport
    fi

    case "$distro_id" in
        ubuntu|debian|rhel|centos|rocky|almalinux|cloudlinux|fedora|amzn|ol|sles|sled|opensuse*|suse)
            [[ "$kernel_state" == "vulnerable" || "$kernel_state" == "patched" ]] && kernel_state="review"
            ;;
    esac

    case "$kernel_state" in
        vulnerable)
            echo -e "\e[1;31m[!] Vulnerable kernel: $kernel_version is below the fixed level (6.18.22 / 6.19.12 / 7.0).\e[0m"
            copy_fail_summary="VULNERABLE to Copy Fail (CVE-2026-31431): kernel $kernel_version. Patch and reboot. Review needed."
            ;;
        review)
            echo -e "\e[1;33m[?] Possibly vulnerable: $kernel_version may carry a backported fix - verify with your vendor.\e[0m"
            case "$distro_id" in
                ubuntu)            echo -e "\e[1;36m    pro fix CVE-2026-31431   (or check the matching USN)\e[0m";;
                debian)            echo -e "\e[1;36m    https://security-tracker.debian.org/tracker/CVE-2026-31431\e[0m";;
                rhel|centos|rocky|almalinux|cloudlinux|fedora|amzn|ol)
                                   echo -e "\e[1;36m    dnf updateinfo info CVE-2026-31431\e[0m";;
                sles|sled|suse|opensuse*)
                                   echo -e "\e[1;36m    zypper patches | grep -i CVE-2026-31431\e[0m";;
                *)                 echo -e "\e[1;36m    Check your distro's security tracker for CVE-2026-31431.\e[0m";;
            esac
            copy_fail_summary="Copy Fail (CVE-2026-31431): kernel $kernel_version needs a vendor patch check. Review needed."
            ;;
        notaffected)
            echo -e "\e[1;32m[+] Kernel predates the 4.14 regression - not affected.\e[0m"
            ;;
        *)
            echo -e "\e[1;32m[+] Kernel $kernel_version is at or above the fixed level - appears patched.\e[0m"
            ;;
    esac

    # --- Exposure context (passive reads only; does NOT trigger the bug) -------
    kconf="/boot/config-${kernel_version}"
    aead=""
    if [ -r "$kconf" ]; then
        grep -q '^CONFIG_CRYPTO_USER_API_AEAD=y' "$kconf" && aead="builtin"
        [ -z "$aead" ] && grep -q '^CONFIG_CRYPTO_USER_API_AEAD=m' "$kconf" && aead="module"
        [ -z "$aead" ] && aead="absent"
    elif [ -r /proc/config.gz ] && command -v zcat >/dev/null 2>&1; then
        zcat /proc/config.gz | grep -q '^CONFIG_CRYPTO_USER_API_AEAD=y' && aead="builtin"
        [ -z "$aead" ] && { zcat /proc/config.gz | grep -q '^CONFIG_CRYPTO_USER_API_AEAD=m' && aead="module"; }
        [ -z "$aead" ] && aead="absent"
    fi
    case "$aead" in
        builtin) echo -e "\e[1;33m[!] algif_aead is built into the kernel (modprobe blacklist will NOT mitigate).\e[0m";;
        module)  echo -e "\e[1;33m[+] algif_aead is a loadable module.\e[0m";;
        absent)  echo -e "\e[1;32m[+] CONFIG_CRYPTO_USER_API_AEAD not set - AEAD AF_ALG interface unavailable.\e[0m";;
        *)       echo -e "\e[1;33m[?] Kernel config not readable - cannot confirm algif_aead exposure.\e[0m";;
    esac

    if grep -rqsE 'install[[:space:]]+algif_aead[[:space:]]+/bin/(false|true)|^[[:space:]]*blacklist[[:space:]]+algif_aead' /etc/modprobe.d/ 2>/dev/null; then
        echo -e "\e[1;32m[+] modprobe mitigation for algif_aead is present.\e[0m"
        [ "$aead" = "builtin" ] && echo -e "\e[1;31m    [!] ...but the module is built-in, so this mitigation is ineffective here.\e[0m"
    fi

    lsmod 2>/dev/null | grep -q '^algif_aead' && echo -e "\e[1;33m[+] algif_aead module is currently loaded.\e[0m"

    # Informational only - the PoC happens to be Python, but the kernel is
    # exploitable regardless of whether Python is installed.
    if command -v python3 >/dev/null 2>&1; then
        echo -e "\e[1;33m[i] python3 present ($(python3 --version 2>&1 | awk '{print $2}')) - public PoC runtime available (informational).\e[0m"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check for vulnerable screen version (4.05.00 / 4.5.0)
check_screen_vuln() {
    echo -e "\n\n\e[1;34m[+] Checking for Vulnerable Services: Screen (4.5.0)\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    # Initialize summary
    screen_summary="Screen not vulnerable or not installed."
    
    if ! command -v screen >/dev/null 2>&1; then
        echo -e "\e[1;31m[-] Screen is not installed.\e[0m"
        return
    fi
    
    # Get screen version output
    screen_version_output=$(screen -v 2>/dev/null)
    if [ -z "$screen_version_output" ]; then
        echo -e "\e[1;31m[-] Unable to retrieve screen version.\e[0m"
        return
    fi
    
    echo -e "\e[1;33mScreen Version:\e[0m $screen_version_output"
    
    # Parse version (e.g., extract "4.05.00" from "Screen version 4.05.00 (GNU) 10-Dec-16")
    parsed_version=$(echo "$screen_version_output" | awk '{for(i=1;i<=NF;i++) if($i ~ /^[0-9]+\.[0-9]+\.[0-9]+$/) print $i;}' | head -1)
    
    if [ -z "$parsed_version" ]; then
        echo -e "\e[1;31m[-] Could not parse screen version.\e[0m"
        return
    fi
    
    # Check if exactly 4.05.00 (vulnerable version)
    if [[ "$parsed_version" == "4.05.00" ]]; then
        echo -e "\e[1;31m[!] VULNERABLE: Screen version $parsed_version detected (CVE-2017-5618).\e[0m"
        echo -e "\e[1;33m[+] This version is exploitable for root via buffer overflow.\e[0m"
        echo -e "\e[1;36m[+] Suggestion: Download and run the exploit from Exploit-DB:\e[0m"
        echo -e "  \e[4mwget https://www.exploit-db.com/download/41154 -O screenroot.sh\e[0m"
        echo -e "  \e[4mchmod +x screenroot.sh && ./screenroot.sh\e[0m"
        echo -e "  \e[4mFull Exploit: https://www.exploit-db.com/exploits/41154\e[0m"
        screen_summary="Screen 4.5.0 vulnerable. Use screenroot.sh exploit for root. Review needed."
    else
        echo -e "\e[1;32m[+] Screen version $parsed_version is not vulnerable (target: 4.05.00).\e[0m"
    fi
    
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check for PwnKit vulnerability (CVE-2021-4034)
check_pwnkit_vuln() {
    echo -e "\n\n\e[1;34m[+] Checking for PwnKit Vulnerability (CVE-2021-4034)\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize summary variable
    pwnkit_summary="PwnKit check completed."

    # Check if pkexec is installed
    if ! command -v pkexec &> /dev/null; then
        echo -e "\e[1;33m[-] pkexec not found. System not vulnerable to PwnKit.\e[0m"
        pwnkit_summary="pkexec not found. System not vulnerable to PwnKit."
        return
    fi

    # Get pkexec version
    pkexec_version=$(pkexec --version | head -n1 | awk '{print $NF}')
    echo -e "\e[1;33mpkexec version:\e[0m $pkexec_version"

    # Check if version is vulnerable (versions before 0.105 are vulnerable)
    # Note: The versioning scheme may vary between distributions
    # We'll use a more comprehensive check
        # Check if version is vulnerable (all < 0.120 are vulnerable unless patched downstream)
    if [[ "$pkexec_version" =~ ^0\.([0-9]{1,2}|1[01][0-9])$ ]]; then
        echo -e "\e[1;33mpkexec version $pkexec_version is older than 0.120.\e[0m"
        echo -e "\e[1;33m[!] This version is *potentially vulnerable* unless your distro has backported the patch.\e[0m"

        # Behavior test: run pkexec without arguments
        if pkexec 2>&1 | grep -q "Usage:"; then
            echo -e "\e[1;32m[+] pkexec appears patched (prints Usage correctly).\e[0m"
            pwnkit_summary="pkexec $pkexec_version — appears patched (Usage output OK)."
        else
            echo -e "\e[1;31m[!] pkexec behavior indicates vulnerability (does not print Usage).\e[0m"
            echo -e "\e[1;36m[-> ExploitDB]:\e[0m https://www.exploit-db.com/exploits/50649"
            echo -e "\e[1;36m[-> GitHub PoC]:\e[0m https://github.com/berdav/CVE-2021-4034"
            pwnkit_summary="pkexec $pkexec_version — vulnerable to CVE-2021-4034."
        fi
    else
        echo -e "\e[1;32m[+] pkexec $pkexec_version is >= 0.120 (safe).\e[0m"
        pwnkit_summary="pkexec $pkexec_version — safe."
    fi

    # Additional heuristic checks for vulnerability
    # Check if polkit policies directory is writable
    if [ -w "/usr/share/polkit-1/actions/" ] 2>/dev/null; then
        echo -e "\e[1;31m[!] Write access to polkit actions directory - potential PwnKit exploitation vector\e[0m"
        pwnkit_summary+=" Write access to polkit actions directory."
    fi

    # Check for GIO modules path vulnerability
    if [ -w "/usr/lib/x86_64-linux-gnu/gio/modules/" ] 2>/dev/null; then
        echo -e "\e[1;31m[!] Write access to GIO modules directory - potential PwnKit exploitation vector\e[0m"
        pwnkit_summary+=" Write access to GIO modules directory."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check for CVE-2017-16995 vulnerability
check_cve_2017_16995_vuln() {
    echo -e "\n\n\e[1;34m[+] Checking for CVE-2017-16995 Vulnerability\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize summary variable
    cve_2017_16995_summary="CVE-2017-16995 check completed."

    # Get kernel version
    kernel_version=$(uname -r)
    echo -e "\e[1;33m[+] Kernel version:\e[0m $kernel_version"

    # Extract major.minor version for comparison
    kernel_major_minor=$(echo "$kernel_version" | cut -d'-' -f1)
    
    # Check if kernel version is vulnerable (< 4.4.0-116)
    # We need to check both the kernel version and Ubuntu-specific version
    if version_lt "$kernel_major_minor" "4.4"; then
        echo -e "\e[1;31m[!] System is potentially vulnerable to CVE-2017-16995\e[0m"
        echo -e "\e[1;36m[-> ExploitDB]:\e[0m https://www.exploit-db.com/exploits/44298"
        echo -e "\e[1;33m[!] Vulnerability allows local privilege escalation via BPF ALU op sign extension bug\e[0m"
        cve_2017_16995_summary="System is potentially vulnerable to CVE-2017-16995 (BPF ALU op sign extension bug)."
    elif [[ "$kernel_major_minor" == "4.4" ]]; then
        # For 4.4.x kernels, check Ubuntu-specific version
        if [[ "$kernel_version" =~ 4\.4\.0-([0-9]+) ]]; then
            ubuntu_version=${BASH_REMATCH[1]}
            if [[ $ubuntu_version -lt 116 ]]; then
                echo -e "\e[1;31m[!] System is vulnerable to CVE-2017-16995\e[0m"
                echo -e "\e[1;36m[-> ExploitDB]:\e[0m https://www.exploit-db.com/exploits/44298"
                echo -e "\e[1;33m[!] Vulnerability allows local privilege escalation via BPF ALU op sign extension bug\e[0m"
                cve_2017_16995_summary="System is vulnerable to CVE-2017-16995 (BPF ALU op sign extension bug)."
            else
                echo -e "\e[1;32m[+] System is not vulnerable to CVE-2017-16995\e[0m"
                cve_2017_16995_summary="System is not vulnerable to CVE-2017-16995."
            fi
        else
            echo -e "\e[1;33m[?] Unable to determine Ubuntu-specific kernel version. Manual verification required.\e[0m"
            cve_2017_16995_summary="Unable to determine Ubuntu-specific kernel version for CVE-2017-16995 check."
        fi
    else
        echo -e "\e[1;32m[+] System is not vulnerable to CVE-2017-16995\e[0m"
        cve_2017_16995_summary="System is not vulnerable to CVE-2017-16995."
    fi

    # Additional checks for BPF functionality
    if [ -d "/proc/sys/net/core/bpf_jit_enable" ] 2>/dev/null; then
        bpf_jit_status=$(cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null)
        if [ "$bpf_jit_status" == "1" ]; then
            echo -e "\e[1;33m[!] BPF JIT is enabled, which may increase exploitation risk\e[0m"
        fi
    fi

    # Check for BPF-related files that might indicate vulnerability
    if [ -r "/proc/version_signature" ] 2>/dev/null; then
        version_signature=$(cat /proc/version_signature 2>/dev/null)
        if [[ "$version_signature" == *"Ubuntu 4.4.0-"* ]]; then
            echo -e "\e[1;33m[+] Ubuntu kernel detected: $version_signature\e[0m"
            # Extract Ubuntu version from signature
            if [[ "$version_signature" =~ Ubuntu\ 4\.4\.0-([0-9]+) ]]; then
                ubuntu_ver=${BASH_REMATCH[1]}
                if [[ $ubuntu_ver -lt 116 ]]; then
                    echo -e "\e[1;31m[!] Ubuntu kernel version is vulnerable to CVE-2017-16995\e[0m"
                    cve_2017_16995_summary="Ubuntu kernel version is vulnerable to CVE-2017-16995."
                fi
            fi
        fi
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check for CVE-2026-24061 (GNU InetUtils telnetd auth bypass).
# REMOTE pre-auth flaw, not a local privesc: telnetd passes the client-controlled
# USER env var (NEW-ENVIRON, RFC 1572) unsanitised into login(1), so a client
# sending USER=-f root makes telnetd run `login -f root`, and -f skips auth ->
# unauthenticated remote root. Affected: GNU inetutils 1.9.3 .. 2.7; fixed in 2.7-2.
# Because the vector is remote, this only FIRES when telnet is actually running /
# exposed; an installed-but-dormant daemon is reported quietly and not flagged.
# Detection only (presence + exposure + version). The daemon binary is never executed.
check_cve_2026_24061_vuln() {
    sec "Checking for CVE-2026-24061 (GNU InetUtils telnetd auth bypass)"
    cve_2026_24061_summary="GNU InetUtils telnetd not found; CVE-2026-24061 not applicable."

    # 1. Locate a telnet daemon binary (never run it - it's a network daemon)
    local bin="" c p
    for c in telnetd in.telnetd; do
        p=$(command -v "$c" 2>/dev/null) && { bin=$p; break; }
    done
    if [ -z "$bin" ]; then
        for p in /usr/sbin/telnetd /usr/sbin/in.telnetd /usr/libexec/telnetd /usr/local/sbin/telnetd; do
            [ -x "$p" ] && { bin=$p; break; }
        done
    fi
    if [ -z "$bin" ]; then
        echo -e "${GRN}No telnetd binary found.${RST}"
        endsec; return
    fi
    echo -e "${YEL}telnetd binary:${RST} $bin"

    # 2. EXPOSURE GATE - remote vector, so only proceed if telnet is reachable / will spawn
    local exposed=""
    if { command -v ss >/dev/null 2>&1 && ss -tlnp 2>/dev/null | grep -qE '[:.]23([^0-9]|$)'; } \
       || { command -v netstat >/dev/null 2>&1 && netstat -tlnp 2>/dev/null | grep -qE '[:.]23([^0-9]|$)'; }; then
        exposed="LISTENING on tcp/23"
    elif grep -RqsiE '^[[:space:]]*telnet' /etc/inetd.conf /etc/inetd.d 2>/dev/null; then
        exposed="enabled via inetd"
    elif [ -f /etc/xinetd.d/telnet ] && grep -qiE 'disable[[:space:]]*=[[:space:]]*no' /etc/xinetd.d/telnet 2>/dev/null; then
        exposed="enabled via xinetd"
    elif systemctl is-active --quiet inetutils-telnetd 2>/dev/null || systemctl is-enabled --quiet inetutils-telnetd 2>/dev/null; then
        exposed="service active/enabled"
    fi

    if [ -z "$exposed" ]; then
        echo -e "${GRN}telnetd is installed but not listening/enabled - remote vector inert, not firing.${RST}"
        cve_2026_24061_summary="telnetd installed but not exposed; CVE-2026-24061 not firing."
        endsec; return
    fi
    echo -e "${RED}Exposure:${RST} $exposed"

    # 3. BusyBox telnetd is a separate codebase and is NOT affected (even when exposed)
    local real; real=$(readlink -f "$bin" 2>/dev/null)
    [ -n "$real" ] && [ "$real" != "$bin" ] && echo -e "    ${YEL}resolves to:${RST} $real"
    local have_strings=0; command -v strings >/dev/null 2>&1 && have_strings=1
    if printf '%s' "$real" | grep -qi busybox \
       || { [ $have_strings -eq 1 ] && strings "$bin" 2>/dev/null | grep -qi busybox; }; then
        echo -e "${GRN}Exposed telnetd is BusyBox (separate codebase) - not affected by CVE-2026-24061.${RST}"
        cve_2026_24061_summary="BusyBox telnetd exposed; not affected by CVE-2026-24061."
        endsec; return
    fi

    # 4. Version: prefer the package manager (reflects backported fixes), then binary strings
    local pkgver="" upstream="" is_inetutils=0 s
    if command -v dpkg-query >/dev/null 2>&1; then
        pkgver=$(dpkg-query -W -f '${Version}' inetutils-telnetd 2>/dev/null)
        [ -n "$pkgver" ] && is_inetutils=1
    fi
    if [ -z "$pkgver" ] && command -v rpm >/dev/null 2>&1; then
        pkgver=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' inetutils 2>/dev/null | grep -vi 'not installed' | head -1)
        [ -n "$pkgver" ] && is_inetutils=1
    fi
    if [ $have_strings -eq 1 ]; then
        s=$(strings "$bin" 2>/dev/null | grep -iE 'inetutils[)[:space:]]*[0-9]' | head -1)
        [ -n "$s" ] && is_inetutils=1
        upstream=$(printf '%s' "$s" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    fi
    [ -z "$upstream" ] && [ -n "$pkgver" ] && upstream=$(printf '%s' "$pkgver" | sed -E 's/^[0-9]+://; s/[-+].*$//')

    [ -n "$pkgver" ]   && echo -e "${YEL}Package version:${RST} $pkgver"
    [ -n "$upstream" ] && echo -e "${YEL}Upstream version (parsed):${RST} $upstream"
    [ $is_inetutils -eq 0 ] && echo -e "${YEL}[?] Could not confirm GNU inetutils (vs netkit/other telnetd); treat as best-effort.${RST}"

    # 5. Authoritative on Debian/Ubuntu: a package revision >= 2.7-2 means the fix is in.
    #    (A backport onto an older base stays < 2.7-2, so only TRUE here is conclusive.)
    if [ -n "$pkgver" ] && command -v dpkg >/dev/null 2>&1 \
       && dpkg --compare-versions "$pkgver" ge "2.7-2" 2>/dev/null; then
        echo -e "${GRN}[+] Package revision >= 2.7-2: CVE-2026-24061 fix is present.${RST}"
        cve_2026_24061_summary="inetutils telnetd $pkgver exposed but patched (>= 2.7-2); CVE-2026-24061 fixed."
        endsec; return
    fi

    # 6. Exposed + not provably patched -> classify on the upstream range (1.9.3 .. 2.7 affected)
    if [ -z "$upstream" ]; then
        echo -e "${RED}[!] Exposed telnetd, version undetermined - cannot rule out CVE-2026-24061. Verify manually.${RST}"
        echo -e "${CYN}    [-> ref]:${RST} https://www.offsec.com/blog/cve-2026-24061/"
        cve_2026_24061_summary="Exposed telnetd, version unknown - cannot rule out CVE-2026-24061. Review needed."
    elif version_lt "$upstream" "1.9.3" || version_lt "2.7" "$upstream"; then
        echo -e "${GRN}[+] Exposed, but version $upstream is outside the affected 1.9.3-2.7 range.${RST}"
        cve_2026_24061_summary="telnetd $upstream exposed but outside CVE-2026-24061 affected range."
    else
        echo -e "${RED}[!] VULNERABLE: exposed inetutils telnetd $upstream is in the affected range (1.9.3-2.7).${RST}"
        echo -e "${RED}    CVE-2026-24061: unauthenticated REMOTE root via 'USER=-f root' ($exposed). Fixed in 2.7-2.${RST}"
        echo -e "${YEL}    Caveat: distros backport fixes WITHOUT bumping the upstream number -${RST}"
        echo -e "${YEL}    confirm against your package version (${pkgver:-unknown}) and distro security tracker.${RST}"
        echo -e "${CYN}    [-> ref]:${RST} https://www.offsec.com/blog/cve-2026-24061/"
        cve_2026_24061_summary="VULNERABLE: inetutils telnetd $upstream ($exposed) - CVE-2026-24061 remote root. Review needed."
    fi

    endsec
}

# Function to check for Dirty Pipe vulnerability (CVE-2022-0847)
check_dirty_pipe() {
    echo -e "\n\n\e[1;34m[+] Checking for Dirty Pipe Vulnerability (CVE-2022-0847)\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize summary variable
    dirty_pipe_summary="Dirty Pipe check completed."

    # Get kernel version
    kernel_version=$(uname -r)
    echo -e "\e[1;33m[+] Kernel version:\e[0m $kernel_version"

    # Extract major.minor.patch version for comparison
    kernel_major=$(echo "$kernel_version" | cut -d'.' -f1)
    kernel_minor=$(echo "$kernel_version" | cut -d'.' -f2)
    kernel_patch=$(echo "$kernel_version" | cut -d'.' -f3 | cut -d'-' -f1)

    # Check if kernel version is in the vulnerable range (5.8 to 5.17)
    # Vulnerable: 5.8 <= version < 5.17
    vulnerable=0
    
    if [[ $kernel_major -eq 5 ]]; then
        if [[ $kernel_minor -ge 8 && $kernel_minor -lt 17 ]]; then
            vulnerable=1
        elif [[ $kernel_minor -eq 17 && $kernel_patch -lt 0 ]]; then
            vulnerable=1
        fi
    elif [[ $kernel_major -eq 5 && $kernel_minor -eq 17 && $kernel_patch -eq 0 ]]; then
        # Special case for 5.17.0 which is still vulnerable
        vulnerable=1
    fi

    if [[ $vulnerable -eq 1 ]]; then
        echo -e "\e[1;31m[!] System is vulnerable to Dirty Pipe (CVE-2022-0847)\e[0m"
        echo -e "\e[1;36m[-> ExploitDB]:\e[0m https://www.exploit-db.com/exploits/50808"
        echo -e "\e[1;36m[-> GitHub PoC]:\e[0m https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits"
        echo -e "\e[1;33m[!] Vulnerability allows overwriting data in arbitrary read-only files\e[0m"
        echo -e "\e[1;33m[!] This can lead to privilege escalation by overwriting suid binaries\e[0m"
        dirty_pipe_summary="System is vulnerable to Dirty Pipe (CVE-2022-0847)."
    else
        echo -e "\e[1;32m[+] System is not vulnerable to Dirty Pipe (CVE-2022-0847)\e[0m"
        dirty_pipe_summary="System is not vulnerable to Dirty Pipe (CVE-2022-0847)."
    fi

    # Additional check: Verify if the system has been patched
    # Check for the specific commit that fixed the vulnerability
    # This is a more precise check but requires access to kernel source info
    
    # Check if we can determine distribution-specific patching
    if [ -f "/proc/version_signature" ]; then
        version_signature=$(cat /proc/version_signature 2>/dev/null)
        echo -e "\e[1;33m[+] Distribution info:\e[0m $version_signature"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check for Dirty COW vulnerability (CVE-2016-5195)
check_dirty_cow() {

    # robust version compare helper using sort -V
    ver_lt() {
        # returns 0 (true) if $1 < $2
        # use sort -V for version comparison
        [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]
    }
    
    # normalize kernel string to major.minor.patch (best-effort)
    kernel_normalize() {
        # Input: uname -r (e.g. "4.4.0-121-generic")
        # Output: "4.4.0"
        local k="$1"
        # extract first three numeric fields
        # allow things like "4.8", "4.8.3", "4.4.0-121-generic"
        # fallback: if cannot parse, return the raw string
        if [[ "$k" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
            printf "%s.%s.%s" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
        elif [[ "$k" =~ ^([0-9]+)\.([0-9]+) ]]; then
            printf "%s.%s.0" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
        else
            printf "%s" "$k"
        fi
    }

    echo -e "\n\n\e[1;34m[+] Checking for Dirty COW (CVE-2016-5195)\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    dirty_cow_summary="Dirty COW check completed."

    # get running kernel
    running_uname="$(uname -r 2>/dev/null || echo unknown)"
    running_kernel="$(kernel_normalize "$running_uname")"
    echo -e "\e[1;33m[+] uname -r:\e[0m $running_uname"
    echo -e "\e[1;33m[+] normalized kernel:\e[0m $running_kernel"

    # upstream thresholds (indicators only)
    # upstream fixed versions (indicators): 4.8.3 (mainline), 4.7.9, 4.4.x backports, and many distro-specific backports
    upstream_safe_main="4.8.3"

    vulnerable_indicator=false

    # If running kernel < 4.8.3 (upstream), it's an indicator of potential vulnerability
    if ver_lt "$running_kernel" "$upstream_safe_main"; then
        vulnerable_indicator=true
        echo -e "\e[1;33m[!] Kernel is older than upstream fixed version $upstream_safe_main - indicator of potential vulnerability.\e[0m"
    else
        echo -e "\e[1;32m[+] Kernel is >= $upstream_safe_main (upstream). This generally indicates the upstream fix is present.\e[0m"
    fi

    # Try to consult package manager for vendor fixes (best-effort)
    if command -v dpkg-query &>/dev/null; then
        # Debian/Ubuntu family
        pkg="$(dpkg-query -S "/boot/vmlinuz-$(uname -r)" 2>/dev/null | awk -F: '{print $1}' | head -n1)"
        if [ -n "$pkg" ]; then
            echo -e "\e[1;33m[+] Detected kernel package:\e[0m $pkg"
            # look for changelog mentioning Dirty COW CVE (best-effort)
            if dpkg-query -W -f='${Version}\n' "$pkg" 2>/dev/null; then
                if dpkg -s "$pkg" 2>/dev/null | grep -i "CVE-2016-5195" -q; then
                    echo -e "\e[1;32m[+] Package changelog mentions CVE-2016-5195 - vendor backport applied.\e[0m"
                    vulnerable_indicator=false
                else
                    echo -e "\e[1;33m[?] No explicit CVE mention in package metadata. Check vendor security advisory for $pkg.\e[0m"
                fi
            fi
        fi
    elif command -v rpm &>/dev/null; then
        # RHEL/CentOS/Fedora family
        # try to detect RPM package providing this kernel
        pkg="$(rpm -qf "/boot/vmlinuz-$(uname -r)" 2>/dev/null || true)"
        if [ -n "$pkg" ]; then
            echo -e "\e[1;33m[+] Detected kernel package:\e[0m $pkg"
            # try to check changelog for CVE mention (may require rpm-changelog)
            if rpm -q --changelog "$pkg" 2>/dev/null | grep -i "CVE-2016-5195" -q; then
                echo -e "\e[1;32m[+] RPM changelog mentions CVE-2016-5195 - vendor backport applied.\e[0m"
                vulnerable_indicator=false
            else
                echo -e "\e[1;33m[?] No CVE mention in RPM changelog. Check vendor advisory for $pkg.\e[0m"
            fi
        fi
    else
        echo -e "\e[1;33m[?] No package manager detected (dpkg/rpm). Rely on uname + vendor advisories.\e[0m"
    fi

    # Final decision (best-effort)
    if [ "$vulnerable_indicator" = true ]; then
        echo -e "\e[1;31m[!] System may be vulnerable to Dirty COW (CVE-2016-5195) — treat as HIGH RISK until vendor confirms.\e[0m"
        echo -e "\e[1;36m[-> Reference]:\e[0m https://nvd.nist.gov/vuln/detail/CVE-2016-5195"
        echo -e "\e[1;36m[-> GitHub GistPoC]:\e[0m https://gist.github.com/rverton/e9d4ff65d703a9084e85fa9df083c679"
        dirty_cow_summary="System may be vulnerable to Dirty COW (CVE-2016-5195). Confirm with vendor patch/changelog."
    else
        echo -e "\e[1;32m[+] Kernel appears to include upstream fix or vendor backport for Dirty COW. Confirm via vendor advisory.\e[0m"
        dirty_cow_summary="Kernel appears patched (upstream or vendor backport); verify with vendor advisory."
    fi

    # Optional: print distribution signature if present
    if [ -f /proc/version_signature ]; then
        echo -e "\e[1;33m[+] Distribution signature:\e[0m $(cat /proc/version_signature 2>/dev/null)"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to check for Netfilter vulnerabilities
check_netfilter_vulns() {
    echo -e "\n\n\e[1;34m[+] Checking for Netfilter Vulnerabilities\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize summary variable
    netfilter_summary="Netfilter vulnerability check completed."

    # Get kernel version
    kernel_version=$(uname -r)
    echo -e "\e[1;33m[+] Kernel version:\e[0m $kernel_version"

    # Extract major.minor.patch version for comparison
    kernel_major=$(echo "$kernel_version" | cut -d'.' -f1)
    kernel_minor=$(echo "$kernel_version" | cut -d'.' -f2)
    kernel_patch=$(echo "$kernel_version" | cut -d'.' -f3 | cut -d'-' -f1)

    # Function to compare versions
    ver_lt() {
        [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" != "$2" ]
    }
    
    ver_le() {
        [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
    }
    
    ver_gt() {
        [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" != "$1" ]
    }
    
    ver_ge() {
        [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
    }

    # Check for CVE-2021-22555 (Vulnerable: 2.6 - 5.11)
    cve_2021_22555_vulnerable=false
    if [[ $kernel_major -ge 2 && $kernel_major -le 5 ]]; then
        if [[ $kernel_major -eq 2 && $kernel_minor -ge 6 ]]; then
            cve_2021_22555_vulnerable=true
        elif [[ $kernel_major -eq 3 || $kernel_major -eq 4 ]]; then
            cve_2021_22555_vulnerable=true
        elif [[ $kernel_major -eq 5 && $kernel_minor -le 11 ]]; then
            cve_2021_22555_vulnerable=true
        elif [[ $kernel_major -eq 5 && $kernel_minor -eq 11 && $kernel_patch -eq 0 ]]; then
            cve_2021_22555_vulnerable=true
        fi
    fi

    if [[ "$cve_2021_22555_vulnerable" = true ]]; then
        echo -e "\e[1;31m[!] System is potentially vulnerable to CVE-2021-22555 (Netfilter heap out-of-bounds write)\e[0m"
        echo -e "\e[1;36m[-> Exploit]:\e[0m https://github.com/google/security-research/tree/master/pocs/linux/cve-2021-22555"
        echo -e "\e[1;33m[!] Affects kernel versions 2.6 - 5.11\e[0m"
        netfilter_summary+=" CVE-2021-22555 (heap OOB write);"
    else
        echo -e "\e[1;32m[+] System is not vulnerable to CVE-2021-22555\e[0m"
    fi

    # Check for CVE-2022-25636 (Vulnerable: 5.4 - 5.6.10)
    cve_2022_25636_vulnerable=false
    if [[ $kernel_major -eq 5 ]]; then
        if [[ $kernel_minor -eq 4 ]]; then
            cve_2022_25636_vulnerable=true
        elif [[ $kernel_minor -eq 5 ]]; then
            cve_2022_25636_vulnerable=true
        elif [[ $kernel_minor -eq 6 && $kernel_patch -le 10 ]]; then
            cve_2022_25636_vulnerable=true
        fi
    fi

    if [[ "$cve_2022_25636_vulnerable" = true ]]; then
        echo -e "\e[1;31m[!] System is potentially vulnerable to CVE-2022-25636 (Netfilter heap out-of-bounds write)\e[0m"
        echo -e "\e[1;36m[-> Exploit]:\e[0m https://github.com/Bonfee/CVE-2022-25636"
        echo -e "\e[1;33m[!] Affects kernel versions 5.4 - 5.6.10\e[0m"
        echo -e "\e[1;33m[!] WARNING: Exploitation may corrupt the kernel and require reboot\e[0m"
        netfilter_summary+=" CVE-2022-25636 (heap OOB write, may corrupt kernel);"
    else
        echo -e "\e[1;32m[+] System is not vulnerable to CVE-2022-25636\e[0m"
    fi

    # Check for CVE-2023-32233 (Vulnerable: up to 6.3.1)
    cve_2023_32233_vulnerable=false
    if [[ $kernel_major -lt 6 ]]; then
        cve_2023_32233_vulnerable=true
    elif [[ $kernel_major -eq 6 && $kernel_minor -eq 0 ]]; then
        cve_2023_32233_vulnerable=true
    elif [[ $kernel_major -eq 6 && $kernel_minor -eq 1 ]]; then
        cve_2023_32233_vulnerable=true
    elif [[ $kernel_major -eq 6 && $kernel_minor -eq 2 ]]; then
        cve_2023_32233_vulnerable=true
    elif [[ $kernel_major -eq 6 && $kernel_minor -eq 3 && $kernel_patch -le 1 ]]; then
        cve_2023_32233_vulnerable=true
    fi

    if [[ "$cve_2023_32233_vulnerable" = true ]]; then
        echo -e "\e[1;31m[!] System is potentially vulnerable to CVE-2023-32233 (Netfilter Use-After-Free)\e[0m"
        echo -e "\e[1;36m[-> Exploit]:\e[0m https://github.com/Liuk3r/CVE-2023-32233"
        echo -e "\e[1;33m[!] Affects kernel versions up to 6.3.1\e[0m"
        netfilter_summary+=" CVE-2023-32233 (UAF in nf_tables);"
    else
        echo -e "\e[1;32m[+] System is not vulnerable to CVE-2023-32233\e[0m"
    fi

    # Additional checks for Netfilter presence
    if lsmod | grep -q "nf_tables" 2>/dev/null; then
        echo -e "\e[1;33m[+] nf_tables module is loaded\e[0m"
    fi
    
    if lsmod | grep -q "nfnetlink" 2>/dev/null; then
        echo -e "\e[1;33m[+] nfnetlink module is loaded\e[0m"
    fi

    # If no vulnerabilities found
    if [[ "$cve_2021_22555_vulnerable" = false && "$cve_2022_25636_vulnerable" = false && "$cve_2023_32233_vulnerable" = false ]]; then
        netfilter_summary="No Netfilter vulnerabilities detected."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display mounted filesystems
filesystems_info() {
    echo -e "\n\n\e[1;34m[+] Gathering Filesystem Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    if command -v lsblk >/dev/null; then
        echo -e "\e[1;33mBlock Devices:\e[0m"
        lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT
    fi
    if command -v findmnt >/dev/null; then
        # Add some spacing
        echo -e "\n"
        echo -e "\e[1;33mMounted Filesystems:\e[0m"
        findmnt -D -o SOURCE,TARGET,FSTYPE,SIZE,USED,AVAIL,USE%,OPTIONS
    else
        echo -e "\e[1;33mMounted Filesystems:\e[0m"
        df -hT
        echo -e "\e[1;33mMount Options:\e[0m"
        mount | sort
    fi
    # Store formatted data for summary
    filesystems_summary=$(df -hT | tail -n +2 | awk '{print $NF " (" $1 ", " $2 ", " $6 ")" }' | tr '\n' '\n')
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display /etc/fstab contents
fstab_info() {
    echo -e "\n\n\e[1;34m[+] Gathering /etc/fstab Information\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    if [ -r /etc/fstab ]; then
        echo -e "\e[1;33m/etc/fstab Contents:\e[0m"
        grep -Ev '^[[:space:]]*(#|$)' /etc/fstab | while IFS= read -r line; do
            if echo "$line" | grep -qE 'noexec|nosuid|nodev'; then
                echo -e "\e[1;31m$line (Restricted options)\e[0m"
            else
                echo "$line"
            fi
        done
    else
        echo -e "\e[1;31m/etc/fstab not readable\e[0m"
    fi
    # Store formatted data for summary
    fstab_summary=$(cat /etc/fstab 2>/dev/null | grep -v '^#' | grep -v '^$' | tr '\n' '; ')
    echo -e "\n\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# check if we can write some critical files
check_writable_critical_files() {
    echo -e "\n\n\e[1;34m[+] Checking Writable Critical Files and Directories\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # List of critical files and directories to check
    critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/sudoers"
        "/etc/sudoers.d"
        "/etc/cron.d"
        "/etc/crontab"
        "/etc/ssh/sshd_config"
    )

    # Initialize the summary
    writable_files_summary="No writable critical files or directories detected."

    writable_files_found=0
    writable_directories_found=0

    for file in "${critical_files[@]}"; do
        if [ -e "$file" ]; then
            if [ -d "$file" ]; then
                # Check if the directory itself is writable
                if [ -w "$file" ]; then
                    echo -e "\e[1;31m[!] Writable Directory: $file (Potential Security Risk)\e[0m"
                    writable_directories_found=1
                fi
                # Check for writable files inside the directory
                while IFS= read -r -d '' writable_file; do
                    echo -e "\e[1;31m[!] Writable: $writable_file (Potential Security Risk)\e[0m"
                    writable_files_found=1
                done < <(find "$file" -type f -writable -print0 2>/dev/null)
            else
                # Check if the file is writable
                if [ -w "$file" ]; then
                    echo -e "\e[1;31m[!] Writable: $file (Potential Security Risk)\e[0m"
                    writable_files_found=1
                fi
            fi
        fi
    done

    # Update the summary
    if [ $writable_files_found -eq 0 ] && [ $writable_directories_found -eq 0 ]; then
        echo -e "\e[1;32m[+] No writable critical files or directories detected.\e[0m"
    else
        writable_files_summary="Writable critical files or directories detected. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# search for potentially interesting files
search_interesting_files() {
    echo -e "\n\n\e[1;34m[+] Searching for Potentially Interesting Files\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize the summary
    interesting_files_summary="No interesting files detected."

    # List of file patterns to search for
    file_patterns=(
        "*.xls"
        "*.xls*"
        "*.xltx"
        "*.csv"
        "*.od*"
        "*.doc"
        "*.doc*"
        "*.pdf"
        "*.pot"
        "*.pot*"
        "*.pp*"
        "*.key"
        "*.conf"
        "*.config"
        "*.cnf"
        "*.sh"
        "*.backup"
        "*.bak"
        "*.pem"
    )

    files_found=0

    find_args=()
    for pattern in "${file_patterns[@]}"; do
        [ ${#find_args[@]} -gt 0 ] && find_args+=(-o)
        find_args+=(-iname "$pattern")
    done

    interesting_results=$(mktemp "${TMPDIR:-/tmp}/magiclinpwn-interesting.XXXXXX") || {
        echo -e "\e[1;31m[-] Unable to create temporary file for interesting file search.\e[0m"
        echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
        return
    }
    find / \( "${find_prune_expr[@]}" \) -prune -o -type f \( "${find_args[@]}" \) -print 2>/dev/null |
        grep -Ev '/(lib|fonts|share|core)(/|$)' > "$interesting_results"

    # Iterate over patterns and group results without scanning the filesystem repeatedly.
    shopt -q nocasematch
    nocasematch_was_set=$?
    shopt -s nocasematch
    for pattern in "${file_patterns[@]}"; do
        echo -e "\n\e[1;33m[!] File pattern:\e[0m $pattern"
        results=$(
            while IFS= read -r found; do
                # shellcheck disable=SC2254
                case "$found" in
                    $pattern) printf '%s\n' "$found" ;;
                esac
            done < "$interesting_results"
        )

        if [ -z "$results" ]; then
            echo -e "    \e[1;31mNo files found with this pattern.\e[0m"
        else
            echo "$results" | sed 's/^/    /'
            files_found=1
        fi
    done
    [ "$nocasematch_was_set" -ne 0 ] && shopt -u nocasematch

    rm -f "$interesting_results"

    # Update the summary
    if [ $files_found -eq 1 ]; then
        interesting_files_summary="Potentially interesting files detected. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to search for interesting files in backup directories
check_backup_files() {
    echo -e "\n\n\e[1;34m[+] Checking for Interesting Files in Backup Directories\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize summary variable
    backup_files_summary="Backup directory check completed."

    # Define backup directories to check
    backup_dirs=("/var/backup" "/var/backups" "/backup" "/backups" "/opt/backup" "/opt/backups")

    # Define interesting file patterns
    interesting_patterns=(
        "*.key"
        "*.pem"
        "*.crt"
        "*.cert"
        "*.conf"
        "*.config"
        "*.sql"
        "*.db"
        "*.dump"
        "*.tar"
        "*.tar.gz"
        "*.zip"
        "*.bak"
        "*.old"
        "id_rsa"
        "id_dsa"
        ".*_history"
        "*.log"
        "shadow"
        "passwd"
        "*.env"
        ".env"
        ".*rc"
        ".*_profile"
        "*.secret*"
        "*password*"
        "*credential*"
        "*private*"
        "wp-config.php"
        "*.sql.gz"
        "*.mysql"
        "*.pg_dump"
        "*.aes*"
    )

    backup_find_args=()
    for pattern in "${interesting_patterns[@]}"; do
        [ ${#backup_find_args[@]} -gt 0 ] && backup_find_args+=(-o)
        backup_find_args+=(-iname "$pattern")
    done

    found_files=0

    # Check each backup directory
    for backup_dir in "${backup_dirs[@]}"; do
        if [ -d "$backup_dir" ]; then
            echo -e "\e[1;33m[+] Checking directory:\e[0m $backup_dir"

            # Search for interesting files in one traversal per backup directory.
            while IFS= read -r -d '' file; do
                if [ -f "$file" ] && [ -r "$file" ]; then
                    # Get file size and last modified time
                    file_size=$(stat -c%s "$file" 2>/dev/null || echo "unknown")
                    mod_time=$(stat -c%y "$file" 2>/dev/null | cut -d' ' -f1 || echo "unknown")

                    # Skip very large files (>100MB) to avoid performance issues
                    if [[ $file_size =~ ^[0-9]+$ ]] && [ "$file_size" -gt 104857600 ]; then
                        echo -e "\e[1;33m[!] Large file (skipped content check):\e[0m $file (\e[1;36mSize:\e[0m $((file_size/1024/1024))MB, \e[1;36mModified:\e[0m $mod_time)"
                        continue
                    fi

                    # For smaller files, show more details
                    echo -e "\e[1;32m[Found]:\e[0m $file (\e[1;36mSize:\e[0m $file_size bytes, \e[1;36mModified:\e[0m $mod_time)"

                    # Show file type
                    file_type=$(file -b "$file" 2>/dev/null || echo "unknown")
                    echo -e "  \e[1;36mType:\e[0m $file_type"

                    # For text files, show first few lines if they might contain sensitive info
                    if [[ "$file_type" == *"text"* ]] || [[ "$file" == *.conf ]] || [[ "$file" == *.config ]] || [[ "$file" == *.env ]]; then
                        # Check if file contains interesting content without printing it all
                        if grep -Iq -E "(password|secret|key|token|credential|private)" "$file" 2>/dev/null; then
                            echo -e "  \e[1;31m[!] May contain sensitive information\e[0m"
                            # Show sample lines with sensitive keywords (first 2 matches)
                            grep -I -m 2 -n -E "(password|secret|key|token|credential|private)" "$file" 2>/dev/null | head -n 2 | while IFS= read -r line; do
                                echo -e "    \e[1;35mSample:\e[0m ...$line..."
                            done
                        fi
                    fi

                    found_files=$((found_files + 1))
                fi
            done < <(find "$backup_dir" -type f \( "${backup_find_args[@]}" \) -print0 2>/dev/null)
            
            # Also check for hidden files and directories
            echo -e "\e[1;33m[+] Checking for hidden files in:\e[0m $backup_dir"
            while IFS= read -r -d '' hidden_file; do
                if [ -f "$hidden_file" ] && [ -r "$hidden_file" ]; then
                    file_size=$(stat -c%s "$hidden_file" 2>/dev/null || echo "unknown")
                    mod_time=$(stat -c%y "$hidden_file" 2>/dev/null | cut -d' ' -f1 || echo "unknown")
                    echo -e "\e[1;32m[Found Hidden]:\e[0m $hidden_file (\e[1;36mSize:\e[0m $file_size bytes, \e[1;36mModified:\e[0m $mod_time)"
                    found_files=$((found_files + 1))
                fi
            done < <(find "$backup_dir" -name ".*" -type f -not -name "." -not -name ".." -print0 2>/dev/null)
        fi
    done

    # Update summary
    if [ $found_files -gt 0 ]; then
        backup_files_summary="Found $found_files potentially interesting files in backup directories."
        echo -e "\e[1;31m[!] $found_files interesting files found in backup directories\e[0m"
        echo -e "\e[1;33m[!] Review these files for potential sensitive information\e[0m"
    else
        backup_files_summary="No interesting files found in backup directories."
        echo -e "\e[1;32m[+] No interesting files found in backup directories\e[0m"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# search and print content of readable mails
check_mail() {
    echo -e "\n\n\e[1;34m[+] Checking for Readable Emails in /var/mail/\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    mail_found=0

    # Loop through all mailboxes in /var/mail/
    for mailbox in /var/mail/*; do
        if [ -f "$mailbox" ] && [ -r "$mailbox" ]; then
            echo -e "\e[1;33m[!] Found Readable Mailbox:\e[0m $mailbox"
            echo -e "\e[1;36m[+] Full Content of $mailbox:\e[0m"
            cat "$mailbox" | sed 's/^/    /'
            echo -e "\e[1;35m----------------------------------------\e[0m"
            mail_found=1
        fi
    done

    if [ $mail_found -eq 0 ]; then
        echo -e "\e[1;31m[-] No readable mailboxes found in /var/mail/.\e[0m"
        mail_summary="No readable mailboxes found in /var/mail/."
    else
        mail_summary="Readable emails found in /var/mail/. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# search for potentially sensitive config files containing credentials
search_sensitive_content() {
    echo -e "\n\n\e[1;34m[+] Searching for Sensitive Content in Config Files\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize the summary
    sensitive_content_summary="No sensitive content detected in config files."

    # Variable to track if sensitive content is found
    sensitive_found=0

    # Directories to exclude (vendor code, documentation, libraries)
    exclude_pattern="/(vendor|node_modules|\.git|doc|docs|documentation|examples|test|tests|spec|cache|log|logs|tmp)/"

    # Patterns that indicate actual credential assignments (not just mentions)
    # These look for assignment operators near credential keywords
    credential_patterns=(
        # Direct assignments with optional quotes: password=, "password":, 'password' =>
        # Matches: password=x, password = x, "password": x, 'password' => x
        "['\"]?password['\"]?[[:space:]]*=>"           # PHP array: 'password' =>
        "['\"]?password['\"]?[[:space:]]*[=:][[:space:]]*[^=]"  # password= or password:
        "['\"]?passwd['\"]?[[:space:]]*=>"
        "['\"]?passwd['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?pwd['\"]?[[:space:]]*=>"
        "['\"]?pwd['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?secret['\"]?[[:space:]]*=>"
        "['\"]?secret['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?api_key['\"]?[[:space:]]*=>"
        "['\"]?api_key['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?apikey['\"]?[[:space:]]*=>"
        "['\"]?apikey['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?api[-_]?secret['\"]?[[:space:]]*=>"
        "['\"]?api[-_]?secret['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?auth[-_]?token['\"]?[[:space:]]*=>"
        "['\"]?auth[-_]?token['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?access[-_]?token['\"]?[[:space:]]*=>"
        "['\"]?access[-_]?token['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?private[-_]?key['\"]?[[:space:]]*=>"
        "['\"]?private[-_]?key['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?token['\"]?[[:space:]]*=>"
        "['\"]?token['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        'db[-_]?pass'
        'db[-_]?password'
        'mysql[-_]?pass'
        'mysql[-_]?password'
        'postgres[-_]?pass'
        'redis[-_]?pass'
        'mongo[-_]?pass'
        'smtp[-_]?pass'
        'mail[-_]?pass'
        'ftp[-_]?pass'
        'ssh[-_]?pass'
        'ldap[-_]?pass'
        'admin[-_]?pass'
        'root[-_]?pass'
        "['\"]?credentials['\"]?[[:space:]]*=>"
        "['\"]?credentials['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
        "['\"]?connectionstring['\"]?[[:space:]]*=>"
        "['\"]?connectionstring['\"]?[[:space:]]*[=:][[:space:]]*[^=]"
    )

    # Build combined regex pattern
    combined_pattern=$(IFS='|'; echo "${credential_patterns[*]}")

    # False positive patterns to filter out (code, comments, documentation)
    # These patterns indicate the line is code/docs rather than actual credentials
    filter_out_patterns=(
        '^\s*//'           # C-style line comments
        '^\s*\*'           # Multi-line comment continuation
        '^\s*#'            # Shell/conf comments
        '^\s*<!--'         # XML comments
        'function\s'       # Function definitions
        'public\s*function'
        'private\s*function'
        'protected\s*function'
        '\$this->'         # PHP method calls
        'return\s'         # Return statements
        '@param'           # PHPDoc
        '@return'
        '@throws'
        'password.*reset'  # Password reset routes/logic (not credentials)
        'password.*hash'   # Password hashing logic
        'password.*valid'  # Password validation
        'password.*confirm'
        'password.*match'
        'password.*check'
        'password.*request'
        'password.*email'
        'forgot.*password'
        'change.*password'
        'new.*password'
        'old.*password'
        'pass.*through'    # passthrough logic
        'pass.*able'       # passable variables
        '\$pass[A-Z]'      # camelCase variables like $passData
        '\$passthru'       # passthru variable
        'passes\('         # Method calls like passes()
        'passed\s'         # "passed" as past tense
        'passing\s'        # "passing" as gerund
        'will be passed'   # Documentation phrases
        'to be passed'
        'are passed'
        'is passed'
        'gets passed'
        'dynamically pass' # Framework boilerplate
        'pass along'
        'pass on'
        'pass calls'
        'pass methods'
        'pass dynamic'
        '->get\('          # Method chains
        '->post\('
        '->name\('
        'Controller@'      # Route definitions
        'filtersPass'      # Laravel method names
        'expressionPass'
        'OptionalCheck'
        'Authorization'
        'getAuthPassword'
        'storePasswordHash'
        'class\s+\w'       # Class definitions
        'interface\s+\w'
        'trait\s+\w'
        'namespace\s'
        'use\s+\w'         # Use statements
        'extends\s'
        'implements\s'
        '\* @'             # PHPDoc lines
    )

    filter_pattern=$(IFS='|'; echo "${filter_out_patterns[*]}")

    env_find_args=(
        -name ".env" -o
        -name ".env.*" -o
        -name "*.env"
    )

    config_find_args=(
        -name "*.cnf" -o
        -name "*.conf" -o
        -name "*.config" -o
        -name "*.ini" -o
        -name "*.cfg" -o
        -name "*.yml" -o
        -name "*.yaml" -o
        -name "*.properties" -o
        -name "*.xml" -o
        -name "*.json" -o
        -name "*.bak" -o
        -name "*.php" -o
        -name "*.inc" -o
        -name ".htpasswd" -o
        -name ".pgpass" -o
        -name "credentials*" -o
        -name "*credentials*"
    )

    echo -e "\e[1;33m[*] Searching .env files (high-value targets)...\e[0m"

    # First, specifically search for .env files (often contain credentials)
    while IFS= read -r -d '' file; do
        [[ "$file" =~ $exclude_pattern ]] && continue
        # For .env files, show any line with values (they're almost always sensitive)
        matches=$(grep -v '^\s*#' "$file" 2>/dev/null | grep -v '^\s*$' | grep '=' | head -20)
        if [ -n "$matches" ]; then
            echo -e "\n\e[1;33m[!] ENV File:\e[0m $file"
            echo "$matches" | sed 's/^/    /'
            sensitive_found=1
        fi
    done < <(find / \( "${find_prune_expr[@]}" \) -prune -o -type f \( "${env_find_args[@]}" \) -print0 2>/dev/null)

    echo -e "\n\e[1;33m[*] Searching config files for credential patterns...\e[0m"

    # Search various config file types (including PHP)
    while IFS= read -r -d '' file; do
        [[ "$file" =~ $exclude_pattern ]] && continue
        # Search for credential patterns, then filter out false positives
        matches=$(grep -iE --color=always "$combined_pattern" "$file" 2>/dev/null | \
                  grep -ivE "$filter_pattern" | \
                  head -10)
        if [ -n "$matches" ]; then
            echo -e "\n\e[1;33m[!] File:\e[0m $file"
            echo "$matches" | sed 's/^/    /'
            sensitive_found=1
        fi
    done < <(find / \( "${find_prune_expr[@]}" \) -prune -o -type f \( "${config_find_args[@]}" \) -print0 2>/dev/null)

    # Update the summary
    if [ $sensitive_found -eq 1 ]; then
        sensitive_content_summary="Sensitive content detected in config files. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# search for SSH private keys
search_ssh_private_keys() {
    echo -e "\n\n\e[1;34m[+] Searching for SSH Private Keys\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize the summary
    ssh_keys_summary="No SSH private keys found in common locations."

    # Get the script's absolute path
    script_path=$(realpath "$0")

    # Target common locations for SSH private keys
    target_dirs=(
        "/root"
        "/home"
        "/etc/ssh"
    )

    results_found=0

    for dir in "${target_dirs[@]}"; do
        if [ -d "$dir" ]; then
            # Use find to locate files, excluding the script itself, and then search for "PRIVATE KEY"
            while IFS= read -r -d '' file; do
                if grep -q "PRIVATE KEY" "$file" 2>/dev/null; then
                    echo -e "\e[1;33m[!] File:\e[0m $file"
                    grep --color=always "PRIVATE KEY" "$file" 2>/dev/null | sed 's/^/    /'
                    results_found=1
                fi
            done < <(find "$dir" -type f ! -path "$script_path" -print0 2>/dev/null)
        fi
    done

    # Update the summary based on results
    if [ $results_found -eq 1 ]; then
        ssh_keys_summary="SSH private keys detected. Review the findings for potential sensitive information."
    fi

    if [ $results_found -eq 0 ]; then
        echo -e "\e[1;31m[-] No SSH private keys found in common locations.\e[0m"
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# check writable systemd related files
check_systemd_writable() {
    echo -e "\n\n\e[1;34m[+] Checking systemd-related Privilege Escalation Vectors\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize the summary
    systemd_summary="No writable systemd files or misconfigurations detected."

    # Timeout duration
    timeout_duration=30

    # Check writable .service files
    echo -e "\e[1;33m[!] Searching for Writable .service Files...\e[0m"
    writable_services=$(timeout "$timeout_duration" find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -name "*.service" -writable 2>/dev/null)
    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] Writable .service file check timed out.\e[0m"
    elif [ -z "$writable_services" ]; then
        echo -e "\e[1;31m[-] No writable .service files found.\e[0m"
    else
        echo -e "\e[1;33m[!] Writable .service Files Found:\e[0m"
        echo "$writable_services" | sed 's/^/    /'
        systemd_summary="Writable .service files detected. Review for privilege escalation opportunities."
    fi

    # Check writable binaries executed by services
    echo -e "\n\e[1;33m[!] Searching for Writable Binaries Executed by Services...\e[0m"
    writable_binaries=()
    while IFS= read -r -d '' service_file; do
        binary=$(awk -F= '/^[[:space:]]*ExecStart=/ {print $2}' "$service_file" 2>/dev/null |
            sed -E 's/^[[:space:]-]+//; s/^"([^"]+)".*/\1/; s/^'\''([^'\'']+)'\''.*/\1/' |
            awk 'NF {print $1; exit}')
        binary=$(realpath "$binary" 2>/dev/null)
        if [ -n "$binary" ] && [ -w "$binary" ]; then
            writable_binaries+=("$binary (from $service_file)")
        fi
    done < <(find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -name "*.service" -print0 2>/dev/null)
    if [ ${#writable_binaries[@]} -eq 0 ]; then
        echo -e "\e[1;31m[-] No writable binaries executed by services found.\e[0m"
    else
        echo -e "\e[1;33m[!] Writable Binaries Executed by Services Found:\e[0m"
        printf "    %s\n" "${writable_binaries[@]}"
        systemd_summary="Writable binaries executed by services detected. Review for potential abuse."
    fi

    # Check writable folders in systemd PATH
    echo -e "\n\e[1;33m[!] Searching for Writable Folders in systemd PATH...\e[0m"
    systemd_paths=$(systemctl show --property=UnitPath 2>/dev/null | cut -d= -f2 | tr ':' '\n')
    writable_dirs=()
    for dir in $systemd_paths; do
        if [ -d "$dir" ] && [ -w "$dir" ]; then
            writable_dirs+=("$dir")
        fi
    done
    if [ ${#writable_dirs[@]} -eq 0 ]; then
        echo -e "\e[1;31m[-] No writable folders in systemd PATH found.\e[0m"
    else
        echo -e "\e[1;33m[!] Writable Folders in systemd PATH Found:\e[0m"
        printf "    %s\n" "${writable_dirs[@]}"
        systemd_summary="Writable folders in systemd PATH detected. Check for privilege escalation opportunities."
    fi

    # Check writable timers
    echo -e "\n\e[1;33m[!] Searching for Writable Timers...\e[0m"
    writable_timers=$(timeout "$timeout_duration" find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system -type f -name "*.timer" -writable 2>/dev/null)
    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] Writable timer check timed out.\e[0m"
    elif [ -z "$writable_timers" ]; then
        echo -e "\e[1;31m[-] No writable timers found.\e[0m"
    else
        echo -e "\e[1;33m[!] Writable Timers Found:\e[0m"
        echo "$writable_timers" | sed 's/^/    /'
        systemd_summary="Writable timers detected. Investigate for potential abuse."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# check for writable files and folders
check_writable_by_user() {
    echo -e "\n\n\e[1;34m[+] Checking Files and Directories Writable by Current User\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    # Initialize variables
    writable_files_dirs_summary="No writable files or directories detected for the current user."
    user_writable_files=""
    user_writable_dirs=""

    # Timeout for the check (in seconds)
    timeout_duration=30
    current_user=$(whoami)

    local excluded_dirs=(
        "/proc"
        "/sys"
        "/dev"
        "/run"
        "/tmp"
        "/var/tmp"
        "/var/cache"
        "/var/log"
        "/var/run"
        "/mnt/cdrom"
    )

    # Build prune expression correctly
    local prune_expr=""
    for dir in "${excluded_dirs[@]}"; do
        if [ -d "$dir" ]; then
            if [ -z "$prune_expr" ]; then
                prune_expr="-path $dir -prune"
            else
                prune_expr="$prune_expr -o -path $dir -prune"
            fi
        fi
    done

    # Handle /home/*/ separately since -path doesn't support wildcards
    if [ -d "/home" ]; then
        # Find all user directories in /home (top level only)
        while IFS= read -r home_dir; do
            if [ -n "$home_dir" ]; then
                if [ -z "$prune_expr" ]; then
                    prune_expr="-path $home_dir -prune"
                else
                    prune_expr="$prune_expr -o -path $home_dir -prune"
                fi
            fi
        done < <(find /home -maxdepth 1 -type d -not -path "/home" 2>/dev/null)
    fi

    # Combine prune expressions
    if [ -n "$prune_expr" ]; then
        prune_expr="( $prune_expr )"
    fi

    echo -e "\e[1;33m[!] Searching for Files Writable by $current_user...\e[0m"
    
    if [ -n "$prune_expr" ]; then
        user_writable_files=$(timeout "$timeout_duration" find / $prune_expr -o \( -type f -writable -print \) 2>/dev/null)
    else
        user_writable_files=$(timeout "$timeout_duration" find / -type f -writable -print 2>/dev/null)
    fi

    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] Writable file check timed out after $timeout_duration seconds. Skipping...\e[0m"
    elif [ -z "$user_writable_files" ]; then
        echo -e "\e[1;31m[-] No files writable by $current_user found.\e[0m"
    else
        echo -e "\e[1;33m[!] Files Writable by $current_user:\e[0m"
        echo "$user_writable_files" | sed 's/^/    /'
        writable_files_dirs_summary="Writable files detected for the current user. Review needed."
    fi

    echo -e "\n\e[1;33m[!] Searching for Directories Writable by $current_user...\e[0m"
    
    if [ -n "$prune_expr" ]; then
        user_writable_dirs=$(timeout "$timeout_duration" find / $prune_expr -o \( -type d -writable -print \) 2>/dev/null)
    else
        user_writable_dirs=$(timeout "$timeout_duration" find / -type d -writable -print 2>/dev/null)
    fi

    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] Writable directory check timed out after $timeout_duration seconds. Skipping...\e[0m"
    elif [ -z "$user_writable_dirs" ]; then
        echo -e "\e[1;31m[-] No directories writable by $current_user found.\e[0m"
    else
        echo -e "\e[1;33m[!] Directories Writable by $current_user:\e[0m"
        echo "$user_writable_dirs" | sed 's/^/    /'
        # Only update summary if it hasn't been set by files
        if [ "$writable_files_dirs_summary" = "No writable files or directories detected for the current user." ]; then
            writable_files_dirs_summary="Writable directories detected for the current user. Review needed."
        else
            writable_files_dirs_summary="Writable files and directories detected for the current user. Review needed."
        fi
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

check_world_writable() {
    echo -e "\n\n\e[1;34m[+] Checking World-Writable Files and Directories\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    world_writable_summary="No world-writable files or directories detected."
    world_writable_files=""
    world_writable_dirs=""

    timeout_duration=30

    local excluded_dirs=(
        "/proc"
        "/sys"
        "/dev"
        "/run"
        "/tmp"
        "/var/tmp"
        "/var/cache"
        "/var/log"
        "/var/run"
        "/mnt/cdrom"
    )

    # Build prune expression correctly
    local prune_expr=""
    for dir in "${excluded_dirs[@]}"; do
        if [ -d "$dir" ]; then
            if [ -z "$prune_expr" ]; then
                prune_expr="-path $dir -prune"
            else
                prune_expr="$prune_expr -o -path $dir -prune"
            fi
        fi
    done

    echo -e "\e[1;33m[!] Searching for World-Writable Files (-perm -o+w)...\e[0m"

    if [ -n "$prune_expr" ]; then
        world_writable_files=$(timeout "$timeout_duration" find / \( $prune_expr \) -o \( -type f -perm -o+w -print \) 2>/dev/null)
    else
        world_writable_files=$(timeout "$timeout_duration" find / -type f -perm -o+w -print 2>/dev/null)
    fi

    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] World-writable file check timed out after $timeout_duration seconds. Skipping...\e[0m"
    elif [ -z "$world_writable_files" ]; then
        echo -e "\e[1;31m[-] No world-writable files found.\e[0m"
    else
        echo -e "\e[1;33m[!] World-Writable Files:\e[0m"
        # Printing red if file is in /etc
        echo "$world_writable_files" | while IFS= read -r file; do
            if [[ "$file" == /etc/* ]]; then
                echo -e "    \e[1;31m$file\e[0m"
            else
                echo "    $file"
            fi
        done
        world_writable_summary="World-writable files detected. Review needed."
    fi

    echo -e "\n\e[1;33m[!] Searching for World-Writable Directories (-perm -o+w)...\e[0m"

    if [ -n "$prune_expr" ]; then
        world_writable_dirs=$(timeout "$timeout_duration" find / \( $prune_expr \) -o \( -type d -perm -o+w -print \) 2>/dev/null)
    else
        world_writable_dirs=$(timeout "$timeout_duration" find / -type d -perm -o+w -print 2>/dev/null)
    fi

    if [ $? -eq 124 ]; then
        echo -e "\e[1;31m[-] World-writable directory check timed out after $timeout_duration seconds. Skipping...\e[0m"
    elif [ -z "$world_writable_dirs" ]; then
        echo -e "\e[1;31m[-] No world-writable directories found.\e[0m"
    else
        echo -e "\e[1;33m[!] World-Writable Directories:\e[0m"
        # Printing red if directory is /etc
        echo "$world_writable_dirs" | while IFS= read -r dir; do
            if [[ "$dir" == /etc/* ]]; then
                echo -e "    \e[1;31m$dir\e[0m"
            else
                echo "    $dir"
            fi
        done
        world_writable_summary="World-writable directories detected. Review needed."
    fi

    if [ -n "$world_writable_files" ] && [ -n "$world_writable_dirs" ]; then
        world_writable_summary="World-writable files and directories detected. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to search for potential credentials in log files
search_credentials_in_logs() {
    echo -e "\n\n\e[1;34m[+] Searching for Credentials in Log Files\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"

    log_files=(
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/syslog"
        "/var/log/httpd/access_log"
        "/var/log/apache2/access.log"
        "/var/log/nginx/access.log"
        "/var/log/mysql/error.log"
        "/var/log/mariadb/mariadb.log"
        "/var/log/postgresql/postgresql.log"
        "/var/log/samba/log.smbd"
    )

    # Improved regex pattern to capture both key and value
    patterns="([a-zA-Z0-9_-]*(user|username|login|pass|password|passwd|pw|token|secret)[a-zA-Z0-9_-]*)=([^&\" ]+)"

    credentials_found=0

    for log in "${log_files[@]}"; do
        if [ -f "$log" ]; then
            matches=$(grep -Eio "$patterns" "$log" 2>/dev/null | sort -u)  # Sort and remove duplicates
            if [ -n "$matches" ]; then
                echo -e "\e[1;33m[!] Potential Credentials Found in:\e[0m $log"
                echo "$matches" | sed 's/^/    /'
                credentials_found=1
            fi
        fi
    done

    if [ $credentials_found -eq 0 ]; then
        echo -e "\e[1;31m[-] No credentials found in log files.\e[0m"
        log_credentials_summary="No credentials found in log files."
    else
        log_credentials_summary="Potential credentials found in log files. Review needed."
    fi

    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
}

# Function to display processes running as root
root_processes_info() {
    echo -e "\n\n\e[1;34m[+] Gathering Processes Running as Root\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    echo -e "\e[1;33mProcesses Running as Root:\e[0m"
    root_process_count=0
    while IFS= read -r line; do
        root_process_count=$((root_process_count + 1))
        if echo "$line" | grep -qE "systemd|apache|mysql|postgres|ssh|ftp|smb|http|nginx|docker|lxd"; then
            echo -e "\e[1;31m$line (Potentially exploitable service)\e[0m"
        else
            echo "$line"
        fi
    done < <(ps -eo user=,pid=,ppid=,stat=,comm=,args= 2>/dev/null | awk '$1 == "root"')
    # Store formatted data for summary
    root_processes_summary="Root processes: $root_process_count"
    echo -e "\n\e[1;32m--------------------------------------------------------------------------\e[0m"
}

print_summary() {
    echo -e "\n\e[1;34m[+] Summary\e[0m"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    
    highlight_summary() {
        local summary_text=$1
        if echo "$summary_text" | grep -q "Review needed"; then
            echo -e "\e[1;31m$summary_text\e[0m"
        else
            echo "$summary_text"
        fi
    }

    echo -e "\e[1;33m[OS Information]:\e[0m $os_info_summary"
    
    # Format user information properly with new lines
    echo -e "\e[1;33m[User Information]:\e[0m"
    echo -e "$user_info_summary" | while IFS= read -r line; do echo " $line"; done
    
    echo -e "\e[1;33m[PATH Information]:\e[0m $path_info_summary"
    echo -e "\e[1;33m[Logged In Users]:\e[0m $logged_users_summary"
    echo -e "\e[1;33m[Shell History]:\e[0m $history_summary"
    echo -e "\e[1;33m[Routing Information]:\e[0m $routing_summary"
    echo -e "\e[1;33m[Command Line]:\e[0m $cmdline_summary"
    echo -e "\e[1;33m[Editor Artifacts]:\e[0m $(highlight_summary "$editor_artifacts_summary")"
    echo -e "\e[1;33m[Sudo Privileges]:\e[0m $(highlight_summary "$sudo_priv_summary")"
    echo -e "\e[1;33m[Doas Configuration]:\e[0m $(highlight_summary "$doas_summary")"
    echo -e "\e[1;33m[Python Library Hijacking]:\e[0m $(highlight_summary "$python_libhijack_summary")"
    echo -e "\e[1;33m[Environment Variables]:\e[0m $(highlight_summary "$env_vars_summary")"
    echo -e "\e[1;33m[SUID Binaries]:\e[0m $(highlight_summary "$suid_summary")"
    echo -e "\e[1;33m[SGID Binaries]:\e[0m $(highlight_summary "$sgid_summary")"
    echo -e "\e[1;33m[Cron Jobs]:\e[0m $(highlight_summary "$cron_summary")"
    echo -e "\e[1;33m[Capabilities]:\e[0m $(highlight_summary "$capabilities_summary")"
    echo -e "\e[1;33m[Copy Fail Vulnerability]:\e[0m $(highlight_summary "$copy_fail_summary")"
    echo -e "\e[1;33m[Screen Vulnerability]:\e[0m $(highlight_summary "$screen_summary")"
    echo -e "\e[1;33m[PwnKit Vulnerability]:\e[0m $(highlight_summary "$pwnkit_summary")"
    echo -e "\e[1;33m[CVE-2017-16995 Vulnerability]:\e[0m $(highlight_summary "$cve_2017_16995_summary")"
    echo -e "\e[1;33m[CVE-2026-24061 Vulnerability]:\e[0m $(highlight_summary "$cve_2026_24061_summary")"
    echo -e "\e[1;33m[Dirty Pipe Vulnerability]:\e[0m $(highlight_summary "$dirty_pipe_summary")"
    echo -e "\e[1;33m[Dirty COW Vulnerability]:\e[0m $(highlight_summary "$dirty_cow_summary")"
    echo -e "\e[1;33m[Netfilter Vulnerabilities]:\e[0m $(highlight_summary "$netfilter_summary")"
    echo -e "\e[1;33m[Critical Writable Files]:\e[0m $(highlight_summary "$writable_files_summary")"
    echo -e "\e[1;33m[Writable Files]:\e[0m $(highlight_summary "$writable_files_dirs_summary")"
    echo -e "\e[1;33m[World-Writable Files]:\e[0m $(highlight_summary "$world_writable_summary")"
    echo -e "\e[1;33m[Interesting Files]:\e[0m $(highlight_summary "$interesting_files_summary")"
    echo -e "\e[1;33m[Backup Files]:\e[0m $(highlight_summary "$backup_files_summary")"
    echo -e "\e[1;33m[Sensitive Content]:\e[0m $(highlight_summary "$sensitive_content_summary")"
    echo -e "\e[1;33m[SSH Private Keys]:\e[0m $(highlight_summary "$ssh_keys_summary")"
    echo -e "\e[1;33m[Log Credentials]:\e[0m $(highlight_summary "$log_credentials_summary")"
    echo -e "\e[1;33m[Email Readability]:\e[0m $(highlight_summary "$mail_summary")"
    echo -e "\e[1;33m[Docker Detection]:\e[0m $docker_summary"
    echo -e "\e[1;33m[Systemd Configurations]:\e[0m $(highlight_summary "$systemd_summary")"
    echo -e "\e[1;33m[Filesystem Information]:\e[0m $filesystems_summary"
    echo -e "\e[1;33m[/etc/fstab Information]:\e[0m $fstab_summary"
    echo -e "\e[1;33m[Root Processes]:\e[0m $root_processes_summary"
    echo -e "\e[1;32m--------------------------------------------------------------------------\e[0m"
    echo -e "\e[1;34m[+] Use Linux Exploit Suggester to find additional exploits: https://github.com/The-Z-Labs/linux-exploit-suggester\e[0m"
}

# ---- Run order -------------------------------------------------------------
# Bail before anything else if root: privesc enumeration is pointless as root,
# every -writable/-readable test passes, and you'd just print a wall of noise.
check_if_root

clear
ascii_art
echo

# Ordered list of checks. Each function prints its own header/rule and sets its
# summary_* variable, so this loop is all the driver needs. check_ad_integration
# now runs AFTER clear, so its output is no longer wiped off the screen.
checks=(
    os_info
    check_ad_integration
    user_info
    logged_users_info
    sudo_check
    doas_check
    path_info
    python_libhijack_check
    history_info
    editor_artifacts_info
    hosts_file
    network_interfaces
    listening_ports
    routing_table
    check_env_variables
    check_cmdline
    suid_check
    sgid_check
    cron_check
    capabilities_check
    check_copy_fail_vuln
    check_screen_vuln
    check_pwnkit_vuln
    check_cve_2017_16995_vuln
    check_dirty_pipe
    check_dirty_cow
    check_netfilter_vulns
    check_cve_2026_24061_vuln
    filesystems_info
    fstab_info
    check_writable_critical_files
    search_interesting_files
    check_backup_files
    check_mail
    search_sensitive_content
    search_ssh_private_keys
    search_credentials_in_logs
    check_systemd_writable
    check_writable_by_user
    check_world_writable
    root_processes_info
)

for chk in "${checks[@]}"; do
    "$chk"
done

print_summary