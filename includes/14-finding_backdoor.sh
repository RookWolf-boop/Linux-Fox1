#!/usr/bin/env bash
set -euo pipefail

# 14-finding_backdoor.sh
# Automated backdoor detection and removal script for Linux systems

scan_network_ports() {
	echo "[+] Step 1: Scanning for suspicious listening ports..."
	if command -v ss >/dev/null 2>&1; then
		ss -plnt 2>/dev/null || true
	else
		netstat -plnt 2>/dev/null || true
	fi
	echo ""
}

inspect_suspicious_processes() {
	echo "[+] Step 2: Inspecting suspicious processes..."
	echo "[i] Review output for non-standard ports or services"
	echo ""
	read -rp "Enter PID to inspect (or press Enter to skip): " pid || pid=""

	if [[ -n "${pid:-}" && -d "/proc/$pid" ]]; then
		echo "[+] Command line:"
		tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true
		echo ""
		echo "[+] Executable path:"
		readlink -f "/proc/$pid/exe" 2>/dev/null || true
		echo ""
	fi
}

check_persistence_systemd() {
	echo "[+] Step 4.1: Checking systemd persistence..."
	grep -R "ExecStart" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null \
		| grep -E "/tmp|/var/tmp|/dev/shm|/home|bash -c|python -c|nc |socat" \
		|| echo "    None found"
	echo ""
}

check_persistence_cron() {
	echo "[+] Step 4.2: Checking cron jobs..."
	[[ -f /etc/crontab ]] && cat /etc/crontab || echo "    /etc/crontab not found"
	echo ""
	ls -la /etc/cron.* 2>/dev/null || true
	echo ""
	crontab -l 2>/dev/null || echo "    No user crontab"
	echo ""
}

check_persistence_shell() {
	echo "[+] Step 4.3: Checking shell startup files..."
	local suspicious_files=(/etc/profile /etc/bash.bashrc "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.profile")
	for file in "${suspicious_files[@]}"; do
		[[ -f "$file" ]] || continue
		echo "[i] $file"
		grep -E "curl|wget|nc |socat|/tmp|/dev/shm|base64" "$file" 2>/dev/null || true
	done
	echo ""
}

check_suid_sgid_binaries() {
	echo "[+] Checking SUID/SGID binaries..."
	find / -type f \( -perm -4000 -o -perm -2000 \) -mtime -30 2>/dev/null | while read -r f; do
		ls -lh "$f" 2>/dev/null || true
	done
	echo ""
}

check_hidden_processes() {
	echo "[+] Checking for hidden processes..."
	local proc_pids ps_pids hidden
	proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's|/proc/||' | sort -n)
	ps_pids=$(ps -eo pid --no-headers 2>/dev/null | sort -n)

	hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids")) || true
	if [[ -n "$hidden" ]]; then
		echo "[!] Hidden processes:"
		echo "$hidden"
	else
		echo "    None found"
	fi
	echo ""
}

check_rootkit_indicators() {
	echo "[+] Checking for rootkit indicators..."

	if [[ -f /etc/ld.so.preload ]]; then
		echo "[!] /etc/ld.so.preload exists"
		cat /etc/ld.so.preload
	else
		echo "    No LD_PRELOAD hooks"
	fi
	echo ""

	lsmod 2>/dev/null | grep -vE "^(Module|ip_tables|nf_|xt_|x_tables)" | head -20 || true
	echo ""
}

check_ssh_backdoors() {
	echo "[+] Checking SSH backdoors..."
	find /root /home -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
		local count
		count=$(wc -l < "$keyfile")
		echo "    $keyfile ($count keys)"
		head -3 "$keyfile"
	done
	echo ""

	grep -E "PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|AllowUsers|AllowTcpForwarding" \
		/etc/ssh/sshd_config 2>/dev/null | grep -v "^#" || true
	echo ""
}

check_suspicious_connections() {
	echo "[+] Checking suspicious network connections..."
	if command -v ss >/dev/null 2>&1; then
		ss -tnp 2>/dev/null | grep ESTAB | grep -v "127.0.0.1\|::1" | head -20 || true
	else
		netstat -antp 2>/dev/null | grep ESTABLISHED | head -20 || true
	fi
	echo ""
}

check_suspicious_locations() {
	echo "[+] Step 3: Checking common backdoor locations..."
	local locations=(/tmp /var/tmp /dev/shm "$HOME/.cache" /usr/local/bin /opt)
	for loc in "${locations[@]}"; do
		[[ -d "$loc" ]] || continue
		echo "[i] $loc"
		find "$loc" -type f -executable -mtime -7 2>/dev/null || true
	done
	echo ""
}

generate_report() {
	local report="/tmp/backdoor_scan_$(date +%Y%m%d_%H%M%S).txt"
	echo "[+] Generating report..."
	{
		echo "=========================================="
		echo "Backdoor Detection Report"
		echo "Generated: $(date)"
		echo "Hostname: $(hostname)"
		echo "=========================================="
		echo ""
		echo "=== Network Ports ==="
		scan_network_ports
		echo "=== Suspicious Locations ==="
		check_suspicious_locations
		echo "=== Systemd Persistence ==="
		check_persistence_systemd
		echo "=== Cron Jobs ==="
		check_persistence_cron
		echo "=== SUID/SGID Binaries ==="
		check_suid_sgid_binaries
		echo "=== Hidden Processes ==="
		check_hidden_processes
		echo "=== Rootkit Indicators ==="
		check_rootkit_indicators
		echo "=== SSH Backdoors ==="
		check_ssh_backdoors
		echo "=== Network Connections ==="
		check_suspicious_connections
	} > "$report"
	echo "[+] Report saved to $report"
}

interactive_removal() {
	echo "[+] Interactive Removal"
	echo ""

	read -rp "Remove systemd service name (Enter to skip): " service || service=""
	if [[ -n "$service" ]]; then
		sudo systemctl stop "$service" 2>/dev/null || true
		sudo systemctl disable "$service" 2>/dev/null || true
		sudo rm -f "/etc/systemd/system/$service.service" || true
		sudo systemctl daemon-reload
		echo "[+] Service removed"
	fi

	echo ""
	read -rp "Remove file path (Enter to skip): " file || file=""
	if [[ -n "$file" && -f "$file" ]]; then
		sudo rm -f "$file"
		echo "[+] File removed"
	fi

	echo ""
	read -rp "Kill PID (Enter to skip): " pid || pid=""
	if [[ -n "$pid" ]]; then
		sudo kill -9 "$pid" 2>/dev/null || true
		echo "[+] Process killed"
	fi
}

main_backdoor_menu() {
	while true; do
		echo ""
		echo "=========================================="
		echo "   Backdoor Detection & Removal Tool"
		echo "=========================================="
		echo "1. Full Scan"
		echo "2. Network Ports"
		echo "3. Persistence Mechanisms"
		echo "4. Advanced Checks (SUID/Hidden/Rootkits)"
		echo "5. SSH Backdoor Check"
		echo "6. Network Connections"
		echo "7. Generate Report"
		echo "8. Interactive Removal"
		echo "9. Exit"
		echo ""
		read -rp "Choice: " choice || choice=""

		case "$choice" in
			1)
				scan_network_ports
				check_suspicious_locations
				check_persistence_systemd
				check_persistence_cron
				check_persistence_shell
				;;
			2) scan_network_ports ;;
			3)
				check_persistence_systemd
				check_persistence_cron
				check_persistence_shell
				;;
			4)
				check_suid_sgid_binaries
				check_hidden_processes
				check_rootkit_indicators
				;;
			5) check_ssh_backdoors ;;
			6) check_suspicious_connections ;;
			7) generate_report ;;
			8) interactive_removal ;;
			9) break ;;
			*) echo "[!] Invalid option" ;;
		esac
	done
}

invoke_finding_backdoor() {
	echo "[+] Starting backdoor detection..."
	main_backdoor_menu
	echo "[+] Done."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	invoke_finding_backdoor
fi
