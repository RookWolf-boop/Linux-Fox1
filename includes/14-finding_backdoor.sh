#!/usr/bin/env bash
set -euo pipefail

# 14-finding_backdoor.sh
# Automated backdoor detection and removal script for Linux systems
# Identifies listening network backdoors, persistence mechanisms, and removes them

scan_network_ports() {
	echo "[+] Step 1: Scanning for suspicious listening ports..."
	ss -plnt 2>/dev/null || netstat -plnt 2>/dev/null
	echo ""
}

inspect_suspicious_processes() {
	echo "[+] Step 2: Inspecting suspicious processes..."
	echo "[i] Review the above output for non-standard ports, unexpected programs,"
	echo "    or services bound to 0.0.0.0 that shouldn't be."
	echo ""
	read -p "Enter PID to inspect (or press Enter to skip): " pid
	
	if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
		echo "[+] Command line for PID $pid:"
		tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "Unable to read cmdline"
		echo ""
		echo "[+] Executable path:"
		readlink -f "/proc/$pid/exe" 2>/dev/null || echo "Unable to read exe"
		echo ""
	fi
}

check_persistence_systemd() {
	echo "[+] Step 4.1: Checking systemd persistence..."
	local suspicious_dirs="/tmp|/var/tmp|/dev/shm|/home|bash -c|python -c|nc |socat"
	
	echo "[i] Suspicious systemd ExecStart entries:"
	grep -R "ExecStart" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null | \
		grep -E "$suspicious_dirs" || echo "    None found"
	echo ""
}

check_persistence_cron() {
	echo "[+] Step 4.2: Checking cron jobs..."
	
	echo "[i] System crontabs:"
	[ -f /etc/crontab ] && cat /etc/crontab || echo "    /etc/crontab not found"
	
	echo ""
	echo "[i] System cron directories:"
	ls -la /etc/cron.* 2>/dev/null || echo "    No cron directories found"
	
	echo ""
	echo "[i] Current user crontab:"
	crontab -l 2>/dev/null || echo "    No crontab for current user"
	echo ""
}

check_persistence_shell() {
	echo "[+] Step 4.3: Checking shell startup files for persistence..."
	local suspicious_files=(
		"/etc/profile"
		"/etc/bash.bashrc"
		"$HOME/.bashrc"
		"$HOME/.bash_profile"
		"$HOME/.profile"
	)
	
	for file in "${suspicious_files[@]}"; do
		if [ -f "$file" ]; then
			echo "[i] Checking $file..."
			grep -E "curl|wget|nc |socat|/tmp|/dev/shm|base64" "$file" 2>/dev/null || true
		fi
	done
	echo ""
}

check_suspicious_locations() {
	echo "[+] Step 3: Checking common backdoor locations..."
	local locations=("/tmp" "/var/tmp" "/dev/shm")
	
	for loc in "${locations[@]}"; do
		if [ -d "$loc" ]; then
			echo "[i] Suspicious executables in $loc:"
			find "$loc" -type f -executable -mtime -7 2>/dev/null || echo "    None found"
		fi
	done
	echo ""
}

interactive_removal() {
	echo "[+] Interactive Removal Mode"
	echo ""
	
	read -p "Remove a systemd service? (y/N): " remove_service
	if [[ "$remove_service" =~ ^[Yy]$ ]]; then
		read -p "Enter service name: " service_name
		if [ -n "$service_name" ]; then
			sudo systemctl stop "$service_name" 2>/dev/null || true
			sudo systemctl disable "$service_name" 2>/dev/null || true
			sudo rm -f "/etc/systemd/system/$service_name.service" 2>/dev/null || true
			sudo systemctl daemon-reload
			echo "[+] Service $service_name removed"
		fi
	fi
	
	echo ""
	read -p "Remove a file? (y/N): " remove_file
	if [[ "$remove_file" =~ ^[Yy]$ ]]; then
		read -p "Enter full path to file: " file_path
		if [ -n "$file_path" ] && [ -f "$file_path" ]; then
			sudo rm -f "$file_path"
			echo "[+] File $file_path removed"
		fi
	fi
	
	echo ""
	read -p "Kill a process? (y/N): " kill_proc
	if [[ "$kill_proc" =~ ^[Yy]$ ]]; then
		read -p "Enter PID: " pid
		if [ -n "$pid" ]; then
			sudo kill "$pid" 2>/dev/null || sudo kill -9 "$pid" 2>/dev/null || echo "[!] Failed to kill PID $pid"
			echo "[+] Process $pid terminated"
		fi
	fi
	
	echo ""
	echo "[+] Verifying cleanup..."
	ss -plnt 2>/dev/null || netstat -plnt 2>/dev/null
}

automated_scan() {
	echo "=========================================="
	echo "   Backdoor Detection & Removal Tool"
	echo "=========================================="
	echo ""
	
	scan_network_ports
	check_suspicious_locations
	check_persistence_systemd
	check_persistence_cron
	check_persistence_shell
	
	echo "[+] Scan complete. Review the output above."
	echo ""
	
	read -p "Proceed with interactive removal? (y/N): " proceed
	if [[ "$proceed" =~ ^[Yy]$ ]]; then
		interactive_removal
	fi
}

invoke_finding_backdoor() {
	echo "[+] Starting backdoor detection..."
	automated_scan
	echo "[+] Done."
}

# If executed directly, run the entrypoint. If sourced, do nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	invoke_finding_backdoor "$@"
fi
