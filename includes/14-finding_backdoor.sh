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

check_suid_sgid_binaries() {
	echo "[+] Checking for suspicious SUID/SGID binaries..."
	echo "[i] SUID/SGID files modified in last 30 days:"
	
	find / -type f -perm -4000 -o -perm -2000 -mtime -30 2>/dev/null | while read -r file; do
		echo "    $file"
		ls -lh "$file" 2>/dev/null
	done
	
	echo ""
	echo "[i] Non-standard SUID binaries (not in /usr/bin, /bin, /usr/sbin, /sbin):"
	find / -type f -perm -4000 -o -perm -2000 ! -path "/usr/bin/*" ! -path "/bin/*" ! -path "/usr/sbin/*" ! -path "/sbin/*" 2>/dev/null || echo "    None found"
	echo ""
}

check_hidden_processes() {
	echo "[+] Checking for hidden processes..."
	echo "[i] Comparing /proc vs ps output (rootkit detection):"
	
	local proc_pids ps_pids
	proc_pids=$(ls -d /proc/[0-9]* 2>/dev/null | sed 's/\/proc\///' | sort -n)
	ps_pids=$(ps -eo pid --no-headers | sort -n)
	
	local hidden
	hidden=$(comm -23 <(echo "$proc_pids") <(echo "$ps_pids"))
	
	if [ -n "$hidden" ]; then
		echo "[!] WARNING: Hidden processes detected:"
		echo "$hidden" | while read -r pid; do
			if [ -d "/proc/$pid" ]; then
				echo "    PID: $pid | Exe: $(readlink -f /proc/$pid/exe 2>/dev/null || echo 'unknown')"
			fi
		done
	else
		echo "    No hidden processes detected"
	fi
	echo ""
}

check_rootkit_indicators() {
	echo "[+] Checking for rootkit indicators..."
	
	echo "[i] Checking for LD_PRELOAD hooks:"
	if [ -f /etc/ld.so.preload ]; then
		echo "[!] /etc/ld.so.preload exists:"
		cat /etc/ld.so.preload
	else
		echo "    /etc/ld.so.preload not found (good)"
	fi
	
	echo ""
	echo "[i] Checking for kernel module backdoors:"
	lsmod | grep -vE "^Module|ip_tables|nf_|xt_|x_tables" | head -20
	
	echo ""
	echo "[i] Suspicious kernel modules (not signed or from unusual paths):"
	for mod in /lib/modules/$(uname -r)/kernel/drivers/*.ko 2>/dev/null; do
		if [ -f "$mod" ]; then
			modinfo "$mod" 2>/dev/null | grep -E "filename|vermagic" | head -2
		fi
	done | head -10
	echo ""
}

check_ssh_backdoors() {
	echo "[+] Checking SSH for backdoors..."
	
	echo "[i] Checking authorized_keys files:"
	find /root /home -name "authorized_keys" 2>/dev/null | while read -r keyfile; do
		if [ -f "$keyfile" ]; then
			local count=$(wc -l < "$keyfile")
			if [ "$count" -gt 0 ]; then
				echo "    $keyfile ($count keys)"
				cat "$keyfile" | head -3
			fi
		fi
	done
	
	echo ""
	echo "[i] Checking SSH config for suspicious settings:"
	if [ -f /etc/ssh/sshd_config ]; then
		grep -E "PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|AllowUsers|AllowTcpForwarding" /etc/ssh/sshd_config 2>/dev/null | grep -v "^#" || echo "    Default settings"
	fi
	echo ""
}

check_suspicious_connections() {
	echo "[+] Checking for suspicious network connections..."
	
	echo "[i] Established connections to external IPs:"
	ss -tnp 2>/dev/null | grep ESTAB | grep -v "127.0.0.1\|::1" | head -20
	
	echo ""
	echo "[i] Processes with unusual network activity:"
	netstat -antp 2>/dev/null | grep ESTABLISHED | awk '{print $7}' | cut -d'/' -f2 | sort | uniq -c | sort -rn | head -10
	echo ""
}

generate_report() {
	local report_file="/tmp/backdoor_scan_$(date +%Y%m%d_%H%M%S).txt"
	echo "[+] Generating comprehensive report..."
	
	{
		echo "=========================================="
		echo "   Backdoor Detection Report"
		echo "   Generated: $(date)"
		echo "   Hostname: $(hostname)"
		echo "=========================================="
		echo ""
		
		echo "=== Network Ports ==="
		ss -plnt 2>/dev/null || netstat -plnt 2>/dev/null
		echo ""
		
		echo "=== Suspicious File Locations ==="
		for loc in "/tmp" "/var/tmp" "/dev/shm" "/usr/local/bin" "/opt"; do
			if [ -d "$loc" ]; then
				echo "--- $loc ---"
				find "$loc" -type f -executable -mtime -7 2>/dev/null || echo "None"
			fi
		done
		echo ""
		
		echo "=== systemd Persistence ==="
		grep -R "ExecStart" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null | grep -E "/tmp|/var/tmp|/dev/shm|/home|bash -c"
		echo ""
		
		echo "=== Cron Jobs ==="
		cat /etc/crontab 2>/dev/null
		crontab -l 2>/dev/null
		echo ""
		
		echo "=== SUID/SGID Binaries (recent) ==="
		find / -type f \( -perm -4000 -o -perm -2000 \) -mtime -30 2>/dev/null | head -20
		echo ""
		
		echo "=== SSH Authorized Keys ==="
		find /root /home -name "authorized_keys" 2>/dev/null -exec echo "{}:" \; -exec cat {} \;
		echo ""
		
		echo "=== Active Connections ==="
		ss -tnp 2>/dev/null | grep ESTAB
		echo ""
		
	} > "$report_file"
	
	echo "[+] Report saved to: $report_file"
	echo "[i] You can review it with: cat $report_file"
}

check_suspicious_locations() {
	echo "[+] Step 3: Checking common backdoor locations..."
	local locations=("/tmp" "/var/tmp" "/dev/shm" "$HOME/.cache" "/usr/local/bin" "/opt")
	
	for loc in "${locations[@]}"; do
		if [ -d "$loc" ]; then
			echo "[i] Suspicious executables in $loc:"
			find "$loc" -type f -executable -mtime -7 2>/dev/null || echo "    None found"
		fi
	done
	echo ""
}

backdoor_location_submenu() {
	local locations=("/tmp" "/var/tmp" "/dev/shm" "/home/*/.cache" "/usr/local/bin" "/opt")
	
	while true; do
		echo ""
		echo "=========================================="
		echo "   Common Backdoor Location Scanner"
		echo "=========================================="
		echo "1. /tmp"
		echo "2. /var/tmp"
		echo "3. /dev/shm"
		echo "4. /home/*/.cache"
		echo "5. /usr/local/bin"
		echo "6. /opt"
		echo "7. Scan All Locations"
		echo "8. Back to Main Menu"
		echo ""
		
		read -rp "Select location to scan: " loc_choice
		
		case "$loc_choice" in
			1) scan_and_remove_location "/tmp" ;;
			2) scan_and_remove_location "/var/tmp" ;;
			3) scan_and_remove_location "/dev/shm" ;;
			4) scan_and_remove_location_wildcard "/home/*/.cache" ;;
			5) scan_and_remove_location "/usr/local/bin" ;;
			6) scan_and_remove_location "/opt" ;;
			7) scan_all_locations ;;
			8) break ;;
			*) echo "[!] Invalid option" ;;
		esac
	done
}

scan_and_remove_location() {
	local location="$1"
	echo ""
	echo "[+] Scanning: $location"
	echo "=========================================="
	
	if [ ! -d "$location" ]; then
		echo "[!] Directory $location does not exist"
		return
	fi
	
	# Find suspicious executables
	echo "[i] Suspicious files (modified in last 7 days):"
	local files
	files=$(find "$location" -type f -executable -mtime -7 2>/dev/null)
	
	if [ -z "$files" ]; then
		echo "    No suspicious files found"
		return
	fi
	
	echo "$files"
	echo ""
	
	# Check for listening processes from these files
	echo "[i] Checking for listening processes from this location..."
	local listening_pids=()
	
	while IFS= read -r line; do
		local pid=$(echo "$line" | awk '{print $6}' | grep -oE '[0-9]+' | head -1)
		local program=$(echo "$line" | awk '{print $7}')
		
		if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
			local exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")
			if [[ "$exe_path" == "$location"* ]]; then
				echo "    PID: $pid | Program: $program | Path: $exe_path"
				listening_pids+=("$pid|$program|$exe_path")
			fi
		fi
	done < <(ss -plnt 2>/dev/null | tail -n +2)
	
	if [ ${#listening_pids[@]} -eq 0 ]; then
		echo "    No listening processes found from this location"
	fi
	
	echo ""
	read -rp "Remove suspicious files from $location? (y/N): " remove_choice
	
	if [[ "$remove_choice" =~ ^[Yy]$ ]]; then
		# Kill listening processes first
		for entry in "${listening_pids[@]}"; do
			local pid=$(echo "$entry" | cut -d'|' -f1)
			local prog=$(echo "$entry" | cut -d'|' -f2)
			echo "[+] Killing process: PID $pid ($prog)"
			sudo kill -9 "$pid" 2>/dev/null || true
		done
		
		# Remove files
		echo "$files" | while IFS= read -r file; do
			if [ -f "$file" ]; then
				echo "[+] Removing: $file"
				sudo rm -f "$file"
			fi
		done
		
		echo "[+] Cleanup complete for $location"
	else
		echo "[i] No files removed"
	fi
}

scan_and_remove_location_wildcard() {
	local pattern="$1"
	echo ""
	echo "[+] Scanning: $pattern"
	echo "=========================================="
	
	# Expand /home/*/.cache to all user cache directories
	local cache_dirs
	cache_dirs=$(find /home -maxdepth 2 -type d -name ".cache" 2>/dev/null)
	
	if [ -z "$cache_dirs" ]; then
		echo "[!] No cache directories found"
		return
	fi
	
	local all_files=""
	while IFS= read -r cache_dir; do
		local files
		files=$(find "$cache_dir" -type f -executable -mtime -7 2>/dev/null)
		if [ -n "$files" ]; then
			echo "[i] Found in $cache_dir:"
			echo "$files"
			all_files+="$files"$'\n'
		fi
	done <<< "$cache_dirs"
	
	if [ -z "$all_files" ]; then
		echo "    No suspicious files found"
		return
	fi
	
	echo ""
	echo "[i] Checking for listening processes..."
	local listening_pids=()
	
	while IFS= read -r line; do
		local pid=$(echo "$line" | awk '{print $6}' | grep -oE '[0-9]+' | head -1)
		local program=$(echo "$line" | awk '{print $7}')
		
		if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
			local exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")
			if [[ "$exe_path" == *"/.cache/"* ]]; then
				echo "    PID: $pid | Program: $program | Path: $exe_path"
				listening_pids+=("$pid|$program|$exe_path")
			fi
		fi
	done < <(ss -plnt 2>/dev/null | tail -n +2)
	
	if [ ${#listening_pids[@]} -eq 0 ]; then
		echo "    No listening processes found from cache directories"
	fi
	
	echo ""
	read -rp "Remove suspicious files from cache directories? (y/N): " remove_choice
	
	if [[ "$remove_choice" =~ ^[Yy]$ ]]; then
		# Kill listening processes first
		for entry in "${listening_pids[@]}"; do
			local pid=$(echo "$entry" | cut -d'|' -f1)
			local prog=$(echo "$entry" | cut -d'|' -f2)
			echo "[+] Killing process: PID $pid ($prog)"
			sudo kill -9 "$pid" 2>/dev/null || true
		done
		
		# Remove files
		echo "$all_files" | while IFS= read -r file; do
			if [ -n "$file" ] && [ -f "$file" ]; then
				echo "[+] Removing: $file"
				sudo rm -f "$file"
			fi
		done
		
		echo "[+] Cleanup complete for cache directories"
	else
		echo "[i] No files removed"
	fi
}

scan_all_locations() {
	echo ""
	echo "[+] Scanning ALL common backdoor locations..."
	echo "=========================================="
	
	local all_listening=()
	
	# Get all listening processes
	echo "[i] Current listening processes:"
	ss -plnt 2>/dev/null || netstat -plnt 2>/dev/null
	echo ""
	
	# Check each location
	local locations=("/tmp" "/var/tmp" "/dev/shm" "/usr/local/bin" "/opt")
	
	for loc in "${locations[@]}"; do
		if [ -d "$loc" ]; then
			echo "[i] Scanning $loc..."
			local files
			files=$(find "$loc" -type f -executable -mtime -7 2>/dev/null)
			
			if [ -n "$files" ]; then
				echo "$files"
				
				# Check for listening processes
				while IFS= read -r line; do
					local pid=$(echo "$line" | awk '{print $6}' | grep -oE '[0-9]+' | head -1)
					local program=$(echo "$line" | awk '{print $7}')
					
					if [ -n "$pid" ] && [ -d "/proc/$pid" ]; then
						local exe_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "")
						if [[ "$exe_path" == "$loc"* ]]; then
							echo "    [LISTENING] PID: $pid | $program | $exe_path"
							all_listening+=("$pid|$program|$exe_path")
						fi
					fi
				done < <(ss -plnt 2>/dev/null | tail -n +2)
			fi
		fi
	done
	
	# Check cache directories
	echo "[i] Scanning /home/*/.cache..."
	local cache_dirs
	cache_dirs=$(find /home -maxdepth 2 -type d -name ".cache" 2>/dev/null)
	
	if [ -n "$cache_dirs" ]; then
		while IFS= read -r cache_dir; do
			local files
			files=$(find "$cache_dir" -type f -executable -mtime -7 2>/dev/null)
			if [ -n "$files" ]; then
				echo "$files"
			fi
		done <<< "$cache_dirs"
	fi
	
	echo ""
	echo "[+] Summary of listening processes from backdoor locations:"
	if [ ${#all_listening[@]} -eq 0 ]; then
		echo "    No listening processes found in common backdoor locations"
	else
		for entry in "${all_listening[@]}"; do
			echo "    $entry"
		done
		
		echo ""
		read -rp "Kill all listening processes from these locations? (y/N): " kill_choice
		
		if [[ "$kill_choice" =~ ^[Yy]$ ]]; then
			for entry in "${all_listening[@]}"; do
				local pid=$(echo "$entry" | cut -d'|' -f1)
				local prog=$(echo "$entry" | cut -d'|' -f2)
				echo "[+] Killing: PID $pid ($prog)"
				sudo kill -9 "$pid" 2>/dev/null || true
			done
			echo "[+] All processes terminated"
		fi
	fi
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

main_backdoor_menu() {
	while true; do
		echo ""
		echo "=========================================="
		echo "   Backdoor Detection & Removal Tool"
		echo "=========================================="
		echo "1. Full Automated Scan"
		echo "2. Common Backdoor Locations (submenu)"
		echo "3. Check Persistence Mechanisms"
		echo "4. Scan Network Ports Only"
		echo "5. Advanced Checks (SUID/Hidden Processes/Rootkits)"
		echo "6. SSH Backdoor Check"
		echo "7. Network Connection Analysis"
		echo "8. Generate Full Report"
		echo "9. Interactive Removal"
		echo "10. Exit"
		echo ""
		
		read -rp "Enter choice: " main_choice
		
		case "$main_choice" in
			1)
				scan_network_ports
				check_suspicious_locations
				check_persistence_systemd
				check_persistence_cron
				check_persistence_shell
				;;
			2) backdoor_location_submenu ;;
			3)
				check_persistence_systemd
				check_persistence_cron
				check_persistence_shell
				;;
			4) scan_network_ports ;;
			5)
				check_suid_sgid_binaries
				check_hidden_processes
				check_rootkit_indicators
				;;
			6) check_ssh_backdoors ;;
			7) check_suspicious_connections ;;
			8) generate_report ;;
			9) interactive_removal ;;
			10) break ;;
			*) echo "[!] Invalid option" ;;
		esac
	done
}

invoke_finding_backdoor() {
	echo "[+] Starting backdoor detection..."
	main_backdoor_menu
	echo "[+] Done."
}

# If executed directly, run the entrypoint. If sourced, do nothing.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	invoke_finding_backdoor "$@"
fi
