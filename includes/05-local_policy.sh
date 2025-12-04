#!/usr/bin/env bash
set -euo pipefail

# 05-local_policy.sh
# Writes a secure set of sysctls to /etc/sysctl.d/99-secure.conf and applies
# them when invoked via invoke_local_policy(). This will run on Linux Mint and
# Ubuntu (and Debian) by default and will not execute when sourced by the
# top-level orchestrator.

apply_sysctl() {
	local sudo_cmd=""
	if [ "${EUID:-$(id -u)}" -ne 0 ]; then
		if command -v sudo >/dev/null 2>&1; then
			sudo_cmd=sudo
		else
			echo "Error: root privileges required to apply sysctl settings." >&2
			return 1
		fi
	fi

	local -a settings=(
		# Network/IP hardening (recommended secure defaults)
		"net.ipv4.conf.all.accept_redirects=0"
		"net.ipv4.conf.all.accept_source_route=0"
		"net.ipv4.ip_forward=0"
		"net.ipv4.conf.all.log_martians=1"
		"net.ipv4.conf.all.proxy_arp=0"
		"net.ipv4.conf.all.rp_filter=1"
		"net.ipv4.conf.default.rp_filter=1"
		"net.ipv4.conf.all.send_redirects=0"
		"net.ipv4.conf.default.accept_redirects=0"
		"net.ipv4.conf.default.accept_source_route=0"
		"net.ipv4.conf.default.log_martians=1"
		"net.ipv4.icmp_echo_ignore_broadcasts=1"
		"net.ipv4.icmp_ignore_bogus_error_responses=1"
		"net.ipv4.tcp_syncookies=1"
		"net.ipv4.tcp_timestamps=0"
		"net.ipv4.tcp_max_syn_backlog=2048"

		# Filesystem limits / protections
		"fs.file-max=100000"
		"fs.protected_fifos=1"
		"fs.protected_hardlinks=1"
		"fs.protected_regular=1"
		"fs.protected_symlinks=1"
		"fs.suid_dumpable=0"

		# Kernel hardening
		"kernel.sysrq=0"
		"kernel.unprivileged_bpf_disabled=1"
		"kernel.panic_on_oops=0"
		"kernel.randomize_va_space=2"
		"kernel.core_uses_pid=1"
		"kernel.ctrl_alt_del=0"
		"kernel.dmesg_restrict=1"
		"kernel.kptr_restrict=2"
		"kernel.perf_event_paranoid=2"

		# VM tuning
		"vm.mmap_min_addr=65536"
		"vm.swappiness=10"
	)

	for setting in "${settings[@]}"; do
		${sudo_cmd:+$sudo_cmd }sysctl -w "$setting"
	done

	printf "%s\n" "${settings[@]}" | ${sudo_cmd:+$sudo_cmd }tee /etc/sysctl.d/99-secure.conf >/dev/null
	${sudo_cmd:+$sudo_cmd }sysctl --system
}

invoke_local_policy() {
	# Prefer ID from config.sh if set; otherwise parse /etc/os-release
	local this_id=""
	if [ -n "${ID:-}" ]; then
		this_id="${ID,,}"
	else
		if [ -r /etc/os-release ]; then
			this_id="$(awk -F= '/^ID=/{print tolower($2)}' /etc/os-release | tr -d '"')"
		fi
	fi

	case "${this_id}" in
		linuxmint|mint|*mint*|ubuntu|debian)
			: ;;
		*)
			echo "[i] Skipping local policy: not running on supported distro (detected: ${this_id:-unknown})."
			return 0
			;;
	esac

	echo "[+] Applying local security policy (Mint/Ubuntu/Debian)..."
	apply_sysctl
	echo "[+] Done."
}

# If executed directly, run the entrypoint. If sourced, do nothing; the
# top-level orchestrator (`harden.sh`) will call invoke_local_policy when the
# user picks the menu item.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	invoke_local_policy "$@"
fi

