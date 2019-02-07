#!/bin/bash

set -e -o pipefail
shopt -s failglob
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )

source "${SCRIPT_DIR}/wgserver-lib.sh" \
	|| { echo "Couldn't find 'wgserver-lib.sh' parsing library in the '$SCRIPT_DIR' directory"; exit 1; }

print_interface_info_rec() {
	local interface_info=$1
	# private-key, public-key, listen-port, fwmark.
	printf '%45s\t %45s\t %5i\t %4s\t \n' ${interface_info}
}

print_peer_info_rec() {
	local peer_info=$1
	# publica-key preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive.
	printf '%45s\t %10s\t %25s\t %25s\t %25s\t'
}

assemble_interface_info() {
	if (( $# != 5 )); then
		local func_name=$0
		die "${func_name}: args not enough." 1
	fi
	printf '%s\t%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4" "$5"
}

assemble_peer_info() {
	if (( $# != 9 )); then
		local func_name=$0
		die "${func_name}: args not enough." 1
	fi
	printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9"
}

process_peer_info() {
	local peer_info=$1 client_name_pubkey_pair=$2
	peer_pubkey=$(echo "${peer_info}" | cut -f 1)
	peer_preshared_key=$(echo "${peer_info}" | cut -f 2)
	peer_endpoint=$(echo "${peer_info}" | cut -f 3)
	peer_allowed_ips=$(echo "${peer_info}" | cut -f 4)
	peer_latest_handshake=$(echo "${peer_info}" | cut -f 5 | convert_unix_time_readable)
	peer_transfer_received=$(echo "${peer_info}" | cut -f 6 | convert_bytes_human_readable)
	peer_transfer_sent=$(echo "${peer_info}" | cut -f 7 | convert_bytes_human_readable)
	peer_persistent_keepalive=$(echo "${peer_info}" | cut -f 8)
	# Add client peer name
	local name pubkey
	while read name pubkey ; do
		if [[ "${pubkey}" = "${peer_pubkey}" ]]; then
			peer_name="$(printf "\e[0;33m${name}\e[0m")"
		fi
	done < <(echo "${client_name_pubkey_pair}")
	peer_name="${peer_name:-"(none)"}"
	# Assemble peer information
	if [[ "${_arg_full_key}" = "off" ]]; then
		peer_pubkey="${peer_pubkey:0:10}(...)"
		[[ "${peer_preshared_key}" = "(none)" ]] || peer_pubkey="${peer_preshared_key:0:10}(...)"
	fi
	peer_info="$(assemble_peer_info \
		"${peer_name}" "${peer_pubkey}" "${peer_preshared_key}" "${peer_endpoint}" \
		"${peer_allowed_ips}" "${peer_latest_handshake}" "${peer_transfer_received}" \
		"${peer_transfer_sent}" "${peer_persistent_keepalive}"
	)" || return 1
	echo "${peer_info}"
}

cmd_show_all() {
	local client_name_pubkey_pair="$(get_name_pubkey_pair "/etc/wireguard/client/*.conf")"
	# print all interfaces' peers
	while read interface ; do
		local int_pubkey=$(wg show ${interface} public-key)
		# Header of interface table
		local interface_table=$(assemble_interface_info \
			$'\e[1;32mInterface\e[0m' $'\e[1;32mPrivate Key\e[0m' $'\e[1;32mPublic Key\e[0m' $'\e[1;32mListen Port\e[0m' $'\e[1;32mfwmark\e[0m' )
		# Header of peers table
		local peers_table=$(assemble_peer_info \
			$'\e[1;33mPeer Name\e[0m' $'\e[1;33mPublic Key\e[0m' $'\e[1;33mPreshared Key\e[0m' $'\e[1;33mEndpoint\e[0m' $'\e[1;33mAllowed Ips\e[0m' \
			$'\e[1;33mLatest Handshake\e[0m' $'\e[1;33mTransfer Receive\e[0m' $'\e[1;33mTransfer Sent\e[0m' $'\e[1;33mPersistent Keepalive\e[0m')
		local peer_name peer_pubkey peer_preshared_key peer_endpoint peer_allowed_ips peer_latest_handshake peer_transfer_received peer_transfer_sent
		local peer_info
		while read peer_info ; do
			# Add interface name
			if [[ "${int_pubkey}" = "$(echo ${peer_info} | cut -d' ' -f 2)" ]]; then
				local int_name="${interface}"
				peer_info="$(printf '\e[0;32m%s\e[0m\t%s' "${int_name}" "${peer_info}")"
				# Print interface infromation
				printf '%s\n%s\n' "${interface_table}" "${peer_info}" | column -t -s $'\t'
				printf '\n'
				continue
			fi
			# Process peer information
			peer_info="$(process_peer_info "${peer_info}" "${client_name_pubkey_pair}")"
			peers_table="$(printf '%s\n%s' "${peers_table}" "${peer_info}")"
		done < <(wg show ${interface} dump)
		# Print peers information
		printf '%s\n' "${peers_table}" | column -t -s $'\t'
	done < <(wg show interfaces)
	# 
	exit 0
}

cmd_show_conf() {
	assert_client_config_dir
	local client_conf="/etc/wireguard/client/$1.conf"
	if [[ -r "${client_conf}" ]]; then
		cat "${client_conf}"
	else
		die "Client $1 does not exist, or can not be read." "${E_NO_CLIENT_CONF}"
	fi
	exit 0
}

cmd_show_qrencode() {
	assert_client_config_dir
	assert_qrencode_existance
	local client_conf="/etc/wireguard/client/$1.conf"
	if [[ -r "${client_conf}" ]]; then
		cat "${client_conf}" | qrencode -o - -t UTF8
	else
		die "Client $1 does not exist, or can not be read." "${E_NO_CLIENT_CONF}"
	fi
	exit 0
}

main() {
	request_administrator_authority

	if [[ -n "${_arg_client_conf}" ]]; then
		cmd_show_conf "${_arg_client_conf}"
	fi

	if [[ -n "${_arg_qrencode}" ]]; then
		cmd_show_qrencode "${_arg_qrencode}"
	fi

	# default action
	cmd_show_all
}

main "$@"