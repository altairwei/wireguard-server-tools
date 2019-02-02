#!/bin/bash

# The following macros are defined by Argbash, see https://github.com/matejak/argbash

# ARG_POSITIONAL_SINGLE([interface], [Specify a wireguard interface.], ["wg0"])
# ARG_OPTIONAL_SINGLE([clients], [c], [Show clients' information.])
# ARG_OPTIONAL_SINGLE([qrencode], [q], [Show clients' information.])
# ARG_OPTIONAL_BOOLEAN([full-key], [k], [Whether show public/private keys with full length or not. Default behaviour just shows the first ten characters.])
# ARG_POSITIONAL_DOUBLEDASH()
# ARG_DEFAULTS_POS
# ARG_HELP([Set the interface, including client user management. -- Altair Wei])
# ARGBASH_GO

# [ <-- needed because of Argbash

set -e -o pipefail
shopt -s failglob
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )
SCRIPT_DIR="$(cd "$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")" && pwd)"

source "${SCRIPT_DIR}/wgserver-lib.sh" \
	|| { echo "Couldn't find 'wg-server-lib.sh' parsing library in the '$SCRIPT_DIR' directory"; exit 1; }

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
	peer_pubkey=$(echo -e "${peer_info}" | cut -f 1)
	peer_preshared_key=$(echo -e "${peer_info}" | cut -f 2)
	peer_endpoint=$(echo -e "${peer_info}" | cut -f 3)
	peer_allowed_ips=$(echo -e "${peer_info}" | cut -f 4)
	peer_latest_handshake=$(echo -e "${peer_info}" | cut -f 5 | convert_unix_time_readable)
	peer_transfer_received=$(echo -e "${peer_info}" | cut -f 6 | convert_bytes_human_readable)
	peer_transfer_sent=$(echo -e "${peer_info}" | cut -f 7 | convert_bytes_human_readable)
	peer_persistent_keepalive=$(echo -e "${peer_info}" | cut -f 8)
	# Add client peer name
	local name pubkey
	while read pair ; do
		name=$(echo -e "${pair}" | cut -f 1)
		pubkey=$(echo -e "${pair}" | cut -f 2)
		if [[ "${pubkey}" = "${peer_pubkey}" ]]; then
			peer_name="${name}"
		fi
	done <<< "$(echo -e "${client_name_pubkey_pair}")"
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
	)"
	echo "${peer_info}"
}

cmd_show_all() {
	local client_name_pubkey_pair=$(get_name_pubkey_pair "/etc/wireguard/client/*.conf")
	# print all interfaces' peers
	while read interface ; do
		local int_pubkey=$(wg show ${interface} public-key)
		# Header of interface table
		local interface_table=$(assemble_interface_info \
			"Interface" "Private Key" "Public Key" "Listen Port" "fwmark" )
		# Header of peers table
		local peers_table=$(assemble_peer_info \
			"Peer Name" "Public Key" "Preshared Key" "Endpoint" "Allowed Ips" \
			"Latest Handshake" "Transfer Receive" "Transfer Sent" "Persistent Keepalive")
		local peer_name peer_pubkey peer_preshared_key peer_endpoint peer_allowed_ips peer_latest_handshake peer_transfer_received peer_transfer_sent
		local peer_info
		while read peer_info ; do
			# Add interface name
			if [[ "${int_pubkey}" = "$(echo ${peer_info} | cut -d' ' -f 2)" ]]; then
				local int_name="${interface}"
				peer_info="$(printf '%s\t%s' "${int_name}" "${peer_info}")"
				# Print interface infromation
				printf '%s\n%s\n' "${interface_table}" "${peer_info}" | column -t -s $'\t'
				printf '\n'
				continue
			fi
			# Process peer information
			peer_info="$(process_peer_info "${peer_info}" "${client_name_pubkey_pair}")"
			peers_table="$(printf '%s\n%s' "${peers_table}" "${peer_info}")"
		done <<< "$(wg show ${interface} dump)"
		# Print peers information
		printf '%s\n' "${peers_table}" | column -t -s $'\t'
		printf '\n'
	done <<< "$(wg show interfaces)"
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

	if [[ -n "${_arg_clients}" ]]; then
		case "${_arg_clients}" in
			all) cmd_show_all ;;
			*) cmd_show_conf "${_arg_clients}";;
		esac
	fi

	if [[ -n "${_arg_qrencode}" ]]; then
		cmd_show_qrencode "${_arg_qrencode}"
	fi

	# default action
	cmd_show_all
}

main "$@"

# ] <-- needed because of Argbash