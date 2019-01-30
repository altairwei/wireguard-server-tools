#!/bin/bash

set -e -o pipefail
shopt -s inherit_errexit
shopt -s failglob
export LC_ALL=C

# The following macros are defined by Argbash, see https://github.com/matejak/argbash

# ARG_POSITIONAL_SINGLE([interface], [Specify a wireguard interface.], ["wg0"])
# ARG_OPTIONAL_REPEATED([add-client], [a], [Add new client users. This argument can be repeated multiple times.])
# ARG_OPTIONAL_REPEATED([remove-client], [r], [Remvoe existing client users. This argument can be repeated multiple times.])
# ARG_OPTIONAL_INCREMENTAL([add-random], [R], [Repeatly add new users with random names. Repeat times indicate the number of new users.])
# ARG_POSITIONAL_DOUBLEDASH()
# ARG_DEFAULTS_POS
# ARG_HELP([Install adn Deploy wireguard.])
# ARGBASH_GO

# [ <-- needed because of Argbash

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )
SCRIPT_DIR="$(cd "$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")" && pwd)"

source "${SCRIPT_DIR}/wgserver-lib.sh" \
	|| { echo "Couldn't find 'wg-server-lib.sh' parsing library in the '$SCRIPT_DIR' directory"; exit 1; }

is_client_reside_interface() {
	local interface=$1 client_pubkey=$2 is_reside
	for cpubkey in $(wg show ${interface} peers); do
		if [[ "${client_pubkey}" = "${cpubkey}" ]]; then
			is_reside="yes"
		fi
	done
	if [[ "${is_reside}" = "yes" ]]; then
		return 0
	else
		return 1
	fi
}

add_normal_user(){
	local newname=$1
	assert_client_config_dir
	cd /etc/wireguard/client
	
	# Check the name of new user.
	if [[ -z "${newname}" ]] || \
			! [[ "${newname}" =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]]; then
		die "${newname} is not a valid config file name." "${E_NO_VALID_CONF}"
	fi
	if [[ -f "${newname}.conf" ]] ; then
		die "${newname}.conf already exists." "${E_NO_VALID_CONF}"
	fi

	# Generate client config file.
	# TODO: Check the interface name (should not set default to wg0)
	# TODO: Do not depend on template.
	cp "client.conf" "${newname}.conf"
	wg genkey | tee temprikey | wg pubkey > tempubkey
	ipnum=$(grep Allowed /etc/wireguard/wg0.conf | tail -1 | awk -F '[ ./]' '{print $6}')
	newnum=$((10#${ipnum}+1))
	sed -i 's%^PrivateKey.*$%'"PrivateKey = $(cat temprikey)"'%' $newname.conf
	sed -i 's%^Address.*$%'"Address = 10.0.0.$newnum\/24"'%' $newname.conf

	cat >> /etc/wireguard/wg0.conf <<-EOF

	[Peer]
	PublicKey = $(cat tempubkey)
	AllowedIPs = 10.0.0.$newnum/32
	EOF

	wg set wg0 peer $(cat tempubkey) allowed-ips 10.0.0.$newnum/32
	echo "Add user successfully, config file is atï¼š /etc/wireguard/client/$newname.conf"
	
	if command -v qrencode >/dev/null 2>&1 ; then
		cat "${newname}.conf" | qrencode -o - -t UTF8
	fi
	rm -f temprikey tempubkey
}

remove_normal_user() {
	local interface=$1 client_conf="/etc/wireguard/client/$2.conf" client_pubkey
	client_pubkey=$(get_int_pri_key "${client_conf}" | wg pubkey)
	# Remove client completely
	if is_client_reside_interface "${interface}" "${client_pubkey}" ; then
		wg set ${interface} peer ${client_pubkey} remove
	fi
	rm "${client_conf}"
}

cmd_add_client() {
	local client_names=($(echo "$@"))
	for name in ${client_names[@]}; do
		add_normal_user ${name}
	done
    exit 0
}

cmd_remove_client() {
	local client_names=($(echo $@)) interface="${_arg_interface}"
	for name in ${client_names[@]}; do
		remove_normal_user "${_arg_interface}" "${name}"
        echo "${name} is removed successfully."
	done
	wg-quick save ${interface}
    exit 0
}

main() {
	request_administrator_authority

	if [[ -n "${_arg_add_client}" ]]; then
        cmd_add_client ${_arg_add_client[@]}
	fi

	if [[ -n "${_arg_remove_client}" ]]; then
        cmd_remove_client ${_arg_remove_client[@]}
	fi

}

main "$@"

# ] <-- needed because of Argbash