#!/bin/bash

readonly E_NO_WIREGUARD=1
readonly E_NO_RUNNING_INT=2
readonly E_NO_CLIENT_DIR=3
readonly E_NO_VALID_CONF=4
readonly E_NO_INTERFACE=5
readonly E_NO_CLIENT_CONF=6
readonly E_NO_MATCH_INT=7
readonly E_NO_SUPPORT=8
readonly E_NO_PERMISSION=9

readonly BASE64_REG='(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'

#######################################
# Throw error messages without exiting
# Globals:
#   None
# Arguments:
#   msg=$@ - The message to throw
# Returns:
#   None
#######################################
err() {
	local msg=$@
	echo -e "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Error: $msg" >&2
}

#######################################
# Ask for sudo authority
# Globals:
#   BASH - has a default value "/bin/bash"
#   SELF - must be defined by SELF="$(readlink -f "${BASH_SOURCE[0]}")"
#   ARGS - must be defined by ARGS=( "$@" )
#   E_NO_PERMISSION
# Arguments:
#   None
# Returns:
#   E_NO_PERMISSION
#######################################
request_administrator_authority() {
	if [[ "$EUID" -ne 0 ]]; then
		if command -v sudo >/dev/null 2>&1 ; then
			exec sudo -p "[sudo] wg-server must be run as root: " -- "${BASH-"/bin/bash"}" -- "$SELF" "${ARGS[@]}"
		else
			die "Sorry, you need to run this script as root." "${E_NO_PERMISSION}"
		fi
		
	fi
}

#######################################
# Check if wireguard is installed
# Globals:
#   E_NO_WIREGUARD
# Arguments:
#   None
# Returns:
#   E_NO_WIREGUARD
#######################################
assert_wireguard_existence() {
	# assert wg command existence
	if ! command -v wg >/dev/null 2>&1 ; then
		die "Command 'wg' is not avaliable, please intall wireguard first." "${E_NO_WIREGUARD}"
	fi
}

#######################################
# Check if wireguard is running
# Globals:
#   E_NO_RUNNING_INT
# Arguments:
#   None
# Returns:
#   E_NO_RUNNING_INT
#######################################
assert_wireguard_running() {
	assert_wireguard_existence
	# assert whether any interfaces is running or not.
	if [[ -z "$(wg show interfaces)" ]]; then
		die "Cannot detect any running wireguard interfaces." "${E_NO_RUNNING_INT}"
	fi
}

#######################################
# Check if /etc/wireguard/client is exist
# Globals:
#   E_NO_CLIENT_DIR
# Arguments:
#   None
# Returns:
#   E_NO_CLIENT_DIR
#######################################
assert_client_config_dir() {
	assert_wireguard_existence
	# Enter client configuration files folder
	if ! [[ -d "/etc/wireguard/client" ]]; then
		die "Client folder does not exist at /etc/wireguard/client , please \
make sure wireguard server is installed by 'wg-server --install-wireguard' ." "${E_NO_CLIENT_DIR}"
	fi
}

#######################################
# Check if interface config file exist
# Globals:
#   E_NO_INTERFACE
# Arguments:
#   None
# Returns:
#   E_NO_INTERFACE
#######################################
assert_interface_valid() {
	if ! [[ -f "/etc/wireguard/$1.conf" ]]; then
		die "$1.conf does not exist at /etc/wireguard." "${E_NO_INTERFACE}"
	fi
}

assert_qrencode_existance() {
	if ! command -v qrencode >/dev/null 2>&1 ; then
		die "qrencode can not be found." 1
	fi
}

#######################################
# Get section contents of ini file
# Globals:
#   None
# Arguments:
#   inifile="$1" - file name
#	section="$2" - section name
# Returns:
#   stdout - section contents
#######################################
listIniSectionContents()
{
    local inifile="$1" section="$2"
	values=$(sed -n '/\['$section'\]/,/^$/p' $inifile | grep -Ev '\[|\]|^$')
	echo ${values}
}

#######################################
# Get interface private key
# Globals:
#   None
# Arguments:
#   conf_file=$1 - file name
# Returns:
#   stdout - base64 format private key
#######################################
get_int_pri_key() {
	# Get interface private key from config file.
	local conf_file=$1
	echo $(listIniSectionContents "${conf_file}" "Interface" \
			| grep -oP "PrivateKey\s*=\s*\K${BASE64_REG}" "${conf_file}")
}

#######################################
# Get interface name and public-key pair
# Globals:
#   None
# Arguments:
#   $@ - file name globs
# Returns:
#   stdout - tab-delimited pair on each row
#######################################
get_name_pubkey_pair() {
	local results
	for file in $@; do
		local name=$(basename -s ".conf" ${file}) pubkey=$(get_int_pri_key "${file}" | wg pubkey)
		results="${results:+"$(echo "${results}\n")"}${name}\t${pubkey}"
	done
	echo -e "${results}"
}

#######################################
# Convert unix timestamp to human readable
# Globals:
#   None
# Arguments:
#   unix_time=$1 - unix timestamp
#	unix_time=stdin - unix timestamp
# Returns:
#   stdout - human-readable date
#######################################
convert_unix_time_readable() {
	# How to set time zone: export TZ='Asia/Shanghai'
    local unix_time=${1:-"$(cat)"}
	date -d "@${unix_time}" +'%Y-%m-%d %H:%M:%S%z'
}

#######################################
# Convert bytes to human readable
# Globals:
#   None
# Arguments:
#   size=$1 - bytes
#	size=stdin - bytes
# Returns:
#   stdout - human-readable size
#######################################
convert_bytes_human_readable() {
	local size=${1:-"$(cat)"} factor="KMGTEPZY" scale="scale=2"
	if (( ${size} < 1024 )); then
		echo "${size} bytes"
		return 0
	else
		size=$(echo "${scale}; ${size}/1024" | bc)
	fi
	while (( $(echo "${size} >= 1024" | bc -l) && ${#factor} > 1 )); do
		size=$(echo "${scale}; ${size}/1024" | bc)
		factor=${factor:1}
	done
	echo "${size} ${factor:0:1}iB"
}
