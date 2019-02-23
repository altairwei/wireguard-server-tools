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

# Define colors
readonly COLOR_NC='\e[0m' # No Color
readonly COLOR_GREEN='\e[0;32m'
readonly COLOR_BOLD_GREEN='\e[1;32m'
readonly COLOR_YELLOW='\e[0;33m'
readonly COLOR_BOLD_YELLOW='\e[1;33m'

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
	echo "[x] Error: $msg" >&2
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
# Get value from given section and key
# Globals:
#   None
# Arguments:
#   config_file="$1" - file name
#	section="$2" - section name
# Returns:
#   stdout - value
#######################################
parse_config_file() {
	local config_file="$1" target_section="$2" target_key="$3"
	local inside_section=0 line key value stripped
	# check file
	[[ -e ${config_file} ]] || die "\`${config_file}' does not exist" 1
	[[ ${config_file} =~ (^|/)([a-zA-Z0-9_=+.-]{1,15})\.conf$ ]] || die "The config file must be a valid interface name, followed by .conf"
	config_file="$(readlink -f "${config_file}")"
	# parsing
	shopt -s nocasematch
	while read -r line || [[ -n ${line} ]]; do
		# remove comments
		stripped="${line%%\#*}"
		# extract key and remove witespcae
		key="${stripped%%=*}"; key="${key#"${key%%[![:space:]]*}"}"; key="${key%"${key##*[![:space:]]}"}"   
		# extract value and remove witespcae
		value="${stripped#*=}"; value="${value#"${value%%[![:space:]]*}"}";	value="${value%"${value##*[![:space:]]}"}"
		# check target section interval
		[[ $key == "["* ]] && inside_section=0
		[[ $key == "[${target_section}]" ]] && inside_section=1
		if [[ $inside_section -eq 1 ]]; then
			if [[ "${key}" = "${target_key}" ]]; then
				echo "${value}"
				return 0
			fi
		fi
	done < "${config_file}"
	shopt -u nocasematch
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
	echo "$(parse_config_file "${conf_file}" "Interface" "PrivateKey")"
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
		#results="${results:+"$(echo "${results}\n")"}${name}\t${pubkey}"
		results="$(printf '%s\n%s\t%s' "${results:-""}" "${name}" "${pubkey}"  )"
	done
	echo "${results}"
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

#######################################
# Create server config file with necessary information
# Globals:
#   None
# Arguments:
#   interface=$1 - interface name
#	eth=$2 - ethernet name
#	port=$3 - udp listen port
#	int_prikey=$4 - interface private key
#	int_addr=$5 - interface address
#	int_dns=$6 - interface DNS
#	int_mtu=$7 - interface MTU
# Returns:
#   None
#######################################
create_server_config_file() {
	local func_name=$0
	if [[ $# != 7 ]]; then
		die "${func_name}: args are not enough." 1
	fi

	local interface=$1 eth=$2 port=$3
	local int_prikey=$4 int_addr=$5 int_dns=$6 int_mtu=$7

	cat > /etc/wireguard/${interface}.conf <<-EOF
	[Interface]
	PrivateKey = ${int_prikey}
	Address = ${int_addr}
	PostUp   = iptables -A FORWARD -i ${interface} -j ACCEPT; iptables -A FORWARD -o ${interface} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${eth} -j MASQUERADE
	PostDown = iptables -D FORWARD -i ${interface} -j ACCEPT; iptables -D FORWARD -o ${interface} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${eth} -j MASQUERADE
	ListenPort = $port
	DNS = ${int_dns}
	MTU = ${int_mtu}
	EOF
}

#######################################
# Create client config file with necessary information
# Globals:
#   None
# Arguments:
#   conf_file=$1 - config file path
#	int_prikey=$2 - the private key of interface
#	int_addr=$3 - interface address
#	int_dns=$4 - interface DNS
#	int_mtu=$5 - interface MTU
#	peer_pubkey=$6 - server public key
#	peer_endpoint=$7 - server address on internet
#	peer_allowedips=$8 - server allowndIps
#	peer_alive=$9 - server PersistentKeepalive
# Returns:
#   None
#######################################
create_client_config_file() {
	local func_name=$0
	if [[ $# != 9 ]]; then
		die "${func_name}: no enough args." 1
	fi

	local conf_file=$1 int_prikey=$2 int_addr=$3 int_dns=$4 int_mtu=$5
	local peer_pubkey=$6 peer_endpoint=$7 peer_allowedips=$8 peer_alive=$9
	local int_pubkey="$(echo "${int_prikey}" | wg pubkey)"
	
	# write to file
	cat > "${conf_file}" <<-EOF
	[Interface]
	PrivateKey = ${int_prikey}
	Address = ${int_addr}
	DNS = ${int_dns}
	MTU = ${int_mtu}

	[Peer]
	PublicKey = ${peer_pubkey}
	Endpoint = ${peer_endpoint}
	AllowedIPs = ${peer_allowedips}
	PersistentKeepalive = ${peer_alive}
	EOF
}

#######################################
# Create client config file with templete
# Globals:
#   None
# Arguments:
#   conf_file=$1 - client config file base name
#	int_prikey=$2 - the private key of interface
#	int_addr=$3 - interface address
#	peer_pubkey=$4 - server public key
#	peer_endpoint=$5 - server address on internet
# Returns:
#   None
#######################################
create_default_client() {
	local conf_file=$1 int_prikey=$2 int_addr=$3
	local peer_pubkey=$4 peer_endpoint=$5

	create_client_config_file "${conf_file}" \
		"${int_prikey}" "${int_addr}" "8.8.8.8" "1420" \
		"${peer_pubkey}" "${peer_endpoint}" "0.0.0.0/0, ::0/0" "25"
}

#######################################
# Get a unused address from peers
# Globals:
#   None
# Arguments:
#   int_addr=$1 - interface address
#	peer_addr_list=$2 - a list of peers' address
# Returns:
#   stdout - unused ip address without CIDR
#######################################
get_unused_ip() {
	local int_addr=$1 peer_addr_list=$2
	local int_addr_part="$(echo ${int_addr} | cut -d "." -f "1 2 3")"
	for i in {2..254}; do 
		if [[ "${peer_addr_list}" == *"${int_addr_part}.$i"* ]]; then
			continue
		else
			echo "${int_addr_part}.$i"
			return 0
		fi
	done
	return 1
}