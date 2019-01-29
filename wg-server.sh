#!/bin/bash
#
# Useful tools for WireGuard VPN server. Manage server or clients config files.

# [ <-- needed because of Argbash

set -eu -o pipefail
shopt -s inherit_errexit
shopt -s failglob
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )
SCRIPT_DIR="$(cd "$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")" && pwd)"

source "${SCRIPT_DIR}/wg-server-lib.sh" \
	|| { echo "Couldn't find 'wg-server-lib.sh' parsing library in the '$SCRIPT_DIR' directory"; exit 1; }


#######################################
# Ask for sudo authority
# Globals:
#   BASH
#   SELF
#   ARGS
#   E_NO_PERMISSION
# Arguments:
#   None
# Returns:
#   E_NO_PERMISSION
#######################################
check_administrator_authority() {
	if [[ "$EUID" -ne 0 ]]; then
		if command -v sudo >/dev/null 2>&1 ; then
			exec sudo -p "[sudo] wg-server must be run as root: " -- "${BASH-"/bin/bash"}" -- "$SELF" "${ARGS[@]}"
		else
			die "Sorry, you need to run this script as root." "${E_NO_PERMISSION}"
		fi
		
	fi
}

rand(){
	min=$1
	max=$(($2-$min+1))
	num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
	echo $(($num%$max+$min))  
}

function get_free_udp_port
{
	# Copyright (c) 2018 Viktor Villainov. Released under the MIT License. 
	# https://github.com/l-n-s/wireguard-install
    local port=$(shuf -i 2000-65000 -n 1)
    ss -lau | grep $port > /dev/null
    if [[ $? == 1 ]] ; then
        echo "$port"
    else
        get_free_udp_port
    fi
}

randpwd(){
	mpasswd=$(cat /dev/urandom | head -1 | md5sum | head -c 4)
	echo ${mpasswd}  
}

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

wireguard_install(){
	check_administrator_authority
	local linux_distro
	if [ -e /etc/centos-release ]; then
		linux_distro="CentOS"
	elif [ -e /etc/debian_version ]; then
		linux_distro=$( lsb_release -is )
	fi
	# Only support ubuntu >= 14.04
	case ${linux_distro} in
		Ubuntu)
			# install all dependecies.
			version=$(cat /etc/os-release | awk -F '[".]' '$1=="VERSION="{print $2}')
			apt-get update -y
			apt-get install -y software-properties-common
			if [ $version == 18 ]; then
				apt-get install -y openresolv
			fi
			add-apt-repository -y ppa:wireguard/wireguard
			apt-get update -y
			apt-get install -y wireguard curl
			apt-get install -y qrencode
			;;
		Debian)
			echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
			printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
			apt update
			apt install wireguard qrencode iptables-persistent -y
			;;
		CentOS)
			curl -Lo /etc/yum.repos.d/wireguard.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
			yum install epel-release -y
			yum install wireguard-dkms qrencode wireguard-tools firewalld -y
			;;
		*)
			die "Your distribution is not supported (yet), Please visit https://www.wireguard.com/install/" "${E_NO_SUPPORT}"
			;;
	esac
}

wireguard_deploy() {
	local interface=$1
	# set ipv4 forwarding
	echo net.ipv4.ip_forward = 1 >> /etc/sysctl.conf
	sysctl -p
	echo "1"> /proc/sys/net/ipv4/ip_forward
	# generate configuration
	mkdir -p /etc/wireguard
	cd /etc/wireguard
	wg genkey | tee sprivatekey | wg pubkey > spublickey
	wg genkey | tee cprivatekey | wg pubkey > cpublickey
	local s1=$(cat sprivatekey)
	local s2=$(cat spublickey)
	local c1=$(cat cprivatekey)
	local c2=$(cat cpublickey)
	# TODO: change the way of getting ip.
	local serverip=$(curl ipv4.icanhazip.com)
	# TODO: change the way of geting port
	local port=$(rand 10000 60000)
	local eth=$(ls /sys/class/net | awk '/^e/{print}')

	# generate interface conf file
	cat > /etc/wireguard/${interface}.conf <<-EOF
	[Interface]
	PrivateKey = $s1
	Address = 10.0.0.1/24 
	PostUp   = iptables -A FORWARD -i ${interface} -j ACCEPT; iptables -A FORWARD -o ${interface} -j ACCEPT; iptables -t nat -A POSTROUTING -o $eth -j MASQUERADE
	PostDown = iptables -D FORWARD -i ${interface} -j ACCEPT; iptables -D FORWARD -o ${interface} -j ACCEPT; iptables -t nat -D POSTROUTING -o $eth -j MASQUERADE
	ListenPort = $port
	DNS = 8.8.8.8
	MTU = 1420

	[Peer]
	PublicKey = $c2
	AllowedIPs = 10.0.0.2/32
	EOF

	# add server boot script
	cat > /etc/init.d/wgstart <<-EOF
	#! /bin/bash
	### BEGIN INIT INFO
	# Provides:		wgstart
	# Required-Start:	$remote_fs $syslog
	# Required-Stop:    $remote_fs $syslog
	# Default-Start:	2 3 4 5
	# Default-Stop:		0 1 6
	# Short-Description:	wgstart
	### END INIT INFO

	wg-quick up ${interface}
	EOF

	chmod 755 /etc/init.d/wgstart
	cd /etc/init.d
	if [ $version == 14 ]
	then
		update-rc.d wgstart defaults 90
	else
		update-rc.d wgstart defaults
	fi
	
	wg-quick up wg0

	# Generate client template.
    mkdir /etc/wireguard/client
	cat > /etc/wireguard/client/client.conf <<-EOF
	[Interface]
	PrivateKey = $c1
	Address = 10.0.0.2/24 
	DNS = 8.8.8.8
	MTU = 1420

	[Peer]
	PublicKey = $s2
	Endpoint = $serverip:$port
	AllowedIPs = 0.0.0.0/0, ::0/0
	PersistentKeepalive = 25
	EOF
}

wireguard_remove(){
	wg-quick down wg0
	apt-get remove -y wireguard
	rm -rf /etc/wireguard
	rm -f /etc/init.d/wgstart
	rm -f /etc/init.d/autoudp
	echo -e "Removing wireguard successfully, please reboot server."
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
	echo "Add user successfully, config file is at： /etc/wireguard/client/$newname.conf"
	
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

convert_unix_time_readable() {
	# How to set time zone: export TZ='Asia/Shanghai'
    local unix_time=${1:-"$(cat)"}
	date -d "@${unix_time}" +'%Y-%m-%d %H:%M:%S%z'
}

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

cmd_install_wireguard() {
	wireguard_install
}

cmd_uninstall() {
	echo 0
}

cmd_deploy_wireguard() {
	local interface=$1
	if ! [[ "${interface}" =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]]; then
		die "${interface} is not a valid config file name." "${E_NO_VALID_CONF}"
	fi	
	wireguard_deploy ${interface}
}

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

cmd_show() {
	local client_name_pubkey_pair=$(get_name_pubkey_pair "/etc/wireguard/client/*.conf")
	# print all interfaces' peers
	while read interface ; do
		local int_pubkey=$(wg show ${interface} public-key) peer_info
		local interface_table=$(echo -e "Interface\tPrivate Key\tPublic Key\tListen Port\tfwmark")
		local peers_table=$(echo -e "Peer Name\tPublic Key\tPreshared Key\tEndpoint\tAllowed Ips\tLatest Handshake\tTransfer Receive\tTransfer Sent\tPersistent Keepalive")
		local peer_name peer_pubkey peer_preshared_key peer_endpoint peer_allowed_ips peer_latest_handshake peer_transfer_received peer_transfer_sent
		while read peer_info ; do
			# Add interface name
			if [[ "${int_pubkey}" = "$(echo ${peer_info} | cut -d' ' -f 2)" ]]; then
				local int_name="${interface}"
				peer_info="${int_name}\t${peer_info}"
				# Print interface infromation
				interface_table="${interface_table}\n${peer_info}"
				echo -e "${interface_table}\n" | column -t -s $'\t'
				continue
			fi
			# Process peer information
			peer_pubkey=$(echo -e "${peer_info}" | cut -f 1)
			peer_preshared_key=$(echo -e "${peer_info}" | cut -f 2)
			peer_endpoint=$(echo -e "${peer_info}" | cut -f 3)
			peer_allowed_ips=$(echo -e "${peer_info}" | cut -f 4)
			peer_latest_handshake=$(echo -e "${peer_info}" | cut -f 5 | convert_unix_time_readable)
			peer_transfer_received=$(echo -e "${peer_info}" | cut -f 6 | convert_bytes_human_readable)
			peer_transfer_sent=$(echo -e "${peer_info}" | cut -f 7 | convert_bytes_human_readable)
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
			peers_table="${peers_table}\n${peer_name}\t${peer_pubkey}\t${peer_preshared_key}\t${peer_endpoint}\t${peer_allowed_ips}\t${peer_latest_handshake}\t${peer_transfer_received}\t${peer_transfer_sent}"
		done <<< "$(wg show ${interface} dump)"
		# Print peers information
		echo -e "${peers_table}\n" | column -t -s $'\t'
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
}

cmd_add_client() {
	local client_names=($(echo $@))
	for name in ${client_names[@]}; do
		add_normal_user ${name}
	done
}

cmd_remove_client() {
	local client_names=($(echo $@)) interface="${_arg_interface}"
	for name in ${client_names[@]}; do
		remove_normal_user "${_arg_interface}" "${name}"
	done
	wg-quick save ${interface}
}

# ] <-- needed because of Argbash

# The following macros are defined by Argbash, see https://github.com/matejak/argbash

# ARG_POSITIONAL_SINGLE([interface], [Specify a wireguard interface.], ["wg0"])
# ARG_OPTIONAL_ACTION([install-wireguard], [i], [Install wireGuard onto which Linux distribution.], [cmd_install_wireguard])
# ARG_OPTIONAL_SINGLE([deploy-wireguard], [D], [Deploy WireGuard server.])
# ARG_OPTIONAL_SINGLE([show-clients], [s], [Show clients' information.])
# ARG_OPTIONAL_REPEATED([add-client], [a], [Add new client users. This argument can be repeated multiple times.])
# ARG_OPTIONAL_REPEATED([remove-client], [r], [Remvoe existing client users. This argument can be repeated multiple times.])
# ARG_OPTIONAL_INCREMENTAL([add-random], [R], [Repeatly add new users with random names. Repeat times indicate the number of new users.])
# ARG_POSITIONAL_DOUBLEDASH()
# ARG_DEFAULTS_POS
# ARG_HELP([Useful tools for WireGuard VPN server. -- Altair Wei])
# ARG_VERSION([echo "wg-server: v0.1"])
# ARGBASH_GO

# [ <-- needed because of Argbash

main() {
	check_administrator_authority
	if [[ -n "${_arg_install_wireguard}" ]]; then
		cmd_install_wireguard ${_arg_install_wireguard}
		exit 0
	fi

	if [[ -n "${_arg_deploy_wireguard}" ]]; then
		cmd_deploy_wireguard ${_arg_deploy_wireguard}
		exit 0
	fi

	if [[ -n "${_arg_show_clients}" ]]; then
		case "${_arg_show_clients}" in
			all) cmd_show ;;
			*) cmd_show_conf "${_arg_show_clients}";;
		esac
	fi

	if [[ -n ${_arg_add_client} ]]; then
		# _arg_add_client is an array.
		cmd_add_client ${_arg_add_client[@]}
	fi

	if [[ -n ${_arg_remove_client} ]]; then
		# _arg_remove_client is an array.
		cmd_remove_client ${_arg_remove_client[@]}
	fi
}

main "$@"

# ] <-- needed because of Argbash