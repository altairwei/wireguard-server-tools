#!/bin/bash
#
# Useful tools for WireGuard VPN server. Manage server or clients config files.

# [ <-- needed because of Argbash

set -e -o pipefail

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )

readonly E_NO_WIREGUARD=1
readonly E_NO_RUNNING_INT=2
readonly E_NO_CLIENT_DIR=3
readonly E_NO_VALID_CONF=4
readonly E_NO_INTERFACE=5
readonly E_NO_CLIENT_CONF=6
readonly E_NO_MATCH_INT=7
readonly E_NO_SUPPORT=8
readonly E_NO_PERMISSION=9

readonly base64_reg='(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'

err() {
	msg=$@
	echo -e "[$(date +'%Y-%m-%dT%H:%M:%S%z')] Error: $msg" >&2
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

check_administrator_authority() {
	if [[ "$EUID" -ne 0 ]]; then
		if command -v sudo >/dev/null 2>&1 ; then
			exec sudo -p "wg-server must be run as root: " -- "${BASH-"/bin/bash"}" -- "$SELF" "${ARGS[@]}"
		else
			die "Sorry, you need to run this script as root." "${E_NO_PERMISSION}"
		fi
		
	fi
}

check_wireguard_existence() {
	# check wg command existence
	if ! command -v wg >/dev/null 2>&1 ; then
		die "Command 'wg' is not avaliable, please intall wireguard first." "${E_NO_WIREGUARD}"
	fi
}

check_wireguard_running() {
	check_wireguard_existence
	# check whether any interfaces is running or not.
	if [[ -z "$(wg show interfaces)" ]]; then
		die "Cannot detect any running wireguard interfaces." "${E_NO_RUNNING_INT}"
	fi
}

check_client_config_dir() {
	check_wireguard_existence
	# Enter client configuration files folder
	if ! [[ -d "/etc/wireguard/client" ]]; then
		die "Client folder does not exist at /etc/wireguard/client , please \
make sure wireguard server is installed by 'wg-server --install-wireguard' ." "${E_NO_CLIENT_DIR}"
	fi
}

check_interface_valid() {
	if ! [[ -f "/etc/wireguard/$1.conf" ]]; then
		die "$1.conf does not exist at /etc/wireguard." "${E_NO_INTERFACE}"
	fi
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

listIniSectionContents()
{
    local inifile="$1" section="$2"
	values=$(sed -n '/\['$section'\]/,/^$/p' $inifile | grep -Ev '\[|\]|^$')
	echo ${values}
}

get_int_pri_key() {
	# Get interface private key from config file.
	local conf_file=$1
	echo $(listIniSectionContents "${conf_file}" "Interface" \
			| grep -oP "PrivateKey\s*=\s*\K${base64_reg}" "${conf_file}")
}

get_name_pubkey_pair() {
	local results
	for file in "$@"; do
		local name=$(basename -s ".conf" ${file}) pubkey=$(get_int_pri_key "${file}" | wg pubkey)
		results="${results:+"${results}\n"}${name}\t${pubkey}"
	done
	echo -e "${results}"
}

wireguard_install(){
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
	mkdir /etc/wireguard
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
	check_client_config_dir
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

cmd_show() {
	local interfaces=($(wg show interfaces))
	# 首先查询所有interfaces
	for interface in ${interfaces[@]}; do
		local int_pubkey=$(wg show ${interface} public-key)
		wg show ${interface} dump > while read peer_info ; do
			local peer_name peer_pubkey=$(cat ${peer_info} | cut -f 1)
			# Add interface name
			if [[ "${int_pubkey}" = "$(cat ${peer_info} | cut -f 2)" ]]; then
				peer_name="${interface}"
				peer_info="${peer_name}\t${peer_info}"
				continue
			fi
			# Add client peer name
			get_name_pubkey_pair "/etc/wireguard/client/*.conf" > while read pair ; do
				local name=$(cat "${pair}" | cut -f 1)
				local pubkey=$(cat "${pair}" | cut -f 2)
				if [[ "${pubkey}" = "${peer_pubkey}" ]]; then
					peer_name="${name}"
				fi
			done
			peer_info="${peer_name:-"(none)"}\t${peer_info}"
		done
	done
	# 
	exit 0
}

cmd_show_conf() {
	check_client_config_dir
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