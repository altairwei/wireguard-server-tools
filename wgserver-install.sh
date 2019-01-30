#!/bin/bash

# The following macros are defined by Argbash, see https://github.com/matejak/argbash

# ARG_POSITIONAL_SINGLE([interface], [Specify a wireguard interface.], ["wg0"])
# ARG_OPTIONAL_SINGLE([deploy], [D], [Deploy WireGuard server.])
# ARG_POSITIONAL_DOUBLEDASH()
# ARG_DEFAULTS_POS
# ARG_HELP([Install adn Deploy wireguard.])
# ARGBASH_GO

# [ <-- needed because of Argbash

set -e -o pipefail
shopt -s inherit_errexit
shopt -s failglob
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )
SCRIPT_DIR="$(cd "$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")" && pwd)"

source "${SCRIPT_DIR}/wgserver-lib.sh" \
	|| { echo "Couldn't find 'wg-server-lib.sh' parsing library in the '$SCRIPT_DIR' directory"; exit 1; }

rand(){
	min=$1
	max=$(($2-$min+1))
	num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
	echo $(($num%$max+$min))  
}

get_free_udp_port()
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

wireguard_install(){
	request_administrator_authority
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

wireguard_remove(){
	wg-quick down wg0
	apt-get remove -y wireguard
	rm -rf /etc/wireguard
	rm -f /etc/init.d/wgstart
	rm -f /etc/init.d/autoudp
	echo -e "Removing wireguard successfully, please reboot server."
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

cmd_install_wireguard() {
	wireguard_install
}

cmd_deploy_wireguard() {
	local interface=$1
	if ! [[ "${interface}" =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]]; then
		die "${interface} is not a valid config file name." "${E_NO_VALID_CONF}"
	fi	
	wireguard_deploy ${interface}
}

main() {
	request_administrator_authority

	if ! command -v wg >/dev/null 2>&1 ; then
		cmd_install_wireguard
	fi

	if [[ -n "${_arg_deploy}" ]]; then
        cmd_deploy_wireguard ${_arg_deploy}
	fi
}

main "$@"

# ] <-- needed because of Argbash