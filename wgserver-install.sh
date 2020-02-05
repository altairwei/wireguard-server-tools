#!/bin/bash

# The following macros are defined by Argbash, see https://github.com/matejak/argbash

# ARG_POSITIONAL_SINGLE([interface], [Specify a wireguard interface.], ["wg0"])
# ARG_OPTIONAL_SINGLE([deploy], [D], [Deploy WireGuard server.])
# ARG_OPTIONAL_SINGLE([remove], [R], [Remove deployed WireGuard interface.])
# ARG_POSITIONAL_DOUBLEDASH()
# ARG_DEFAULTS_POS
# ARG_HELP([Install and Deploy wireguard.])
# DEFINE_SCRIPT_DIR([SCRIPT_DIR])
# ARGBASH_GO

# [ <-- needed because of Argbash

set -e -o pipefail
shopt -s failglob
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )

source "${SCRIPT_DIR}/wgserver-lib.sh" \
	|| { echo "Couldn't find 'wgserver-lib.sh' parsing library in the '$SCRIPT_DIR' directory"; exit 1; }

rand(){
	min=$1
	max=$(($2-$min+1))
	num=$(cat /dev/urandom | head -n 10 | cksum | awk -F ' ' '{print $1}')
	echo $(($num%$max+$min))  
}

get_free_udp_port()
{
    local port=$(shuf -i 2000-65000 -n 1)
    local port_list="$(ss -lau)"
    # check port existence
    if [[ "${port_list}" == *"${port}"* ]]; then
        get_free_udp_port
    else 
        echo "$port"
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
		Raspbian)
			apt-get update -y
			apt-get install -y raspberrypi-kernel-headers libelf-dev libmnl-dev build-essential git bc
			echo "deb http://deb.debian.org/debian/ unstable main" > /etc/apt/sources.list.d/unstable.list
			printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable
			apt update -y
			apt install dirmngr
			apt-key adv --keyserver   keyserver.ubuntu.com --recv-keys 7638D0442B90D010
			apt-key adv --keyserver   keyserver.ubuntu.com --recv-keys 04EE7237B7D453EC
			apt update -y
			apt install wireguard qrencode iptables-persistent -y
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
	local port=$(get_free_udp_port)
	#TODO: 改变网卡名获取方式，避免获取多个网卡，造成错误。判断是不是以太网。
	#TODO: 添加选项，让用户自己指定网卡名
	local eth=$(ls /sys/class/net | awk '/^e/{print$1}')

	# generate interface conf file
	create_server_config_file "${interface}" "${eth}" "${port}" \
		"${s1}" "10.0.0.1/24" "8.8.8.8" "1420"

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
	
	wg-quick up ${interface}

	# Generate client template.
	wg set "${interface}" peer "${c2}" allowed-ips "10.0.0.2/32"
	wg-quick save "${interface}"
    mkdir -p /etc/wireguard/client
	create_default_client "/etc/wireguard/client/client.conf" \
		"${c1}" "10.0.0.2/24" \
		"${s2}" "${serverip}:${port}"
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

cmd_remove_wireguard() {
	local interface="$1"
    wg-quick down "${interface}"
    rm -rf /etc/wireguard
    rm -f /etc/init.d/wgstart
	echo "${interface} has been removed, please reboot your server."
}

main() {
	request_administrator_authority

	if ! command -v wg >/dev/null 2>&1 ; then
		cmd_install_wireguard
	fi

	if [[ -n "${_arg_deploy}" ]]; then
        cmd_deploy_wireguard ${_arg_deploy}
	fi

	if [[ -n "${_arg_remove}" ]]; then
		cmd_remove_wireguard ${_arg_remove}
	fi
}

main "$@"

# ] <-- needed because of Argbash
