#!/bin/bash
#
# Useful tools for WireGuard VPN server.

# [ <-- needed because of Argbash

readonly E_NO_WIREGUARD=1
readonly E_NO_RUNNING_INT=2
readonly E_NO_CLIENT_DIR=3
readonly E_NO_VALID_CONF=4
readonly E_NO_INTERFACE=5

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

randpwd(){
	mpasswd=$(cat /dev/urandom | head -1 | md5sum | head -c 4)
	echo ${mpasswd}  
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

wireguard_install(){
	# install all dependecies.
	version=$(cat /etc/os-release | awk -F '[".]' '$1=="VERSION="{print $2}')
	if [ $version == 18 ]
	then
		sudo apt-get update -y
		sudo apt-get install -y software-properties-common
		sudo apt-get install -y openresolv
	else
		sudo apt-get update -y
		sudo apt-get install -y software-properties-common
	fi
	sudo add-apt-repository -y ppa:wireguard/wireguard
	sudo apt-get update -y
	sudo apt-get install -y wireguard curl
	sudo apt-get install -y qrencode
	# set ipv4 forwarding
	sudo echo net.ipv4.ip_forward = 1 >> /etc/sysctl.conf
	sysctl -p
	echo "1"> /proc/sys/net/ipv4/ip_forward
	# generate configuration
	mkdir /etc/wireguard
	cd /etc/wireguard
	wg genkey | tee sprivatekey | wg pubkey > spublickey
	wg genkey | tee cprivatekey | wg pubkey > cpublickey
	s1=$(cat sprivatekey)
	s2=$(cat spublickey)
	c1=$(cat cprivatekey)
	c2=$(cat cpublickey)
	serverip=$(curl ipv4.icanhazip.com)
	port=$(rand 10000 60000)
	eth=$(ls /sys/class/net | awk '/^e/{print}')

	# generate interface conf file
	sudo cat > /etc/wireguard/wg0.conf <<- EOF
	[Interface]
	PrivateKey = $s1
	Address = 10.0.0.1/24 
	PostUp   = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $eth -j MASQUERADE
	PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $eth -j MASQUERADE
	ListenPort = $port
	DNS = 8.8.8.8
	MTU = 1420

	[Peer]
	PublicKey = $c2
	AllowedIPs = 10.0.0.2/32
	EOF

	# add server script
	sudo cat > /etc/init.d/wgstart <<-EOF
	#! /bin/bash
	### BEGIN INIT INFO
	# Provides:		wgstart
	# Required-Start:	$remote_fs $syslog
	# Required-Stop:    $remote_fs $syslog
	# Default-Start:	2 3 4 5
	# Default-Stop:		0 1 6
	# Short-Description:	wgstart
	### END INIT INFO

	sudo wg-quick up wg0
	EOF

	sudo chmod 755 /etc/init.d/wgstart
	cd /etc/init.d
	if [ $version == 14 ]
	then
		sudo update-rc.d wgstart defaults 90
	else
		sudo update-rc.d wgstart defaults
	fi
	
	sudo wg-quick up wg0
}

wireguard_remove(){
	sudo wg-quick down wg0
	sudo apt-get remove -y wireguard
	sudo rm -rf /etc/wireguard
	sudo rm -f /etc/init.d/wgstart
	sudo rm -f /etc/init.d/autoudp
	echo -e "Removing wireguard successfully, please reboot server."
}

add_normal_user(){
	local newname=$1
	check_client_config_dir
	cd /etc/wireguard/client
	
	# Check the name of new user.
	if [[ -z "${newname}" ]] || \
			![[ "${newname}" =~ ^[a-zA-Z0-9_=+.-]{1,15}$ ]]; then
		die "${newname} is not a valid config file name." "${E_NO_VALID_CONF}"
	fi
	if [[ -f "${newname}.conf" ]] ; then
		die "${newname}.conf already exists." "${E_NO_VALID_CONF}"
	fi

	# Generate client config file.
	# TODO: Check the interface name (should not set default to wg0)
	cp "client_noudp.conf" "${newname}.conf"
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
	echo "Add user successfully, config file is at： \
		/etc/wireguard/client/$newname.conf"
	
	if command -v qrencode >/dev/null 2>&1 ; then
		cat "${newname}.conf" | qrencode -o - -t UTF8
	fi
	rm -f temprikey tempubkey
}

cmd_install() {
	echo "Install wireguard on $1"
}

cmd_uninstall() {
	echo 0
}

cmd_show() {
	check_client_config_dir
	ls -l "/etc/wireguard/client"
	exit 0
}

cmd_add_client() {
	local client_names=($(echo $@))
	for name in ${client_names[@]}; do
		add_normal_user ${name}
	done
}

# ] <-- needed because of Argbash

# The following macros are defined by Argbash, see https://github.com/matejak/argbash

# ARG_POSITIONAL_SINGLE([interface], [Specify a wireguard interface.], ["wg0"])
# ARG_OPTIONAL_SINGLE([install-wireguard], [i], [Install wireGuard onto which Linux distribution.])
# ARG_OPTIONAL_ACTION([deploy-wireguard], [], [Deploy WireGuard server.], [cmd_show])
# ARG_OPTIONAL_ACTION([show-clients], [s], [Show clients' information.], [cmd_show])
# ARG_OPTIONAL_REPEATED([add-client], [a], [Add new client users. The argument can be repeated multiple times.])
# ARG_OPTIONAL_INCREMENTAL([add-random], [r], [Repeatly add new users with random names. Repeat times indicate the number of new users.])
# ARG_POSITIONAL_DOUBLEDASH()
# ARG_DEFAULTS_POS
# ARG_HELP([Useful tools for WireGuard VPN server. -- Altair Wei])
# ARG_VERSION([echo "wg-server: v0.1"])
# ARGBASH_GO

# [ <-- needed because of Argbash

main() {
	
	if [[ -n ${_arg_install_wireguard} ]]; then
		cmd_install ${_arg_install_wireguard}
		exit 0
	fi

	if [[ -n ${_arg_add_client} ]]; then
		# _arg_add_client is an array.
		cmd_add_client ${_arg_add_client[@]}
	fi

	check_wireguard_existence
	if sudo wg show ${_arg_interface}; then
		exit 0
	elif ! sudo cat "/etc/wireguard/${_arg_interface}.conf"; then
		die "Interface ${_arg_interface} do not exist." "${E_NO_INTERFACE}"
	fi
}

main "$@"

# ] <-- needed because of Argbash