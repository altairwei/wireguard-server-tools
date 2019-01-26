# m4_ignore(
echo "This is just a script template, not the script (yet) - please use build.py to generate the full script." >&2
exit 11  #)Created by argbash-init v2.7.1

err() {
  msg=$@
  echo -e "\n[$(date +'%Y-%m-%dT%H:%M:%S%z')] Error: $msg" >&2
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
sudo cat > /etc/wireguard/wg0.conf <<-EOF
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

cmd_install() {
    wireguard_install
}

cmd_uninstall() {

}

cmd_show() {
    printf "Value of '%s': %s\\n" 'subcommand' "$_arg_subcommand"
    exit 0
}

main() {
    case $_arg_subcommand in
        install)
            cmd_install
            ;;
        uninstall)
            cmd_uninstall
            ;;
        show) 
            cmd_show
            ;;
        *) 
            print_help
            err "Unknown subcommand!"
            exit 127
            ;;
    esac    
}

main "$@"