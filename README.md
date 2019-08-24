# WireGuard Server Tools

## Introduction

WireGuard Server Tools are useful tools for WireGuard VPN server.

## Installation

Go ahead to the release page and donwload the script to your server, then link the entry script `wgserver` to wherever you like.

```shell
wget https://github.com/altairwei/wireguard-server-tools/releases/download/v0.2/wgserver.tar.gz
mkdir wgserver-tools
tar -zxv -f wgserver.tar.gz -C ./wgserver-tools/
ln -s $(pwd)/wgserver-tools/wgserver /usr/bin/wgserver
```

Or, you can build the script by using [Argbash](https://github.com/matejak/argbash):

```shell
git clone https://github.com/altairwei/wireguard-server-tools.git
chmod +x ./INSTALL.sh
sudo ./INSTALL.sh /usr/bin/
```

## Features and Usage

You can pass `-h|--help` to any subcommands to get help messages.

```shell
wgserver -h
wgserver install -h
wgserver show -h
wgserver set -h
```

### Install and Deploy

You need to install necessary packages first, but `wgserver` only support auto-installation on Ubuntu, Debian and CentOS. Other distributions should refer to the official documentation of [WireGuard](https://www.wireguard.com/install/). To get complete functionality of `wgserver`, the package `qrencode` is highly recommended to install.

```shell
wgserver install

```

Then, deploy a tunnel interface:

```shell
wgserver install -D wg0
```

`wg0` is the default name of WireGuard server tunnel interface, and is also the default positional argment of `wgserver` subcommands.

### Add and Remove Clients

You can add servaral clients at a time.

```shell
wgserver set -q -a test1 -a test2 -a test3
```

or, remove some clients:

```shell
wgserver set -r test1 -r test2 -r test3
```

### Show Clients Informations

Show details of all clients:

```shell
wgserver show
# or
wgserver show -c all
```

Display the contents of specific client config file:

```shell
wgserver show -c test1
```

or, you can get qrencode from terminal by:

```shell
wgserver show -q test1
```

## Thanks

The tools are inspired by [l-n-s/wireguard-install](https://github.com/l-n-s/wireguard-install) and [atrandys/wireguard](https://github.com/atrandys/wireguard) .