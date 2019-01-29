#!/bin/bash

set -e -o pipefail

# check argbash existence
command -v argbash >/dev/null 2>&1 || \
	{ echo >&2 "$0 requires argbash but it's not installed. Please visit 
https://argbash.readthedocs.io/en/latest/install.html"; exit 1; }

DESTDIR=$1
if [ -z "${DESTDIR}" ]; then
	mkdir -p "build"
	DESTDIR="$(pwd)/build"
fi

argbash wg-server.sh -o "${DESTDIR}/wg-server" \
	&& echo "Wiregaurd-Server-Tools is generated as ${DESTDIR}/wg-server"
echo "Install Successfully."