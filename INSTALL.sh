#!/bin/bash

set -eu -o pipefail
shopt -s failglob
# check argbash existence
command -v argbash >/dev/null 2>&1 || \
	{ echo >&2 "$0 requires argbash but it's not installed. Please visit 
https://argbash.readthedocs.io/en/latest/install.html"; exit 1; }

DESTDIR=${1:-}
if [[ -z "${DESTDIR}" ]]; then
	mkdir -p "build"
	DESTDIR="$(pwd)/build"
fi

build_script() {
	local target_name=$1
	local target_script="$1.sh"
	local target_parsing="$1-parsing.m4"
	local excutable_name="$(basename -s ".sh" ${target_name})"
	local excutable_path="${DESTDIR}/${excutable_name}"
	# build mode
	if [[ -r "${target_parsing}" ]]; then
		argbash "${target_parsing}" -o "${excutable_path}"
		cat "${target_script}" >> "${excutable_path}"
	else
		argbash "${target_script}" -o "${excutable_path}" 
	fi
	 
	echo "${excutable_name} is generated as ${excutable_path}"
}

# target list
build_script "wgserver"
build_script "wgserver-install"
build_script "wgserver-set"
build_script "wgserver-show"

cp "wgserver-lib.sh" "${DESTDIR}/"

echo "Install Successfully."