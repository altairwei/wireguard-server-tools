#!/bin/bash

set -eu -o pipefail
shopt -s inherit_errexit
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
	local script_name=$1
	local excutable_name="$(basename -s ".sh" ${script_name})"
	local excutable_path="${DESTDIR}/${excutable_name}"

	argbash "${script_name}" -o "${excutable_path}" \
		&& echo "${excutable_name} is generated as ${excutable_path}"
}

build_script "wgserver.sh"
build_script "wgserver-install.sh"
build_script "wgserver-set.sh"
build_script "wgserver-show.sh"

cp "wgserver-lib.sh" "${DESTDIR}/"

echo "Install Successfully."