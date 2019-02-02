#!/bin/bash
#
# Useful tools for WireGuard VPN server. Manage server or clients config files.

# The following macros are defined by Argbash, see https://github.com/matejak/argbash

# ARG_POSITIONAL_SINGLE([subcommand], [Call sub-command])
# ARG_LEFTOVERS([Arguments passed to sub-command.])
# ARG_DEFAULTS_POS
# ARG_HELP([Useful tools for WireGuard VPN server.])
# ARG_VERSION_AUTO([0.1.0])
# ARGBASH_GO

# [ <-- needed because of Argbash

set -e -o pipefail
shopt -s failglob
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )
SCRIPT_DIR="$(cd "$(dirname "$(readlink -e "${BASH_SOURCE[0]}")")" && pwd)"

source "${SCRIPT_DIR}/wgserver-lib.sh" \
	|| { echo "Couldn't find 'wg-server-lib.sh' parsing library in the '$SCRIPT_DIR' directory"; exit 1; }

main() {
	request_administrator_authority

	case $_arg_subcommand in
		install)
			${SCRIPT_DIR}/wgserver-install "${_arg_leftovers[@]}"
			;;
		show)
			${SCRIPT_DIR}/wgserver-show "${_arg_leftovers[@]}"
			;;
		set)
			${SCRIPT_DIR}/wgserver-set "${_arg_leftovers[@]}"
			;;
		*)
			die "Unknown sub-command." 127
			;;
	esac
}

main "$@"

# ] <-- needed because of Argbash