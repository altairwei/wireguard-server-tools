#!/bin/bash
#
# Useful tools for WireGuard VPN server. Manage server or clients config files.

# The following macros are defined by Argbash, see https://github.com/matejak/argbash

# ARG_POSITIONAL_SINGLE([subcommand], [Call sub-command, including <install | show | set> ])
# ARG_OPTIONAL_BOOLEAN([help], [h], [Print help])
# ARG_VERSION_AUTO([0.1.0])
# ARG_LEFTOVERS([Arguments passed to sub-command.])
# ARG_DEFAULTS_POS
# DEFINE_SCRIPT_DIR([SCRIPT_DIR])
# ARGBASH_PREPARE

# [ <-- needed because of Argbash

set -e -o pipefail
export LC_ALL=C

SELF="$(readlink -f "${BASH_SOURCE[0]}")"
ARGS=( "$@" )

source "${SCRIPT_DIR}/wgserver-lib.sh" \
	|| { echo "Couldn't find 'wgserver-lib.sh' parsing library in the '$SCRIPT_DIR' directory"; exit 1; }

print_help()
{
	printf '%s\n' "Useful tools for WireGuard VPN server."
	printf 'Usage: %s [-h|--help] [-v|--version] <subcommand> ... \n' "wgserver"
	printf '\t%s\n' "<subcommand>: Call sub-command, including <install | show | set> "
	printf '\t%s\n' "... : Arguments passed to sub-command."
	printf '\t%s\n' "-h, --help: Prints help. You can also pass '-h|--help' to sub-command to get help message."
	printf '\t%s\n' "-v, --version: Prints version"
}

main() {
	# Process options
	export _PRINT_HELP="yes"
	parse_commandline "$@"
	assign_positional_args 1 "${_positionals[@]}"
	local show_help
	if [[ ("${_arg_help}" = "on") && ( -z "${_arg_subcommand}") ]]; then
		# Show wgserver help
		print_help
		exit 0
	elif [[ ("${_arg_help}" = "on") && ( -n "${_arg_subcommand}") ]]; then
		# Show subcommand help
		show_help='-h'
	fi
	handle_passed_args_count
	# Process subcommand
	request_administrator_authority
	case $_arg_subcommand in
		install)
			${SCRIPT_DIR}/wgserver-install ${show_help} "${_arg_leftovers[@]}"
			;;
		show)
			${SCRIPT_DIR}/wgserver-show ${show_help} "${_arg_leftovers[@]}"
			;;
		set)
			${SCRIPT_DIR}/wgserver-set ${show_help} "${_arg_leftovers[@]}"
			;;
		*)
			print_help
			err "Unknown sub-command: ${_arg_subcommand}"
			exit 127
			;;
	esac
}

main "$@"

# ] <-- needed because of Argbash