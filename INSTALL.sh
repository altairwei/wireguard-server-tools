# check argbash existence
command -v argbash >/dev/null 2>&1 || \
	{ echo >&2 "$0 requires argbash but it's not installed. Please visit 
https://argbash.readthedocs.io/en/latest/install.html"; exit 1; }

mkdir -p "build"
argbash wg-server.sh -o "build/wg-server" \
	&& echo "Wiregaurd-Server-Tools is generated as $(pwd)/build/wg-server"

if [ $? -eq 0 ] && [ -n "$1" ]; then
	echo "wg-server will be installed to $1"
	sudo cp "build/wg-server" $1 && echo "Install Successfully."
fi