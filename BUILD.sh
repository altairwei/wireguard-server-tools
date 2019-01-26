command -v argbash >/dev/null 2>&1 || { echo >&2 "I require foo but it's not installed.  Aborting."; exit 1; }
mkdir -p "build"
argbash --strip user-content "wg-server-parsing.m4" -o "build/wg-server" \
    && argbash wg-server.sh >> "build/wg-server" \
    && echo "Wiregaurd-Server-Tools is generated in $(pwd)/build/wg-server"