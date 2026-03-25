CID=$(nitro-cli describe-enclaves | tr -d '\n' | sed -n 's/.*"EnclaveCID"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')
PORT=5005

CONFIG='{"api_key":"super-secret","mode":"prod"}'

echo $(cat build/.env) | socat - VSOCK-CONNECT:${CID}:${PORT}
