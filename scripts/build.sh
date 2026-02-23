#!/usr/bin/env bash
set -euo pipefail

CMD_DIR=./cmd/attested
BIN_DIR=./bin
BIN_NAME=attested
HOST_BIN_DIR="/usr/local/bin"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "error: root privileges are required. run with sudo." >&2
    exit 1
  fi
}

build() {
    echo "+ BUILD"
    go generate ./internal/collector/ebpf
    go build -o "${BIN_DIR}/${BIN_NAME}" "${CMD_DIR}"
    echo "+ BUILD DONE."
}

install() {
    echo "+ INSTALL"
    sudo install -m 0755 "${BIN_DIR}/${BIN_NAME}" "${HOST_BIN_DIR}/${BIN_NAME}"
    echo "+ INSTALL DONE"
}

main() {
    local target="${1:-all}"

    case "${target}" in
        build)
            build
            ;;
        install)
            install
            ;;
        all)
            build
            install
            ;;
        *)
            echo "error: unknown target: ${target}" >&2
            exit 1
            ;;
    esac
}

main "$@"