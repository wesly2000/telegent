#!/usr/bin/env bash

scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$scripts_dir/_env.sh"

telegent_launch_model() {
    if [[ $# -lt 1 ]]; then
        echo "error: a model name is required" >&2
        return 2
    fi
    local model=$1
    shift

    telegent_load_dotenv

    local working_directory=$PWD
    local config_root=${TELEGENT_CODEX_CONFIG_ROOT:-$working_directory/codex-third-party}
    local capture_root=${TELEGENT_CAPTURE_ROOT:-$working_directory/capture/chat}
    local codex_binary=${TELEGENT_CODEX_BINARY:-}
    if [[ -z $codex_binary ]]; then
        local local_codex=$working_directory/codex-rs/target/debug/codex
        if [[ -x $local_codex ]]; then
            codex_binary=$local_codex
        else
            codex_binary=$(command -v codex || true)
        fi
    fi

    local codex_home=$config_root/$model
    if [[ ! -f $codex_home/config.toml ]]; then
        echo "error: model configuration does not exist: $codex_home/config.toml" >&2
        return 1
    fi
    if [[ -z $codex_binary || ! -x $codex_binary ]]; then
        echo "error: Codex binary is not executable: ${codex_binary:-<not found>}" >&2
        return 1
    fi

    mkdir -p "$capture_root/$model"
    export CODEX_HOME
    CODEX_HOME=$(cd -- "$codex_home" && pwd -P)
    export SSLKEYLOGFILE
    SSLKEYLOGFILE=$(cd -- "$capture_root/$model" && pwd -P)/sslkeys.key
    exec "$codex_binary" "$@"
}
