#!/usr/bin/env bash

telegent_load_dotenv() {
    local env_file=${TELEGENT_ENV_FILE:-.env}
    local explicit_env_file=false
    if [[ -v TELEGENT_ENV_FILE ]]; then
        explicit_env_file=true
    fi
    if [[ ! -f $env_file ]]; then
        if [[ $explicit_env_file == true ]]; then
            echo "error: environment file does not exist: $env_file" >&2
            return 1
        fi
        return 0
    fi

    local python_binary=${TELEGENT_PYTHON_BINARY:-python3}
    if ! command -v "$python_binary" >/dev/null 2>&1; then
        echo "error: Python is required to load $env_file" >&2
        return 1
    fi
    if ! "$python_binary" -c 'from dotenv import dotenv_values' >/dev/null 2>&1; then
        echo "error: python-dotenv is required to load $env_file" >&2
        return 1
    fi

    local dotenv_output
    dotenv_output=$(mktemp "${TMPDIR:-/tmp}/telegent-dotenv.XXXXXX")
    if ! "$python_binary" - "$env_file" >"$dotenv_output" <<'PYTHON'
import re
import sys

from dotenv import dotenv_values

for key, value in dotenv_values(sys.argv[1]).items():
    if value is None:
        continue
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        print(f"error: invalid environment variable name: {key}", file=sys.stderr)
        raise SystemExit(1)
    sys.stdout.buffer.write(key.encode() + b"\0" + value.encode() + b"\0")
PYTHON
    then
        rm -f "$dotenv_output"
        return 1
    fi

    local -a dotenv_items=()
    mapfile -d '' -t dotenv_items <"$dotenv_output"
    rm -f "$dotenv_output"
    if (( ${#dotenv_items[@]} % 2 != 0 )); then
        echo "error: could not parse environment file: $env_file" >&2
        return 1
    fi

    local index key value
    for ((index = 0; index < ${#dotenv_items[@]}; index += 2)); do
        key=${dotenv_items[index]}
        value=${dotenv_items[index + 1]}
        if [[ ! -v $key ]]; then
            printf -v "$key" '%s' "$value"
            export "$key"
        fi
    done
}
