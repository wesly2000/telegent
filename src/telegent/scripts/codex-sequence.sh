#!/usr/bin/env bash

set -euo pipefail

scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$scripts_dir/_env.sh"
telegent_load_dotenv

usage() {
    echo "Usage: $0 [codex-binary] [profile]" >&2
    echo "The arguments may instead be set with TELEGENT_AGENT_BINARY and TELEGENT_MODEL_PROVIDER." >&2
}

if [[ $# -gt 2 ]]; then
    usage
    exit 2
fi

codex_binary=${1:-${TELEGENT_AGENT_BINARY:-}}
profile=${2:-${TELEGENT_MODEL_PROVIDER:-}}
if [[ -z $codex_binary || -z $profile ]]; then
    usage
    exit 2
fi
if [[ ! -x $codex_binary ]]; then
    echo "error: Codex binary is not executable: $codex_binary" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to read the Codex JSON event stream" >&2
    exit 1
fi

prompts_file=${TELEGENT_PROMPTS_FILE:-$scripts_dir/test-prompts.txt}
if [[ ! -f $prompts_file ]]; then
    echo "error: prompts file does not exist: $prompts_file" >&2
    exit 1
fi
mapfile -t prompts <"$prompts_file"
if (( ${#prompts[@]} == 0 )); then
    echo "error: prompts file is empty: $prompts_file" >&2
    exit 1
fi

request_interval=${TELEGENT_REQUEST_INTERVAL_SECONDS:-0}
if [[ ! $request_interval =~ ^[+]?([0-9]+([.][0-9]*)?|[.][0-9]+)([eE][+-]?[0-9]+)?$ ]]; then
    echo "error: TELEGENT_REQUEST_INTERVAL_SECONDS must be a nonnegative number" >&2
    exit 1
fi
printf -v request_interval_sleep '%.15f' "$request_interval"
while [[ $request_interval_sleep == *0 ]]; do
    request_interval_sleep=${request_interval_sleep%0}
done
request_interval_sleep=${request_interval_sleep%.}
request_interval_sleep=${request_interval_sleep:-0}

timestamp=$(date +%Y%m%d-%H%M%S)
binary_name=$(basename "$codex_binary")
run_label="$binary_name-$profile"
run_label=$(printf '%s' "$run_label" | tr -cs '[:alnum:]_.-' '_')
output_root=${TELEGENT_AGENT_OUTPUT_DIR:-capture/codex-sequences}
run_dir="$output_root/$timestamp-$run_label-$$"
mkdir -p "$run_dir"

catalog_args=()
if [[ -n ${TELEGENT_CODEX_MODEL_CATALOG:-} ]]; then
    catalog_args=(-c "model_catalog_json=\"$TELEGENT_CODEX_MODEL_CATALOG\"")
fi
start_args=(exec -p "$profile" "${catalog_args[@]}" --json -s read-only)
resume_args=(exec -p "$profile" "${catalog_args[@]}" -s read-only resume --json)

session_id=
answers_file="$run_dir/answers.txt"

for index in "${!prompts[@]}"; do
    turn_number=$((index + 1))
    prompt=${prompts[$index]}
    event_file=$(printf '%s/turn_%02d.jsonl' "$run_dir" "$turn_number")

    echo
    echo "Turn $turn_number: $prompt"

    if [[ $turn_number -eq 1 ]]; then
        "$codex_binary" "${start_args[@]}" "$prompt" | tee "$event_file"
        session_id=$(jq -r 'select(.type == "thread.started") | .thread_id' "$event_file" | head -n 1)
        if [[ -z $session_id || $session_id == null ]]; then
            echo "error: Codex did not emit a thread id" >&2
            exit 1
        fi
    else
        "$codex_binary" "${resume_args[@]}" "$session_id" "$prompt" | tee "$event_file"
    fi

    if jq -e 'select(.type == "item.completed" and .item.type == "error")' "$event_file" \
        >/dev/null
    then
        echo "error: Codex reported an error event in turn $turn_number" >&2
        exit 1
    fi
    if ! jq -e 'select(.type == "turn.completed")' "$event_file" >/dev/null; then
        echo "error: Codex did not complete turn $turn_number" >&2
        exit 1
    fi

    {
        printf 'Turn %d: %s\n' "$turn_number" "$prompt"
        jq -r 'select(.type == "item.completed" and .item.type == "agent_message") | .item.text' "$event_file"
        echo
    } >>"$answers_file"

    if (( index + 1 < ${#prompts[@]} )) && [[ $request_interval_sleep != 0 ]]; then
        echo "Waiting $request_interval_sleep seconds before the next turn..."
        sleep "$request_interval_sleep"
    fi
done

echo
echo "Completed session: $session_id"
echo "Results: $run_dir"
