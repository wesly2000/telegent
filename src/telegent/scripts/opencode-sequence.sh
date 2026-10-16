#!/usr/bin/env bash

set -euo pipefail

scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$scripts_dir/_env.sh"
telegent_load_dotenv

usage() {
    echo "Usage: $0 [opencode-binary] [provider/model] [working-directory]" >&2
    echo "The binary may instead be set with TELEGENT_AGENT_BINARY." >&2
}

if [[ $# -gt 3 ]]; then
    usage
    exit 2
fi

opencode_binary=${1:-${TELEGENT_AGENT_BINARY:-}}
configured_model=${2:-}
working_directory=${3:-$PWD}
if [[ -z $opencode_binary || -z $configured_model ]]; then
    usage
    exit 2
fi
if [[ ! -x $opencode_binary ]]; then
    echo "error: OpenCode binary is not executable: $opencode_binary" >&2
    exit 1
fi
if [[ ! -d $working_directory ]]; then
    echo "error: working directory does not exist: $working_directory" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required to read the OpenCode JSON event stream" >&2
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
binary_name=$(basename "$opencode_binary")
run_label="$binary_name-$configured_model"
run_label=$(printf '%s' "$run_label" | tr -cs '[:alnum:]_.-' '_')
output_root=${TELEGENT_AGENT_OUTPUT_DIR:-capture/opencode-sequences}
run_dir="$output_root/$timestamp-$run_label-$$"
mkdir -p "$run_dir"

session_id=
answers_file="$run_dir/answers.txt"

for index in "${!prompts[@]}"; do
    turn_number=$((index + 1))
    prompt=${prompts[$index]}
    event_file=$(printf '%s/turn_%02d.jsonl' "$run_dir" "$turn_number")
    command=(
        "$opencode_binary" run --pure --format json
        --model "$configured_model" --dir "$working_directory"
    )
    if [[ -n $session_id ]]; then
        command+=(--session "$session_id")
    fi

    echo
    echo "Turn $turn_number: $prompt"
    "${command[@]}" "$prompt" | tee "$event_file"

    if jq -s -e 'any(.[]; .type == "error")' "$event_file" >/dev/null; then
        echo "error: OpenCode reported an error event in turn $turn_number" >&2
        exit 1
    fi
    if [[ -z $session_id ]]; then
        session_id=$(jq -s -r 'map(select(.sessionID? != null))[0].sessionID // empty' "$event_file")
        if [[ -z $session_id || $session_id == null ]]; then
            echo "error: OpenCode did not emit a session ID" >&2
            exit 1
        fi
    fi
    if ! jq -s -e 'any(.[]; .type == "text" and .part.type == "text" and ((.part.text | type) == "string"))' \
        "$event_file" >/dev/null
    then
        echo "error: OpenCode did not emit text in turn $turn_number" >&2
        exit 1
    fi

    {
        printf 'Turn %d: %s\n' "$turn_number" "$prompt"
        jq -r 'select(.type == "text" and .part.type == "text") | .part.text' "$event_file"
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
