#!/usr/bin/env bash

set -euo pipefail
scripts_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
source "$scripts_dir/_launcher.sh"
telegent_launch_model deepseek "$@"
