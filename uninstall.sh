#!/usr/bin/env bash
set -euo pipefail
INK_VENV="${XDG_DATA_HOME:-$HOME/.local/share}/ink-app/venv"
if [[ -L "$HOME/.local/bin/ink" && "$(readlink "$HOME/.local/bin/ink")" == "$INK_VENV/bin/ink" ]]; then
  rm -- "$HOME/.local/bin/ink"
fi
if [[ -x "$INK_VENV/bin/python" ]]; then
  "$INK_VENV/bin/python" -m pip uninstall -y enkidu-ink
fi
echo 'Ink removed. Notebook databases are preserved.'
