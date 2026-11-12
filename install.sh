#!/usr/bin/env bash
set -euo pipefail
INK_SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null || { echo 'Install Python 3.10+ first.' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
INK_VENV="${XDG_DATA_HOME:-$HOME/.local/share}/ink-app/venv"
INK_BIN="$HOME/.local/bin"
if [[ -e "$INK_BIN/ink" && ! -L "$INK_BIN/ink" ]]; then
  echo "$INK_BIN/ink already exists and is not an Ink symlink; refusing to replace it." >&2; exit 1
fi
if [[ -L "$INK_BIN/ink" && "$(readlink "$INK_BIN/ink")" != "$INK_VENV/bin/ink" ]]; then
  echo 'Another ink command is installed at this location; refusing to replace it.' >&2; exit 1
fi
mkdir -p "$INK_BIN"
python3 -m venv "$INK_VENV" || { echo 'Install python3-venv using your package manager, then retry.' >&2; exit 1; }
"$INK_VENV/bin/python" -m pip install "$INK_SOURCE"
ln -sfn "$INK_VENV/bin/ink" "$INK_BIN/ink"
echo 'Ink installed. Your notebooks are preserved during updates.'
case ":$PATH:" in
  *":$INK_BIN:"*) echo 'Run: ink --help' ;;
  *) echo 'Add this to your shell configuration, then open a new terminal:'; echo 'export PATH="$HOME/.local/bin:$PATH"' ;;
esac
