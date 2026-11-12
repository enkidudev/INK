# INK

**Keep what the terminal forgets.**

INK is a small, local-first credential and authentication-evidence notebook built for penetration testing engagements and training labs. It records what was discovered, where it came from, and whether access was actually validated.

The terminal is a poor place to remember every account, hash, host, reuse observation, and privilege boundary. INK keeps those details in separate, passphrase-encrypted notebooks. When the work is done, export a readable, offline HTML field report.

No cloud account, API server, background service, or telemetry.

## Features

- **Encrypted notebooks:** one SQLite database per assessment, encrypted record payloads, scrypt-derived keys, Fernet authentication and owner-only local permissions on POSIX systems.
- **Credential capture:** usernames, passwords, hashes, tokens, account types, domains, hosts, services, and sources. Secrets are entered through hidden prompts.
- **Bulk input:** positional username/secret pairing, CSV-style comma input, or one-per-line mode for secrets with commas and whitespace.
- **Evidence timeline:** append notes, provenance, and access observations with UTC timestamps. Track the observed result and privilege separately; INK never tests credentials automatically.
- **Search and corrections:** find entries by account, host, source or notes, edit fields, and preserve stable record IDs.
- **Import:** CSV input for existing records and optional JSON event histories, with validation before database changes.
- **Offline HTML reports:** self-contained search, filters, reveal/copy controls, CSV downloads, and printable layouts. A successful export clears just the selected notebook by default; `--keep` makes a non-destructive copy.

## Installation

On Parrot OS, Debian, or another Linux environment with Python 3.10+:

```bash
git clone https://github.com/enkidudev/INK.git
cd INK
chmod +x install.sh
./install.sh
ink --help
```

The installer sets up a dedicated Python virtual environment, installs the `cryptography` dependency, and links the `ink` command into `~/.local/bin`. It never deletes existing notebook data. The first installation requires a working Python package index connection.

If the executable is not found, add this to your shell configuration:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

To uninstall the command and package, run `./uninstall.sh`. Encrypted notebook databases remain on disk.

## Quick start

```bash
ink new assessment
ink add assessment
ink entries assessment
ink show assessment 1
ink append assessment 1
ink validate assessment 1
ink find assessment DC01
ink export assessment --output "$HOME/assessment.html" --keep
```

`new` prompts for a notebook passphrase. Every later action unlocks that notebook; there is no remote recovery service. Keep the passphrase safe.

A normal export creates a standalone HTML report and **clears the exported records only after the file is written and verified**:

```bash
ink export assessment --output "$HOME/assessment-final.html"
```

Use `--keep` for a report without clearing the database:

```bash
ink export assessment --output "$HOME/assessment-copy.html" --keep
```

Export files must use a new `.html` filename in an existing directory. INK will not overwrite existing exports. Record IDs are not reused after a clear.

## Common commands

| Command | Function |
| --- | --- |
| `ink list` | Show available notebooks |
| `ink new <name>` | Create an encrypted notebook |
| `ink add <name>` | Add a credential or hash with a hidden secret prompt |
| `ink add <name> --bulk` | Add multiple positional user/secret pairs |
| `ink entries <name>` | List metadata without printing secrets |
| `ink show <name> <id>` | Inspect an entry and its evidence history, masked by default |
| `ink show <name> <id> --reveal` | Explicitly display the stored secret |
| `ink append <name> <id>` | Append a note, source, or access event |
| `ink note <name> <id>` | Add a note interactively |
| `ink validate <name> <id>` | Record an observed authentication result |
| `ink edit <name> <id>` | Correct a field without retaining the old secret |
| `ink find <name> <query>` | Search non-secret metadata and events |
| `ink import <name> file.csv` | Review and import CSV rows transactionally |
| `ink export <name> --output report.html` | Export, then clear the selected notebook |
| `ink export <name> --output report.html --keep` | Export without clearing |
| `ink delete <name> <id>` | Delete an entry after confirmation |

Omitting an entry ID on commands such as `show`, `edit`, `append`, and `delete` opens an interactive picker.

### Bulk input

```bash
ink add assessment --bulk
```

Choose `comma` or `lines`. In comma mode, secrets are parsed with CSV-style quoting; commas can be quoted. In line mode, each secret is entered separately and significant whitespace is retained. If there is one password for several users, INK asks before reusing it. Count mismatches or cancelled operations do not save partial batches.

### CSV import

```bash
ink import assessment examples/import.csv
```

Required columns: `user,secret`. Optional: `type,domain,host,service,source,events`. The `events` column must be a JSON array of objects with `at` and `kind` properties.

The sample contains **fictional** accounts only. Do not commit real CSV imports, databases, reports, dumps, or credential lists to Git.

## Reports

The generated HTML is completely self-contained and opens without a server. It supports searching by account, host, source and timeline, type filtering, masked/revealed secrets, export to CSV, and print-to-PDF. See `examples/Revachol.html` for a fictional report.

**Security-critical behavior:** HTML exports and downloaded CSV files contain **plaintext secrets** even when the screen shows a mask. A copied secret goes to the system clipboard. Keep reports out of public repositories and shared folders. The command-line import accepts plaintext CSV only when the operator explicitly supplies a file.

CSV downloads protect against common spreadsheet formula injection by prefixing formula-like values. That prefix can affect spreadsheet interpretation of those individual cells.

## Storage and threat model

By default, notebook files are stored in `${XDG_DATA_HOME:-~/.local/share}/ink/`. Set `INK_HOME` to choose another directory. Records inside SQLite are individually encrypted with Fernet using a per-notebook random salt and a scrypt-derived key. The notebook name, record count, schema, and internal IDs are not encrypted.

- The app is offline, but it cannot protect secrets from a compromised host, malicious process, keylogger, unlocked session or clipboard monitor.
- Never put passwords or tokens into shell arguments. `ink add` intentionally does **not** accept `--secret`; use the hidden prompt. For sensitive notes, omit the positional text and use the interactive prompt.
- Exporting and clearing uses SQLite logical deletion. It does not guarantee secure erasure from SSDs, backups, snapshots, or filesystem history. A published report is plaintext.
- Export commits follow successful report publication; if a later database commit fails, the report may coexist with uncleared records. Check the file before repeating the export.
- Encrypted notebook data should be backed up independently before high-stakes operations. Test restores using a separate copy and a fictional notebook first.
- The encryption implementation is not independently audited. INK is a lightweight personal notebook, not a password manager or enterprise secrets vault.

## Development

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
```

All included tests use synthetic credentials. The project is self-contained apart from Python and the declared cryptography dependency.
