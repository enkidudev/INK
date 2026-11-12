"""INK: a local, encrypted credential notebook for assessment evidence."""

import argparse
import base64
import csv
import getpass
import hashlib
import html
import json
import os
import re
import shlex
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

FIELDS = ("user", "secret", "type", "domain", "host", "service", "source")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def root():
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    directory = Path(os.environ.get("INK_HOME") or str(Path(base) / "ink")).expanduser()
    if directory.is_symlink():
        raise ValueError("Notebook directory must not be a symbolic link.")
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not directory.is_dir():
        raise ValueError("Notebook storage is not a directory.")
    if os.name == "posix":
        directory.chmod(0o700)
    return directory


def path(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name):
        raise ValueError("Notebook name must be 1–64 letters, digits, dots, underscores or hyphens.")
    return root() / (name + ".db")


class Book:
    """One SQLite database per notebook; all record payloads are encrypted."""

    def __init__(self, name, create=False):
        self.name = name
        self.db = None
        notebook = path(name)
        created = False
        if notebook.is_symlink() or (not create and notebook.exists() and not notebook.is_file()):
            raise ValueError("Notebook path must be a regular file, not a symbolic link.")
        if create:
            descriptor = os.open(notebook, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            created = True
        elif not notebook.exists():
            raise ValueError("Notebook not found. Use ink new NAME.")
        if os.name == "posix":
            notebook.chmod(0o600)
        try:
            self.db = sqlite3.connect(notebook, timeout=30)
            self.db.execute("PRAGMA secure_delete=ON")
            self.db.execute("PRAGMA journal_mode=DELETE")
            if create:
                self.db.executescript(
                    "CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT);"
                    "CREATE TABLE entries(id INTEGER PRIMARY KEY AUTOINCREMENT, payload BLOB NOT NULL);"
                )
                salt = os.urandom(16)
                password = getpass.getpass("New notebook passphrase: ")
                if not password:
                    raise ValueError("Passphrase cannot be empty.")
                if password != getpass.getpass("Repeat passphrase: "):
                    raise ValueError("Passphrases differ.")
                self.cipher = self.key(password, salt)
                self.db.executemany(
                    "INSERT INTO meta VALUES(?, ?)",
                    [
                        ("salt", base64.b64encode(salt).decode()),
                        ("check", self.cipher.encrypt(b"ink").decode()),
                        ("volume", "1"),
                    ],
                )
                self.db.commit()
            else:
                meta = dict(self.db.execute("SELECT k,v FROM meta"))
                self.cipher = self.key(
                    getpass.getpass("Notebook passphrase: "),
                    base64.b64decode(meta["salt"], validate=True),
                )
                try:
                    self.cipher.decrypt(meta["check"].encode())
                except InvalidToken as exc:
                    raise ValueError("Incorrect passphrase or damaged notebook.") from exc
        except BaseException:
            if self.db is not None:
                self.db.close()
            if created:
                notebook.unlink(missing_ok=True)
            raise

    @staticmethod
    def key(password, salt):
        # Parameters are deliberately unchanged, preserving existing encrypted notebooks.
        derived = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
        return Fernet(base64.urlsafe_b64encode(derived))

    def records(self):
        return [
            dict(json.loads(self.cipher.decrypt(blob)), id=entry_id)
            for entry_id, blob in self.db.execute("SELECT id,payload FROM entries ORDER BY id")
        ]

    def save(self, record, commit=True):
        record = dict(record)
        entry_id = record.pop("id", None)
        blob = self.cipher.encrypt(json.dumps(record, ensure_ascii=False).encode("utf-8"))
        if entry_id is not None:
            cursor = self.db.execute("UPDATE entries SET payload=? WHERE id=?", (blob, entry_id))
            if cursor.rowcount != 1:
                raise ValueError("Entry not found; nothing updated.")
        else:
            self.db.execute("INSERT INTO entries(payload) VALUES(?)", (blob,))
        if commit:
            self.db.commit()

    def pick(self, entry_id=None):
        rows = self.records()
        if entry_id is None:
            query = input("Search account/host (Enter for all): ").lower()
            for record in rows:
                if query in searchable(record):
                    print(
                        f"{record['id']:>4}  {record['domain']}\\{record['user']}  "
                        f"{record['host']}  {record['type']}"
                    )
            try:
                entry_id = int(input("Entry ID: "))
            except ValueError as exc:
                raise ValueError("Entry ID must be a number.") from exc
        for record in rows:
            if record["id"] == entry_id:
                return record
        raise ValueError("Entry not found.")


def searchable(record):
    """Search account metadata and observations, not the secret itself."""
    return json.dumps(
        {key: value for key, value in record.items() if key != "secret"},
        ensure_ascii=False,
    ).lower()


def prompt(label, default=""):
    suffix = f" [{default}]" if default else ""
    return input(f"{label}{suffix}: ") or default


def _bulk_items(label, secret=False, mode="comma"):
    reader = getpass.getpass if secret else input
    if mode == "lines":
        print(f"{label}: one per line; an empty line finishes input.")
        values = []
        while True:
            value = reader("> ")
            if not value:
                return values
            values.append(value)
    value = reader(f"{label}: ")
    return [part.strip() for part in next(csv.reader([value], skipinitialspace=True))] if value else []


def add(book, args):
    shared = {key: getattr(args, key, None) for key in FIELDS}
    if args.bulk:
        mode = prompt("Input format: comma or lines", "comma").lower()
        if mode not in {"comma", "lines"}:
            raise ValueError("Choose comma or lines.")
        users = _bulk_items("Users", mode=mode)
        passwords = _bulk_items("Passwords", secret=True, mode=mode)
        if len(passwords) == 1 and len(users) > 1:
            if prompt("Apply this password to EVERY user? yes/no", "no").lower() != "yes":
                raise ValueError("Cancelled; no records saved.")
            passwords *= len(users)
        if not users or len(users) != len(passwords) or any(not user for user in users):
            raise ValueError("User/password counts must match; no records saved.")
        for index, user in enumerate(users, 1):
            print(f"{index}. {user} → secret {index} (masked)")
        if prompt("Save these pairs? yes/no", "no").lower() != "yes":
            return
        pairs = list(zip(users, passwords))
    else:
        user = shared["user"] or prompt("Account")
        if not user:
            raise ValueError("Account cannot be empty.")
        # Never accept a plaintext secret as a CLI flag: it would leak via process listings.
        pairs = [(user, getpass.getpass("Password/hash/token: "))]

    for key in FIELDS[2:]:
        if shared[key] is None:
            shared[key] = prompt(key.title(), "password" if key == "type" else "")

    # Gather all operations before committing, so cancelling mid-bulk does not save half.
    existing = book.records()
    operations = []
    for user, secret in pairs:
        record = {key: shared[key] or "" for key in FIELDS}
        record.update(user=user, secret=secret, created=now(), events=[])
        match = next(
            (old for old in existing if all(old[key] == record[key] for key in
                                           ("user", "secret", "domain", "host", "type"))),
            None,
        )
        if match is not None:
            print(f"Matching record #{match['id']} exists." if match.get("id") is not None else "Matching record in this batch exists.")
            if prompt("Append source to existing? yes/no", "yes").lower() == "yes":
                if record["source"]:
                    match["events"].append({"at": now(), "kind": "source", "text": record["source"]})
                    # A duplicate within this same batch is already queued as an insert.
                    if match.get("id") is not None and match not in operations:
                        operations.append(match)
                continue
        operations.append(record)
        existing.append(record)
    with book.db:
        for record in operations:
            book.save(record, commit=False)
    print(f"Saved {len(operations)} record update(s).")


def export(book, output, clear=True):
    """Write and verify a plaintext HTML archive before optionally clearing records."""
    destination = Path(output).expanduser().absolute()
    if destination.suffix.lower() != ".html":
        raise ValueError("Output must end in .html.")
    if destination.exists():
        raise ValueError("Output exists. Choose another filename.")
    if not destination.parent.is_dir():
        raise ValueError("Output directory does not exist.")
    book.db.execute("BEGIN IMMEDIATE")
    published = False
    try:
        rows = book.records()
        if not rows:
            raise ValueError("Notebook is empty.")
        volume = book.db.execute("SELECT v FROM meta WHERE k='volume'").fetchone()[0]
        # Keep script-breaking markup out of JSON placed in a <script> tag.
        data = (
            json.dumps(rows, ensure_ascii=True)
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        )
        report = (
            Path(__file__).with_name("report.html").read_text(encoding="utf-8")
            .replace("__TITLE__", html.escape(book.name))
            .replace("__VOLUME__", volume)
            .replace("__DATA__", data)
        )
        descriptor, temporary = tempfile.mkstemp(prefix=".ink-", dir=destination.parent)
        try:
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(report)
                stream.flush()
                os.fsync(stream.fileno())
            if Path(temporary).read_text(encoding="utf-8") != report:
                raise OSError("Export verification failed.")
            os.link(temporary, destination)  # Atomic no-clobber publication.
            published = True
            if os.name == "posix":
                parent_descriptor = os.open(destination.parent, os.O_RDONLY)
                try:
                    os.fsync(parent_descriptor)
                finally:
                    os.close(parent_descriptor)
        finally:
            Path(temporary).unlink(missing_ok=True)
        if clear:
            book.db.executemany("DELETE FROM entries WHERE id=?", [(r["id"],) for r in rows])
            book.db.execute("UPDATE meta SET v=? WHERE k='volume'", (str(int(volume) + 1),))
        book.db.commit()
        action = "Notebook cleared." if clear else "Notebook kept unchanged."
        print(f"Exported {len(rows)} entries → {destination}\n{action}")
    except BaseException:
        book.db.rollback()
        if published:
            print(
                "INK: HTML was published, but the notebook transaction failed. "
                "Records may remain; inspect the archive before exporting again.",
                file=sys.stderr,
            )
        raise


def parser():
    app = argparse.ArgumentParser(description="INK · Keep what the terminal forgets.")
    commands = app.add_subparsers(dest="cmd")
    commands.add_parser("list", help="List local notebooks")
    for command in (
        "new", "add", "entries", "show", "find", "append", "note", "validate",
        "edit", "delete", "export", "import",
    ):
        item = commands.add_parser(command)
        item.add_argument("notebook")
        if command in ("show", "append", "note", "validate", "edit", "delete"):
            item.add_argument("id", type=int, nargs="?")
        if command == "add":
            item.add_argument("--bulk", action="store_true")
            for key in FIELDS:
                if key != "secret":
                    item.add_argument("--" + key)
        if command in ("show", "entries", "find"):
            item.add_argument("--reveal", action="store_true")
        if command == "find":
            item.add_argument("query")
        if command == "note":
            item.add_argument("text", nargs="?")
        if command == "export":
            item.add_argument("--output", required=True)
            item.add_argument("--keep", action="store_true", help="Export without clearing the notebook")
        if command == "import":
            item.add_argument("file")
    return app


def run(args):
    if args.cmd == "list":
        for notebook in sorted(root().glob("*.db")):
            if notebook.is_file() and not notebook.is_symlink():
                print(notebook.stem)
        return
    if args.cmd == "new":
        book = Book(args.notebook, True)
        book.db.close()
        print(f"Notebook '{args.notebook}' created.")
        return
    book = Book(args.notebook)
    try:
        if args.cmd == "add":
            add(book, args)
        elif args.cmd in ("entries", "find", "show"):
            rows = [book.pick(args.id)] if args.cmd == "show" else book.records()
            for record in rows:
                if args.cmd == "find" and args.query.lower() not in searchable(record):
                    continue
                if not args.reveal:
                    record["secret"] = "••••••••"
                if args.cmd == "show":
                    print(f"\n✦ ENTRY #{record['id']} · {record['domain']}\\{record['user']}")
                    for key in FIELDS[1:]:
                        print(f"  {key.title():<9} {record[key]}")
                    for event in record["events"]:
                        details = event.get("text") or " / ".join(
                            str(event.get(key, "")) for key in
                            ("host", "service", "result", "privilege")
                        )
                        print(f"  {event['at']} · {event['kind']} · {details}")
                else:
                    print(
                        f"#{record['id']:<5} {record['user']:<24} "
                        f"{record['domain']:<20} {record['host']:<20} "
                        f"{record['type']:<12}"
                        + (f" {record['secret']}" if args.reveal else "")
                    )
        elif args.cmd in ("append", "note", "validate"):
            record = book.pick(args.id)
            kind = args.cmd
            if kind == "append":
                kind = prompt("Append: note / access / source", "note").lower()
            if kind not in ("note", "validate", "access", "source"):
                raise ValueError("Choose note, access or source.")
            event = {"at": now(), "kind": "access" if kind == "validate" else kind}
            if kind in ("access", "validate"):
                for key in ("host", "domain", "service", "result", "privilege"):
                    event[key] = prompt(key.title())
            else:
                event["text"] = getattr(args, "text", None) or prompt("Text")
            record["events"].append(event)
            book.save(record)
            print(f"Updated entry #{record['id']}.")
        elif args.cmd == "edit":
            record = book.pick(args.id)
            key = prompt("Field (" + ", ".join(FIELDS) + ")")
            if key not in FIELDS:
                raise ValueError("Unknown field.")
            record[key] = (
                getpass.getpass("New secret: ") if key == "secret"
                else input("New value (empty clears): ")
            )
            record["events"].append({"at": now(), "kind": "edit", "text": key + " corrected"})
            book.save(record)
            print(f"Updated entry #{record['id']}.")
        elif args.cmd == "delete":
            record = book.pick(args.id)
            if prompt(f"Delete #{record['id']}? Type DELETE") == "DELETE":
                book.db.execute("DELETE FROM entries WHERE id=?", (record["id"],))
                book.db.commit()
                print("Entry deleted.")
            else:
                print("Deletion cancelled.")
        elif args.cmd == "export":
            export(book, args.output, clear=not args.keep)
        elif args.cmd == "import":
            with open(args.file, newline="", encoding="utf-8-sig") as stream:
                reader = csv.DictReader(stream)
                if not {"user", "secret"}.issubset(reader.fieldnames or []):
                    raise ValueError("CSV requires user and secret columns.")
                rows = list(reader)
            if not rows:
                raise ValueError("CSV has no records.")
            prepared = []
            for item in rows:
                if None in item:
                    raise ValueError("CSV contains more columns than its header; nothing imported.")
                record = {key: item.get(key, "") or "" for key in FIELDS}
                record.update(created=now(), events=[])
                if not record["user"]:
                    raise ValueError("Every imported row requires a user; nothing imported.")
                if item.get("events"):
                    record["events"] = json.loads(item["events"])
                    if not isinstance(record["events"], list) or any(
                        not isinstance(event, dict) or not {"at", "kind"}.issubset(event)
                        for event in record["events"]
                    ):
                        raise ValueError("Events must be objects with at and kind; nothing imported.")
                prepared.append(record)
            if prompt(f"Import {len(prepared)} rows? yes/no", "no").lower() != "yes":
                return
            with book.db:
                for record in prepared:
                    book.save(record, commit=False)
            print(f"Imported {len(prepared)} entries.")
    finally:
        book.db.close()


def main():
    app = parser()
    args = app.parse_args()
    try:
        if not args.cmd:
            print("INK · Keep what the terminal forgets.")
            print("new · list · add · entries · show · append · edit · find · import · export")
            args = app.parse_args(shlex.split(input("Command (e.g. entries pale): ")))
            if not args.cmd:
                return
        run(args)
    except (ValueError, OSError, sqlite3.Error, InvalidToken, KeyError, json.JSONDecodeError) as exc:
        print("INK: " + str(exc), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nINK: cancelled.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
