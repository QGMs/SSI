#!/usr/bin/env python3
"""Note app sem SQL injection nem command injection."""

import sqlite3
import string
from pathlib import Path

DB_FILE = Path(__file__).with_name("notes.db")
EXPORT_DIR = Path(__file__).with_name("exports")
ALLOWED_FILENAME_CHARS = set(string.ascii_letters + string.digits + "._-")


def open_db():
    """Abre a base de dados com rows nomeadas para simplificar a leitura."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Garante que a tabela existe e que as notas iniciais estao presentes."""
    with open_db() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS notes "
            "(id INTEGER PRIMARY KEY, title TEXT, body TEXT)"
        )
        conn.execute(
            "INSERT OR IGNORE INTO notes (id, title, body) VALUES "
            "(1, 'Welcome', 'This is your first note.'), "
            "(2, 'Reminder', 'Submit the SSI lab report on time.'), "
            "(3, 'Secret', 'The admin password is hunter2.')"
        )


def search_notes(query):
    """Pesquisa segura usando placeholders SQL."""
    statement = "SELECT id, title, body FROM notes WHERE title LIKE ? ORDER BY id"
    parameter = f"%{query}%"
    print(f"[DEBUG] Executing SQL: {statement} | params=({parameter!r},)")

    try:
        with open_db() as conn:
            rows = conn.execute(statement, (parameter,)).fetchall()
    except sqlite3.Error as exc:
        print(f"  SQL error: {exc}")
        return

    if not rows:
        print("  No notes found.")
        return

    for row in rows:
        print(f"  [{row['id']}] {row['title']}: {row['body']}")


def fetch_note(note_id):
    """Devolve uma nota pelo ID, ou None se nao existir."""
    with open_db() as conn:
        return conn.execute(
            "SELECT id, title, body FROM notes WHERE id = ?",
            (note_id,),
        ).fetchone()


def is_valid_export_name(filename):
    """Aceita apenas nomes simples, sem paths nem metacaracteres de shell."""
    if not filename or len(filename) > 64:
        return False
    if filename in {".", ".."}:
        return False
    if filename[0] not in string.ascii_letters + string.digits:
        return False
    if any(char not in ALLOWED_FILENAME_CHARS for char in filename):
        return False
    if "/" in filename or "\\" in filename:
        return False
    return True


def export_note(note_id):
    """Escreve a nota para um ficheiro sem invocar qualquer shell."""
    row = fetch_note(note_id)
    if row is None:
        print("  Note not found.")
        return

    filename = input("  Enter filename to export to: ").strip()
    if not is_valid_export_name(filename):
        print("  Invalid filename. Use a simple local filename with letters, digits, ., _ or -.")
        return

    EXPORT_DIR.mkdir(exist_ok=True)
    destination = EXPORT_DIR / filename
    content = f"Title: {row['title']}\nBody: {row['body']}\n"
    destination.write_text(content, encoding="utf-8")
    print(f"  Note exported to {destination}")


def main():
    init_db()
    while True:
        print("\n=== Note App ===")
        print("1. Search notes")
        print("2. Export note")
        print("3. Quit")
        choice = input("Choice: ").strip()

        if choice == "1":
            query = input("  Search query: ")
            search_notes(query)
        elif choice == "2":
            try:
                note_id = int(input("  Note ID: "))
            except ValueError:
                print("  Invalid ID.")
                continue
            export_note(note_id)
        elif choice == "3":
            break
        else:
            print("  Invalid choice.")


if __name__ == "__main__":
    main()
