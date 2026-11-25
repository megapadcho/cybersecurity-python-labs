"""Task 3: secure password hashing, CSV storage and JSON login logging."""

import csv
import hashlib
import hmac
import inspect
import json
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any

PERSONAL_SALT = "00008"
MIN_PASSWORD_LENGTH = 11
DATA_DIRECTORY = Path(__file__).resolve().parent / "data"
USERS_CSV = DATA_DIRECTORY / "users.csv"
LOG_JSON = DATA_DIRECTORY / "log.json"

users_to_register = (
    ("crypto.admin", "Cyber@Admin2026"),
    ("privacy.officer", "Privacy#Shield44"),
    ("network.analyst", "Network$Scan2026"),
    ("forensic.examiner", "Evidence&Trace99"),
    ("incident.responder", "Incident@Rapid2026"),
    ("security.architect", "Threat%Design2026"),
    ("cloud.auditor", "Cloud!Audit2026"),
    ("risk.manager", "Risk+Control2026"),
    ("malware.analyst", "Malware#Study2026"),
    ("student.account", "Student$Lab008"),
)

users_db: list[dict[str, str]] = []


class ValidationError(Exception):
    """Raised when an input value fails a domain validation rule."""


def generate_hash(password: str, salt: str = PERSONAL_SALT) -> str:
    """Generate a SHA-256 hex digest from password and salt."""
    if password is None or password == "" or salt is None or salt == "":
        raise ValueError("Password and salt must not be empty")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must contain at least {MIN_PASSWORD_LENGTH} characters"
        )

    # Compliance implementation; production systems should use Argon2id or bcrypt.
    digest_input = (password + salt).encode("utf-8")
    return hashlib.sha256(digest_input).hexdigest()


def create_user(username: str, password: str) -> tuple[str, str]:
    """Create one username and password-hash pair."""
    if username is None or username == "" or password is None or password == "":
        raise ValueError("Username and password must not be empty")
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list: tuple[tuple[str, str], ...]) -> list[tuple[str, str]]:
    """Validate users, generate hashes and save the CSV database."""
    created_users: list[tuple[str, str]] = []
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)

    for record in users_list:
        try:
            if not isinstance(record, tuple) or len(record) != 2:
                raise ValueError("Invalid user record")
            username, password = record
            created_users.append(create_user(username, password))
        except ValidationError as error:
            print(f"Registration skipped: {error}")
        except ValueError as error:
            print(f"Invalid registration record: {error}")

    try:
        with USERS_CSV.open("w", encoding="utf-8", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["username", "password_hash"])
            writer.writerows(created_users)
    except FileNotFoundError as error:
        print(f"CSV database directory not found: {error}")
    except PermissionError as error:
        print(f"Permission denied while writing CSV database: {error}")
    except OSError as error:
        print(f"Could not write CSV database: {error}")

    return created_users


def read_users_db() -> list[dict[str, str]]:
    """Read the username and hash database from CSV."""
    global users_db

    try:
        with USERS_CSV.open("r", encoding="utf-8", newline="") as csv_file:
            users_db = list(csv.DictReader(csv_file))
    except FileNotFoundError as error:
        print(f"CSV database not found: {error}")
        users_db = []
    except PermissionError as error:
        print(f"Permission denied while reading CSV database: {error}")
        users_db = []
    except OSError as error:
        print(f"Could not read CSV database: {error}")
        users_db = []

    return users_db


def display_users_db(database: list[dict[str, str]]) -> None:
    """Display a structured view of the CSV database."""
    print("CSV database:")
    print("-" * 82)
    print(f"{'Username':<24}{'Password hash (SHA-256)':<64}")
    print("-" * 82)
    for record in database:
        print(f"{record.get('username', ''):<24}{record.get('password_hash', ''):<64}")
    print("-" * 82)


def load_log_entries() -> list[dict[str, Any]]:
    """Load existing JSON events, resetting safely after corruption."""
    if not LOG_JSON.exists():
        return []

    try:
        with LOG_JSON.open("r", encoding="utf-8") as log_file:
            entries = json.load(log_file)
        if not isinstance(entries, list):
            print("Corrupted log format: JSON root is not a list.")
            return []
        return entries
    except json.JSONDecodeError as error:
        print(f"Corrupted JSON log; starting a new event list: {error}")
        return []
    except PermissionError as error:
        print(f"Permission denied while reading JSON log: {error}")
        return []
    except FileNotFoundError as error:
        print(f"JSON log not found; starting a new event list: {error}")
        return []
    except OSError as error:
        print(f"Could not read JSON log: {error}")
        return []


def append_log_entry(entry: dict[str, Any]) -> None:
    """Append a login event while preserving valid previous entries."""
    entries = load_log_entries()
    entries.append(entry)
    DATA_DIRECTORY.mkdir(parents=True, exist_ok=True)

    try:
        with LOG_JSON.open("w", encoding="utf-8") as log_file:
            json.dump(entries, log_file, ensure_ascii=False, indent=2)
    except PermissionError as error:
        print(f"Permission denied while writing JSON log: {error}")
    except FileNotFoundError as error:
        print(f"JSON log directory not found: {error}")
    except OSError as error:
        print(f"Could not write JSON log: {error}")


def sanitize_arguments(
    function: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> tuple[list[Any], dict[str, Any]]:
    """Replace password-like values before an event is logged."""
    signature = inspect.signature(function)
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    sensitive_names = {"password", "salt", "secret", "token"}

    positional_names = list(signature.parameters)
    safe_args: list[Any] = []
    for index, value in enumerate(args):
        name = positional_names[index] if index < len(positional_names) else ""
        safe_args.append("[REDACTED]" if name in sensitive_names else value)

    safe_kwargs = {
        name: "[REDACTED]" if name in sensitive_names else value
        for name, value in kwargs.items()
    }
    return safe_args, safe_kwargs


def log_event(function: Callable[..., Any]) -> Callable[..., Any]:
    """Log successful and unsuccessful login attempts."""

    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        username = kwargs.get(
            "username",
            args[0] if args else "",
        )
        safe_args, safe_kwargs = sanitize_arguments(function, args, kwargs)
        result = "failure"

        try:
            function_result = function(*args, **kwargs)
            if function_result:
                result = "success"
        except ValueError:
            append_log_entry(
                {
                    "event": "login",
                    "user": str(username),
                    "result": "failure",
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "args": safe_args,
                    "kwargs": safe_kwargs,
                }
            )
            raise

        append_log_entry(
            {
                "event": "login",
                "user": str(username),
                "result": result,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "args": safe_args,
                "kwargs": safe_kwargs,
            }
        )
        return function_result

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Authenticate a username and password against the CSV database."""
    if username is None or username == "" or password is None or password == "":
        raise ValueError("Username and password must not be empty")

    stored_hash: str | None = None
    for record in users_db:
        if record.get("username") == username:
            stored_hash = record.get("password_hash")
            break

    if stored_hash is None:
        return False

    try:
        supplied_hash = generate_hash(password, PERSONAL_SALT)
    except ValidationError:
        return False
    return hmac.compare_digest(supplied_hash, stored_hash)


def run() -> None:
    """Execute registration, database reading and authentication demonstrations."""
    print("Task 3 - Secure Hashing and Authentication")

    created_users = create_users(users_to_register)
    print(f"Registered users: {len(created_users)}")

    database = read_users_db()
    display_users_db(database)

    if database:
        first_username, first_password = users_to_register[0]
        print(
            f"Valid login ({first_username}): {login(first_username, first_password)}"
        )
        print(
            f"Invalid login ({first_username}): "
            f"{login(first_username, 'incorrectPassword')}"
        )
