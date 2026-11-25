"""Command-line entry point for Laboratory Work 1."""

import sys

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

from . import task1, task2, task3


def print_separator(title: str) -> None:
    """Print a clear section heading."""
    print("\n" + "=" * 74)
    print(title)
    print("=" * 74)


def main() -> None:
    """Run all Laboratory Work 1 tasks."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print("=" * 74)
    print("Лабораторна робота №1")
    print("Основи розробки на Python, Git та стандарти стилю коду")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група: {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")

    print_separator("TASK 1")
    try:
        task1.run()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Task 1 error: {error}")

    print_separator("TASK 2")
    try:
        task2.run()
    except (OSError, ValueError, RuntimeError) as error:
        print(f"Task 2 error: {error}")

    print_separator("TASK 3")
    try:
        task3.run()
    except (
        task3.ValidationError,
        ValueError,
        FileNotFoundError,
        PermissionError,
        OSError,
    ) as error:
        print(f"Task 3 error: {error}")


if __name__ == "__main__":
    main()
