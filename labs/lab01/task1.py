import random
import string
from collections import Counter
from collections.abc import Iterable

from shared.student import STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "ThreatH@nt3r",
    "weak123",
    "P3n3trat10n@Test",
    "visitor",
    "Cyber@Defense2023",
    "normal",
    "Incident@R3sp0nse",
    "standard",
    "Risk@Analys1s",
    "typical",
]

CRITERIA = {
    "min_length": 10,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "weak123",
    "visitor",
    "normal",
    "standard",
    "typical",
    "admin",
}


def generate_test_passwords() -> list[str]:
    """Copy passwords and append exactly three random duplicates."""
    result = PASSWORDS.copy()
    duplicate_indices = random.sample(range(len(PASSWORDS)), 3)
    result.extend(PASSWORDS[index] for index in duplicate_indices)
    return result


def analyze_password(
    password: str,
    password_counts: Counter[str],
) -> str:
    """Classify one password using the required priority order."""
    minimum_length = CRITERIA["min_length"]

    if password in FORBIDDEN_PASSWORDS or len(password) < minimum_length:
        return "FORBIDDEN"

    has_digits = any(character.isdigit() for character in password)
    has_upper = any(character.isupper() for character in password)
    has_special = any(character in string.punctuation for character in password)
    matched_criteria = sum((has_digits, has_upper, has_special))

    if matched_criteria == 3:
        if len(password) >= minimum_length + 4:
            if password_counts[password] == 1:
                return "VERY STRONG"
        return "STRONG"

    if matched_criteria > 0:
        return "MEDIUM"

    return "WEAK"


def display_password_results(passwords: Iterable[str]) -> None:
    """Display password classifications in a readable table."""
    password_list = list(passwords)
    counts = Counter(password_list)

    print("Task 1 - Password Security Analyzer")
    print(f"Student: {STUDENT_NAME} | Variant: {VARIANT_NUMBER}")
    print("-" * 74)
    print(f"{'#':<4}{'Password':<28}{'Length':<8}{'Classification':<20}")
    print("-" * 74)
    for index, password in enumerate(password_list, start=1):
        classification = analyze_password(password, counts)
        print(f"{index:<4}{password:<28}{len(password):<8}{classification:<20}")
    print("-" * 74)


def run() -> list[str]:
    """Execute Task 1 and return the modified password list."""
    passwords = generate_test_passwords()
    print(f"Original passwords: {len(PASSWORDS)}")
    print(f"Random duplicates appended: {len(passwords) - len(PASSWORDS)}")
    display_password_results(passwords)
    return passwords
