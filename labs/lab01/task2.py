"""Task 2: multilevel access control system."""

USERS = {
    "crypto_specialist": {
        "role": "cryptographer",
        "clearance": 4,
        "department": "Cryptography",
        "active": True,
    },
    "privacy_officer": {
        "role": "privacy_analyst",
        "clearance": 3,
        "department": "Privacy",
        "active": True,
    },
    "data_scientist": {
        "role": "data_analyst",
        "clearance": 2,
        "department": "Analytics",
        "active": True,
    },
    "field_engineer": {
        "role": "field_support",
        "clearance": 2,
        "department": "Field Ops",
        "active": True,
    },
    "test_account": {
        "role": "testing",
        "clearance": 1,
        "department": "QA",
        "active": False,
    },
}

RESOURCES = [
    ("encryption_keys", 4),
    ("privacy_policies", 3),
    ("anonymized_data", 2),
    ("field_reports", 2),
    ("crypto_algorithms", 4),
    ("consent_forms", 1),
    ("data_classification", 3),
    ("key_management", 4),
    ("statistical_models", 2),
    ("public_datasets", 1),
]

SECURITY_LEVELS = (
    "Unclassified",
    "For Official Use",
    "Confidential",
    "Secret",
)

BLOCKED_USERS = {
    "test_account",
    "gdpr_violation",
    "data_breach_user",
}


def security_level_name(level: int) -> str:
    """Convert a numeric resource level to its textual name."""
    if 1 <= level <= len(SECURITY_LEVELS):
        return SECURITY_LEVELS[level - 1]
    return f"Unknown ({level})"


def check_access(
    username: str,
    resource_name: str,
    resource_level: int,
) -> tuple[bool, str]:
    """Apply the access-control decision order."""
    if username not in USERS:
        return False, "User not found"

    if username in BLOCKED_USERS:
        return False, "User is blocked"

    user = USERS[username]
    if not user["active"]:
        return False, "Account inactive"

    if user["clearance"] >= resource_level:
        return True, ""

    return False, "Insufficient clearance"


def display_resources() -> None:
    """Print all resources with textual security levels."""
    print("Resources:")
    print("-" * 62)
    print(f"{'Resource':<24}{'Level':<8}{'Security name':<28}")
    print("-" * 62)
    for resource_name, level in RESOURCES:
        print(f"{resource_name:<24}{level:<8}{security_level_name(level):<28}")
    print("-" * 62)


def run() -> int:
    """Execute all 50 user-resource access checks."""
    print("Task 2 - Multilevel Access Control")
    display_resources()

    check_count = 0
    print("Access checks:")
    for username in USERS:
        for resource_name, resource_level in RESOURCES:
            allowed, explanation = check_access(
                username,
                resource_name,
                resource_level,
            )
            result = "ALLOW" if allowed else "DENY"
            suffix = f" ({explanation})" if explanation else ""
            print(f"user={username} resource={resource_name} -> {result}{suffix}")
            check_count += 1

    print(f"Total access checks: {check_count}")
    return check_count
