def validate_password_strength(candidate: str) -> bool:
    return len(candidate) >= 12 and any(ch.isdigit() for ch in candidate)
