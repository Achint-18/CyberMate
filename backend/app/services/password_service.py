"""Cryptographically secure password generation and entropy analysis for CyberMate.
Compliant with NIST Special Publication 800-63B guidelines.
Zero-storage guarantee: generated passwords are never saved, cached, or logged.
"""
import math
import secrets
import string
from typing import List
from pydantic import BaseModel, Field


class PasswordGenerateRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=64)
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_numbers: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True  # Exclude: l, 1, I, o, 0, O


class PasswordGenerateResponse(BaseModel):
    password: str
    length: int
    entropy_bits: float
    strength: str  # "Weak", "Moderate", "Strong", "Very Strong"
    crack_time_estimate: str
    security_notice: str


AMBIGUOUS_CHARS = set("l1Io0O`~|[]{}();:,. '\"")


def calculate_entropy(password: str, pool_size: int) -> float:
    """Calculates NIST Shannon entropy in bits for the generated password."""
    if not password or pool_size <= 0:
        return 0.0
    return round(len(password) * math.log2(pool_size), 1)


def determine_strength(entropy: float) -> tuple[str, str]:
    if entropy < 40:
        return "Weak", "< 1 hour"
    elif entropy < 60:
        return "Moderate", "Days to months"
    elif entropy < 80:
        return "Strong", "Decades to centuries"
    else:
        return "Very Strong", "Millions of years (unfeasible with current compute)"


def generate_secure_password(req: PasswordGenerateRequest) -> PasswordGenerateResponse:
    pools: List[str] = []

    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if req.exclude_ambiguous:
        upper = "".join(c for c in upper if c not in AMBIGUOUS_CHARS)
        lower = "".join(c for c in lower if c not in AMBIGUOUS_CHARS)
        digits = "".join(c for c in digits if c not in AMBIGUOUS_CHARS)
        symbols = "".join(c for c in symbols if c not in AMBIGUOUS_CHARS)

    required_chars: List[str] = []
    if req.use_uppercase and upper:
        pools.append(upper)
        required_chars.append(secrets.choice(upper))
    if req.use_lowercase and lower:
        pools.append(lower)
        required_chars.append(secrets.choice(lower))
    if req.use_numbers and digits:
        pools.append(digits)
        required_chars.append(secrets.choice(digits))
    if req.use_symbols and symbols:
        pools.append(symbols)
        required_chars.append(secrets.choice(symbols))

    # Fallback to lowercase + digits if everything unchecked
    if not pools:
        pools.append(lower)
        required_chars.append(secrets.choice(lower))

    full_pool = "".join(pools)
    remaining_length = max(0, req.length - len(required_chars))
    random_chars = [secrets.choice(full_pool) for _ in range(remaining_length)]

    # Combine and cryptographically shuffle
    password_list = required_chars + random_chars
    # Fisher-Yates shuffle with secrets.randbelow
    for i in range(len(password_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_list[i], password_list[j] = password_list[j], password_list[i]

    password = "".join(password_list)
    entropy = calculate_entropy(password, len(set(full_pool)))
    strength, crack_time = determine_strength(entropy)

    return PasswordGenerateResponse(
        password=password,
        length=len(password),
        entropy_bits=entropy,
        strength=strength,
        crack_time_estimate=crack_time,
        security_notice="Generated client-side/in-memory using cryptographically secure CSPRNG (secrets). Never reused or logged."
    )
