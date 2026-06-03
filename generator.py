"""
Secure password and passphrase generation.
"""

import math
import secrets
import string
from dataclasses import dataclass


@dataclass(frozen=True)
class StrengthReport:
    length: int
    has_lowercase: bool
    has_uppercase: bool
    has_digits: bool
    has_symbols: bool
    score: int          # 0-100
    entropy_bits: float
    label: str          # "Weak" / "Fair" / "Strong" / "Very strong"


class PasswordGen:
    """Generate cryptographically secure passwords and passphrases."""

    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate(
        self,
        length: int = 16,
        use_lowercase: bool = True,
        use_uppercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
    ) -> str:
        """
        Generate a random password of *length* characters.

        At least one character from each enabled class is guaranteed.
        Raises ValueError if length < 8 or no character class is enabled.
        """
        if length < 8:
            raise ValueError("Password length must be at least 8 characters.")

        pool = ""
        mandatory: list[str] = []

        if use_lowercase:
            pool += string.ascii_lowercase
            mandatory.append(secrets.choice(string.ascii_lowercase))
        if use_uppercase:
            pool += string.ascii_uppercase
            mandatory.append(secrets.choice(string.ascii_uppercase))
        if use_digits:
            pool += string.digits
            mandatory.append(secrets.choice(string.digits))
        if use_symbols:
            pool += self.SYMBOLS
            mandatory.append(secrets.choice(self.SYMBOLS))

        if not pool:
            raise ValueError("At least one character class must be enabled.")

        filler = [secrets.choice(pool) for _ in range(length - len(mandatory))]
        combined = mandatory + filler
        secrets.SystemRandom().shuffle(combined)
        return "".join(combined)

    def generate_memorable(self, num_words: int = 4, separator: str = "-") -> str:
        """
        Generate a memorable passphrase from a built-in word list.

        Appends a two-digit number for extra entropy.
        """
        word_list = [
            "apple", "banana", "cherry", "dragon", "eagle", "forest",
            "garden", "harbor", "island", "jungle", "knight", "lemon",
            "mountain", "ninja", "orange", "pepper", "queen", "river",
            "silver", "tiger", "umbrella", "violet", "window", "yellow",
            "anchor", "blaze", "cobalt", "dagger", "ember", "falcon",
            "glacier", "hollow", "inferno", "jasper", "kelp", "lantern",
        ]
        words = [secrets.choice(word_list) for _ in range(num_words)]
        words.append(str(secrets.randbelow(90) + 10))   # always 2 digits
        return separator.join(words)

    def check_strength(self, password: str) -> StrengthReport:
        """Return a :class:`StrengthReport` for *password*."""
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_sym = any(c in self.SYMBOLS for c in password)

        # Pool size for entropy estimate
        pool_size = 0
        if has_lower:
            pool_size += 26
        if has_upper:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_sym:
            pool_size += len(self.SYMBOLS)

        entropy = math.log2(pool_size ** len(password)) if pool_size > 0 else 0.0

        # Score: length (40 pts) + diversity (60 pts)
        score = 0
        if len(password) >= 20:
            score += 40
        elif len(password) >= 16:
            score += 30
        elif len(password) >= 12:
            score += 20
        elif len(password) >= 8:
            score += 10

        for flag in (has_lower, has_upper, has_digit, has_sym):
            if flag:
                score += 15

        score = min(score, 100)

        if score >= 80:
            label = "Very strong"
        elif score >= 60:
            label = "Strong"
        elif score >= 40:
            label = "Fair"
        else:
            label = "Weak"

        return StrengthReport(
            length=len(password),
            has_lowercase=has_lower,
            has_uppercase=has_upper,
            has_digits=has_digit,
            has_symbols=has_sym,
            score=score,
            entropy_bits=round(entropy, 1),
            label=label,
        )
