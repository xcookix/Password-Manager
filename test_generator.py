"""Tests for core/generator.py"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.generator import PasswordGen


@pytest.fixture
def gen():
    return PasswordGen()


def test_length_respected(gen):
    for n in (8, 12, 16, 24, 32):
        assert len(gen.generate(length=n)) == n


def test_minimum_length_enforced(gen):
    with pytest.raises(ValueError):
        gen.generate(length=7)


def test_no_charset_raises(gen):
    with pytest.raises(ValueError):
        gen.generate(
            use_lowercase=False, use_uppercase=False,
            use_digits=False, use_symbols=False,
        )


def test_guaranteed_classes(gen):
    for _ in range(20):
        pwd = gen.generate(16, use_lowercase=True, use_uppercase=True,
                           use_digits=True, use_symbols=True)
        assert any(c.islower() for c in pwd)
        assert any(c.isupper() for c in pwd)
        assert any(c.isdigit() for c in pwd)
        assert any(c in gen.SYMBOLS for c in pwd)


def test_symbols_excluded(gen):
    for _ in range(20):
        pwd = gen.generate(16, use_symbols=False)
        assert not any(c in gen.SYMBOLS for c in pwd)


def test_strength_report_very_strong(gen):
    pwd = gen.generate(20)
    report = gen.check_strength(pwd)
    assert report.score >= 80
    assert report.label == "Very strong"


def test_strength_report_weak(gen):
    report = gen.check_strength("aaaaaaaa")
    assert report.label in ("Weak", "Fair")


def test_entropy_increases_with_length(gen):
    short = gen.check_strength("Abc1!xxx")
    long_ = gen.check_strength("Abc1!xxxAbc1!xxx")
    assert long_.entropy_bits > short.entropy_bits


def test_memorable_contains_separator(gen):
    phrase = gen.generate_memorable(num_words=3, separator="-")
    assert phrase.count("-") >= 3   # 3 words + 1 number = 4 parts → 3 separators


def test_memorable_ends_with_two_digit_number(gen):
    phrase = gen.generate_memorable()
    last_part = phrase.split("-")[-1]
    assert last_part.isdigit() and 10 <= int(last_part) <= 99
