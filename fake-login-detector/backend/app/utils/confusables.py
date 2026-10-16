"""
utils/confusables.py — Homoglyph normalization and skeleton computation.

The skeleton() function maps visually similar characters to a canonical ASCII
form so that domain lookalike detection is not fooled by character substitution.

All tables are defined as module-level constants so they load once.

Inputs:  a string (hostname label or brand label)
Outputs: a normalized "skeleton" string
Failure: returns the input lowercased on any error; never raises
"""
from __future__ import annotations

# ── Digit-to-letter substitutions (leet-speak) ───────────────────────────────
# Maps individual characters to their most common ASCII impersonation target.
DIGIT_SUBS: dict[str, str] = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
}

# ── Cyrillic and Greek lookalikes mapped to their Latin doppelgängers ─────────
# Only characters that are visually indistinguishable at typical font sizes.
UNICODE_LOOKALIKES: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u043e": "o",  # о → o
    "\u0440": "p",  # р → p
    "\u0441": "c",  # с → c
    "\u0445": "x",  # х → x
    "\u0455": "s",  # ѕ → s
    "\u0456": "i",  # і → i
    "\u0454": "e",  # є → e
    "\u0405": "s",  # Ѕ → s
    "\u0406": "i",  # І → i
    "\u0410": "a",  # А → a
    "\u0412": "b",  # В → b
    "\u0415": "e",  # Е → e
    "\u041a": "k",  # К → k
    "\u041c": "m",  # М → m
    "\u041d": "h",  # Н → h
    "\u041e": "o",  # О → o
    "\u0420": "p",  # Р → p
    "\u0421": "c",  # С → c
    "\u0422": "t",  # Т → t
    "\u0425": "x",  # Х → x
    # Greek
    "\u03b1": "a",  # α → a
    "\u03b2": "b",  # β → b
    "\u03b5": "e",  # ε → e
    "\u03b7": "n",  # η → n  (eta looks like n)
    "\u03b9": "i",  # ι → i
    "\u03bd": "v",  # ν → v
    "\u03bf": "o",  # ο → o
    "\u03c1": "p",  # ρ → p
    "\u03c5": "u",  # υ → u
    "\u03c7": "x",  # χ → x
    "\u0391": "a",  # Α → a
    "\u0392": "b",  # Β → b
    "\u0395": "e",  # Ε → e
    "\u0396": "z",  # Ζ → z
    "\u0397": "h",  # Η → h
    "\u0399": "i",  # Ι → i
    "\u039a": "k",  # Κ → k
    "\u039c": "m",  # Μ → m
    "\u039d": "n",  # Ν → n
    "\u039f": "o",  # Ο → o
    "\u03a1": "p",  # Ρ → p
    "\u03a4": "t",  # Τ → t
    "\u03a5": "y",  # Υ → y
    "\u03a7": "x",  # Χ → x
    # Fullwidth ASCII lookalikes
    **{chr(0xFF01 + i): chr(0x21 + i) for i in range(94)},
}

# ── Multi-character confusion sequences ──────────────────────────────────────
# Applied after per-character substitution, in order.
MULTI_CHAR_SUBS: list[tuple[str, str]] = [
    ("rn", "m"),   # "rn" is visually close to "m"
    ("vv", "w"),   # "vv" looks like "w"
    ("cl", "d"),   # "cl" approximates "d"
    ("li", "h"),   # rarely used but included for completeness
]


def skeleton(label: str) -> str:
    """
    Reduce a domain label (or brand name) to a canonical ASCII skeleton
    that is equal for visually similar strings.

    Steps:
      1. Lowercase.
      2. Decode punycode if the label starts with xn--.
      3. Map each character through UNICODE_LOOKALIKES.
      4. Map individual digits through DIGIT_SUBS.
      5. Apply MULTI_CHAR_SUBS (multi-character sequences).
      6. Strip hyphens and any remaining non-alphabetic characters.

    Inputs:  label — a hostname label or brand label string
    Outputs: normalized skeleton string (only lowercase a-z)
    Failure: returns label.lower() on any decoding error; never raises
    """
    if not label:
        return ""
    try:
        label = label.lower().strip()

        # Decode punycode
        if label.startswith("xn--"):
            try:
                import idna
                label = idna.decode(label.encode("ascii"))
            except Exception:
                pass  # keep as-is if decode fails

        # Per-character substitutions (unicode lookalikes first)
        result: list[str] = []
        for ch in label:
            ch = UNICODE_LOOKALIKES.get(ch, ch)
            ch = DIGIT_SUBS.get(ch, ch)
            result.append(ch)
        label = "".join(result)

        # Multi-character substitutions
        for pattern, replacement in MULTI_CHAR_SUBS:
            label = label.replace(pattern, replacement)

        # Strip everything that is not a-z
        label = "".join(ch for ch in label if "a" <= ch <= "z")
        return label

    except Exception:
        return (label or "").lower()


def char_diff(suspect_label: str, brand_label: str) -> list[dict[str, str]]:
    """
    Produce a character-level diff between the suspect label and the brand label.

    Each entry in the returned list has:
      char:   the character in the suspect label
      status: "match" | "substituted" | "extra" | "missing"

    This is used by the frontend's domainHighlight.js to render swapped chars
    in red.

    Inputs:  suspect_label — the hostname label from the suspect URL
             brand_label   — the canonical brand label
    Outputs: list of {"char": str, "status": str} dicts
    Failure: returns [] on any error; never raises
    """
    if not suspect_label or not brand_label:
        return []
    try:
        import difflib
        matcher = difflib.SequenceMatcher(None, brand_label, suspect_label, autojunk=False)
        result: list[dict[str, str]] = []
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for ch in suspect_label[j1:j2]:
                    result.append({"char": ch, "status": "match"})
            elif tag == "replace":
                for ch in suspect_label[j1:j2]:
                    result.append({"char": ch, "status": "substituted"})
            elif tag == "insert":
                for ch in suspect_label[j1:j2]:
                    result.append({"char": ch, "status": "extra"})
            elif tag == "delete":
                for ch in brand_label[i1:i2]:
                    result.append({"char": ch, "status": "missing"})
        return result
    except Exception:
        return []


if __name__ == "__main__":
    # Quick demo / REPL smoke-test
    tests = [
        ("c0llege", "college"),
        ("c\u043fllege", "college"),   # Cyrillic о
        ("rnicrosoft", "microsoft"),
        ("xn--vgr", "vgr"),
        ("portal-secure-login", "portal"),
    ]
    print("skeleton() demo:")
    for label, brand in tests:
        s = skeleton(label)
        b = skeleton(brand)
        print(f"  {label!r:30} → {s!r:20}  (brand skeleton: {b!r})")
    print()
    print("char_diff() demo:")
    diff = char_diff("c0llege", "college")
    print("  " + "".join(f"[{d['char']}:{d['status'][0]}]" for d in diff))
