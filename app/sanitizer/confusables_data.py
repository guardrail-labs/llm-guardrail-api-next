"""Lookup tables for Unicode confusable detection."""

from __future__ import annotations

from typing import Dict, Set

# Common zero-width characters that should be stripped during normalization.
ZERO_WIDTH_CHARACTERS: Set[str] = {
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u200e",  # LEFT-TO-RIGHT MARK
    "\u200f",  # RIGHT-TO-LEFT MARK
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u2060",  # WORD JOINER
    "\u2061",  # FUNCTION APPLICATION
    "\u2062",  # INVISIBLE TIMES
    "\u2063",  # INVISIBLE SEPARATOR
    "\u2064",  # INVISIBLE PLUS
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
}

# Minimal confusable mapping: characters that visually resemble ASCII
# letters or digits. This is intentionally small but covers common attacks.
CONFUSABLES_MAP: Dict[str, str] = {
    "\u0131": "i",  # LATIN SMALL LETTER DOTLESS I
    "\u0142": "l",  # LATIN SMALL LETTER L WITH STROKE
    "\u0391": "A",  # GREEK CAPITAL LETTER ALPHA
    "\u039f": "O",  # GREEK CAPITAL LETTER OMICRON
    "\u03a5": "Y",  # GREEK CAPITAL LETTER UPSILON
    "\u03bf": "o",  # GREEK SMALL LETTER OMICRON
    "\u0400": "E",  # CYRILLIC CAPITAL LETTER IE WITH GRAVE
    "\u0401": "E",  # CYRILLIC CAPITAL LETTER IO
    "\u0410": "A",  # CYRILLIC CAPITAL LETTER A
    "\u0412": "B",  # CYRILLIC CAPITAL LETTER VE
    "\u0415": "E",  # CYRILLIC CAPITAL LETTER IE
    "\u041a": "K",  # CYRILLIC CAPITAL LETTER KA
    "\u041c": "M",  # CYRILLIC CAPITAL LETTER EM
    "\u041d": "H",  # CYRILLIC CAPITAL LETTER EN
    "\u041e": "O",  # CYRILLIC CAPITAL LETTER O
    "\u041f": "P",  # CYRILLIC CAPITAL LETTER PE
    "\u0420": "P",  # CYRILLIC CAPITAL LETTER ER
    "\u0421": "C",  # CYRILLIC CAPITAL LETTER ES
    "\u0425": "X",  # CYRILLIC CAPITAL LETTER HA
    "\u0430": "a",  # CYRILLIC SMALL LETTER A
    "\u0435": "e",  # CYRILLIC SMALL LETTER IE
    "\u043e": "o",  # CYRILLIC SMALL LETTER O
    "\u0440": "p",  # CYRILLIC SMALL LETTER ER
    "\u0441": "c",  # CYRILLIC SMALL LETTER ES
    "\u0445": "x",  # CYRILLIC SMALL LETTER HA
    "\u2170": "i",  # SMALL ROMAN NUMERAL ONE
    "\u2171": "ii",  # SMALL ROMAN NUMERAL TWO
    "\u2172": "iii",  # SMALL ROMAN NUMERAL THREE
    "\u217c": "l",  # SMALL ROMAN NUMERAL FIFTY
    "\u2160": "I",  # ROMAN NUMERAL ONE
    "\u2161": "II",  # ROMAN NUMERAL TWO
    "\u216c": "L",  # ROMAN NUMERAL FIFTY
    "\u216f": "M",  # ROMAN NUMERAL ONE THOUSAND
    "\uff10": "0",  # FULLWIDTH DIGIT ZERO
    "\uff11": "1",  # FULLWIDTH DIGIT ONE
    "\uff12": "2",  # FULLWIDTH DIGIT TWO
    "\uff13": "3",  # FULLWIDTH DIGIT THREE
    "\uff14": "4",  # FULLWIDTH DIGIT FOUR
    "\uff15": "5",  # FULLWIDTH DIGIT FIVE
    "\uff16": "6",  # FULLWIDTH DIGIT SIX
    "\uff17": "7",  # FULLWIDTH DIGIT SEVEN
    "\uff18": "8",  # FULLWIDTH DIGIT EIGHT
    "\uff19": "9",  # FULLWIDTH DIGIT NINE
}

# Scripts considered high-risk for mixed-script spoofing when combined with
# basic Latin. The detection code performs a coarse check; keeping the set
# tight avoids false positives in legitimate multilingual content.
SUSPICIOUS_SCRIPTS: Dict[str, str] = {
    "CYRILLIC": "cyrillic",
    "GREEK": "greek",
    "ARMENIAN": "armenian",
    "HEBREW": "hebrew",
    "ARABIC": "arabic",
}
