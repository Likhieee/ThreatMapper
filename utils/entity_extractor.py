"""
Entity extractor – pulls a threat actor name out of a free-text question.
"""
import re

KNOWN_ACTORS = [
    "APT28", "APT29", "APT32", "APT33", "APT34", "APT38", "APT40", "APT41",
    "Lazarus Group", "Lazarus", "Sandworm", "OilRig", "FIN7", "FIN6",
    "Carbanak", "Cobalt Group", "MuddyWater", "Kimsuky", "Turla",
    "Volt Typhoon", "Wizard Spider", "DarkHydrus", "Chimera",
    "Leviathan", "Dragonfly", "Equation Group", "Cozy Bear", "Fancy Bear",
]


def extract_actor(text: str):
    """Return the first matching actor name found in *text*, or None."""
    text_lower = text.lower()
    for actor in sorted(KNOWN_ACTORS, key=len, reverse=True):  # longest first
        if actor.lower() in text_lower:
            return actor
    return None
