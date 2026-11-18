# sdk/src/openapl/controls.py
"""Framework-to-control table (design §4.5)."""

CONTROLS: dict[str, tuple[str, ...]] = {
    "NIST-800-53": ("NIST-800-53:AC-3", "NIST-800-53:AC-6"),
    "SOC2": ("SOC2:CC6.1", "SOC2:CC6.3"),
}

# Controls the decision log itself bears on; cited by evidence export only.
LOG_CONTROLS = ("NIST-800-53:AU-2", "NIST-800-53:AU-3")
