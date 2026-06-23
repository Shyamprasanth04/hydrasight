from enum import Enum


class FindingConfidence(str, Enum):
    CANDIDATE = "CANDIDATE"     # Raw output from a script (e.g., Nmap NSE)
    OBSERVED = "OBSERVED"       # Manual note or simple observation
    PLAUSIBLE = "PLAUSIBLE"     # Version match suggests vulnerability
    VERIFIED = "VERIFIED"       # Active check confirmed the finding
    EXPLOITED = "EXPLOITED"     # Successful exploitation occurred
