from dataclasses import dataclass, field


@dataclass
class ScanProfile:
    name: str
    description: str
    port_mode: str  # "top", "list", "all"
    top_ports: int | None = None
    ports: list[int] | None = None
    service_detection: bool = False
    default_scripts: list[str] = field(default_factory=list)
    timing_template: int | None = None
    staged: bool = False
    stage_two_service_detection: bool = False
    stage_three_targeted_scripts: bool = False
    timeout_multiplier: float = 1.0

PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Top 100 ports, fast timing, light version detection",
        port_mode="top",
        top_ports=100,
        service_detection=True,
        default_scripts=[],
        timing_template=4,
        staged=False,
        timeout_multiplier=0.5
    ),
    "default": ScanProfile(
        name="default",
        description="Top 1000 ports, standard version detection",
        port_mode="top",
        top_ports=1000,
        service_detection=True,
        default_scripts=["default"],
        timing_template=3,
        staged=False,
        timeout_multiplier=1.0
    ),
    "deep": ScanProfile(
        name="deep",
        description="All TCP ports, staged service detection",
        port_mode="all",
        service_detection=False, # Handled in stage two
        default_scripts=[],
        timing_template=3,
        staged=True,
        stage_two_service_detection=True,
        stage_three_targeted_scripts=False,
        timeout_multiplier=3.0
    ),
    "web": ScanProfile(
        name="web",
        description="Focus on common web ports",
        port_mode="list",
        ports=[80, 443, 8080, 8443],
        service_detection=True,
        default_scripts=["http-title", "http-methods"],
        timing_template=3,
        staged=False,
        timeout_multiplier=1.0
    ),
    "smb": ScanProfile(
        name="smb",
        description="Focus on SMB ports",
        port_mode="list",
        ports=[139, 445],
        service_detection=True,
        default_scripts=["smb-os-discovery", "smb-security-mode"],
        timing_template=3,
        staged=False,
        timeout_multiplier=1.0
    )
}
