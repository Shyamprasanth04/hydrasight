from hydrasight.core.registry import registry
from hydrasight.models.actions import ActionArgSchema, ActionDefinition, ROECategory


def register_builtins():
    registry.register(ActionDefinition(
        action_id="nmap_scan",
        display_name="Nmap Port Scan",
        roe_category=ROECategory.RECON,
        description="Standard Nmap port and service scan",
        tool_family="nmap",
        default_timeout=600,
        default_ports=[1, 1000],
        args={
            "target": ActionArgSchema("target", str, required=True),
            "ports": ActionArgSchema("ports", str, default="1-1000"),
            "scan_type": ActionArgSchema("scan_type", str, default="-sV -sC"),
            "additional_args": ActionArgSchema("additional_args", str, default="-T4 -Pn")
        },
        aliases=["scan"]
    ))

    registry.register(ActionDefinition(
        action_id="smb_check",
        display_name="SMB Vuln Check",
        roe_category=ROECategory.VULN,
        description="Check for common SMB vulnerabilities like MS17-010",
        tool_family="nmap",
        default_timeout=300,
        args={
            "target": ActionArgSchema("target", str, required=True),
        }
    ))

    registry.register(ActionDefinition(
        action_id="smb_enum",
        display_name="SMB Enumeration",
        roe_category=ROECategory.ENUM,
        description="Enumerate SMB shares and users using enum4linux",
        tool_family="enum4linux",
        default_timeout=240,
        args={
            "target": ActionArgSchema("target", str, required=True),
        }
    ))

    registry.register(ActionDefinition(
        action_id="smbclient_enum",
        display_name="SMB Client Share List",
        roe_category=ROECategory.ENUM,
        description="List shares using smbclient",
        tool_family="smbclient",
        default_timeout=120,
        args={
            "target": ActionArgSchema("target", str, required=True),
        }
    ))

    registry.register(ActionDefinition(
        action_id="ftp_check",
        display_name="FTP Vuln Check",
        roe_category=ROECategory.VULN,
        description="Check FTP for anonymous access and vulns",
        tool_family="nmap",
        default_timeout=300,
        args={
            "target": ActionArgSchema("target", str, required=True),
        }
    ))

    registry.register(ActionDefinition(
        action_id="ssh_check",
        display_name="SSH Auth Check",
        roe_category=ROECategory.ENUM,
        description="Check SSH auth methods",
        tool_family="nmap",
        default_timeout=300,
        args={
            "target": ActionArgSchema("target", str, required=True),
        }
    ))

    registry.register(ActionDefinition(
        action_id="vuln_scan",
        display_name="Nmap Vuln Scan",
        roe_category=ROECategory.VULN,
        description="Run Nmap vuln scripts on common ports",
        tool_family="nmap",
        default_timeout=600,
        args={
            "target": ActionArgSchema("target", str, required=True),
            "ports": ActionArgSchema("ports", str, default="21,22,80,135,139,443,445,8080"),
        }
    ))

    registry.register(ActionDefinition(
        action_id="dir_enum",
        display_name="Directory Enumeration",
        roe_category=ROECategory.ENUM,
        description="Discover web directories",
        tool_family="gobuster",
        default_timeout=300,
        args={
            "target": ActionArgSchema("target", str, required=True),
            "wordlist": ActionArgSchema("wordlist", str, default="/usr/share/wordlists/dirb/common.txt"),
        }
    ))

    registry.register(ActionDefinition(
        action_id="autopwn",
        display_name="AutoPwn",
        roe_category=ROECategory.EXPLOIT,
        description="Full adaptive engagement",
        tool_family="hydrasight",
        default_timeout=3600,
        args={
            "target": ActionArgSchema("target", str, required=True),
        }
    ))

    # Test compatibility actions
    registry.register(ActionDefinition(
        action_id="run_command",
        display_name="Run Command",
        roe_category=ROECategory.RECON,
        description="Run arbitrary command",
        tool_family="shell",
        default_timeout=300,
        args={"command": ActionArgSchema("command", str, required=True)}
    ))

    registry.register(ActionDefinition(
        action_id="ssh_brute",
        display_name="SSH Brute Force",
        roe_category=ROECategory.EXPLOIT,
        description="Brute force SSH",
        tool_family="hydra",
        default_timeout=600,
        args={"target": ActionArgSchema("target", str, required=True)}
    ))

    registry.register(ActionDefinition(
        action_id="ftp_brute",
        display_name="FTP Brute Force",
        roe_category=ROECategory.EXPLOIT,
        description="Brute force FTP",
        tool_family="hydra",
        default_timeout=600,
        args={"target": ActionArgSchema("target", str, required=True)}
    ))

    registry.register(ActionDefinition(
        action_id="nikto_scan",
        display_name="Nikto Scan",
        roe_category=ROECategory.VULN,
        description="Web vulnerability scanner",
        tool_family="nikto",
        default_timeout=600,
        args={"target": ActionArgSchema("target", str, required=True)},
        aliases=["nikto"]
    ))

    registry.register(ActionDefinition(
        action_id="gobuster_scan",
        display_name="Gobuster Scan",
        roe_category=ROECategory.ENUM,
        description="Directory brute force",
        tool_family="gobuster",
        default_timeout=600,
        args={"target": ActionArgSchema("target", str, required=True)},
        aliases=["gobuster"]
    ))
