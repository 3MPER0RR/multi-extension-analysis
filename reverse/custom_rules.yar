/*
        Custom YARA Rules
    ====================================
    Add your own rules below.
    Use: python3 analyzer.py sample.bin --yara custom_rules.yar

    Reference: https://yara.readthedocs.io/
*/

// ── Example: Custom APT signature ─────────────────────────────────────────

rule Custom_Suspicious_URL {
    meta:
        description = "Hardcoded suspicious domain/IP"
        severity    = "HIGH"
        author      = "Your Name"
    strings:
        // Add your C2 domains/IPs here
        $c2_1 = "evil.example.com" nocase ascii wide
        $c2_2 = "192.168.100.200"  ascii
    condition:
        any of them
}

rule Custom_Encoded_Payload {
    meta:
        description = "PowerShell encoded command"
        severity    = "CRITICAL"
    strings:
        $enc1 = "-EncodedCommand" nocase ascii wide
        $enc2 = "-enc "           nocase ascii wide
        $enc3 = "powershell"      nocase ascii wide
    condition:
        ($enc1 or $enc2) and $enc3
}

rule Custom_Reverse_Shell_Python {
    meta:
        description = "Python reverse shell pattern"
        severity    = "CRITICAL"
    strings:
        $s1 = "import socket" ascii
        $s2 = "s.connect("    ascii
        $s3 = "os.dup2("      ascii
    condition:
        2 of them
}

rule Custom_C2_Beacon_HTTP {
    meta:
        description = "Basic HTTP beacon pattern"
        severity    = "HIGH"
    strings:
        $ua   = "User-Agent:"        ascii
        $post = "POST /"             ascii
        $host = "Host:"              ascii
        $beat = /sleep\(\d{4,6}\)/  ascii
    condition:
        3 of them
}

// ── Add more rules below ───────────────────────────────────────────────────
