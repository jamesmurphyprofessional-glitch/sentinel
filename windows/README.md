# Sentinel 2.0 for Windows

Windows edition of Sentinel: a defensive scanner for **your** LAN and this PC.

It does **not** exploit services, try passwords, or send attack payloads.

## What it does

Everything the macOS Sentinel does, plus Windows-specific security coverage:

- Network connect-scan and banner / HTTP HEAD identification
- Listening sockets on this PC
- Defender, firewall profiles, UAC, WDigest, LSA, NTLM, AlwaysInstallElevated
- SMBv1, LLMNR, BitLocker, Secure Boot
- RDP + NLA, WinRM, Remote Registry, Telnet
- Autoruns: Run keys, Startup folders, services (including unquoted paths), scheduled tasks, Winlogon, IFEO, AppInit_DLLs
- Process hunt (system-process impersonation, temp/AppData, RMM tools, hash vs IOC set)
- Local admins, Guest, saved credentials
- Event log triage (4625, 4624 type 10, 7045, PowerShell 4104)
- Hosts file, user proxy, USBSTOR history, SMB shares
- Signature updates from MalwareBazaar, ThreatFox, URLhaus (download only)

## Requirements
- 64-bit Windows 10 / 11
- Permission to scan the network
- Administrator recommended for Security event logs

## Use
1. Check the authorization box on Overview.
2. **Scan Network** and/or **Scan This PC**.
3. Review Findings. Export Markdown or HTML.
4. Signatures → Update now.

This is not a substitute for Microsoft Defender or an EDR product.
