using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.ServiceProcess;
using Microsoft.Win32;
using Sentinel.Models;

namespace Sentinel.Services;

public static class HardeningScanner
{
    public static List<Finding> Run(Action<ScanProgress>? progress = null)
    {
        progress?.Invoke(new ScanProgress { Phase = "Windows hardening", Completed = 0, Total = 1, StatusLine = "Reading security posture" });
        var findings = new List<Finding>();
        findings.AddRange(ListeningSockets());
        findings.AddRange(Defender());
        findings.AddRange(Firewall());
        findings.AddRange(UacAndAuth());
        findings.AddRange(RemoteAccess());
        findings.AddRange(SmbAndDiscovery());
        findings.AddRange(PowerShell());
        findings.AddRange(BitLockerAndSecureBoot());
        findings.AddRange(Integrity());
        findings.AddRange(Shares());
        if (!WinHelpers.IsWindows)
        {
            findings.Add(new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.Info,
                Title = "Windows hardening checks run only on Windows",
                Detail = "This build was launched on a non-Windows host. The full This-PC pass is included in the Windows .exe.",
                Remediation = "Run Sentinel.exe on the Windows PC you want to assess."
            });
        }
        return findings;
    }

    public static List<Finding> ListeningSockets()
    {
        var findings = new List<Finding>();
        try
        {
            var props = IPGlobalProperties.GetIPGlobalProperties();
            var listeners = props.GetActiveTcpListeners()
                .Where(ep => ep.Port > 0)
                .Select(ep => (Address: ep.Address.ToString(), ep.Port, Exposed: !IsLoopback(ep.Address.ToString())))
                .Distinct()
                .ToList();

            var owners = ParseNetstat();
            var exposed = listeners.Where(l => l.Exposed).ToList();
            findings.Add(new Finding
            {
                Category = FindingCategory.Listening,
                Severity = exposed.Count == 0 ? Severity.Info : Severity.Medium,
                Title = $"{listeners.Count} listening TCP socket(s) on this PC",
                Detail = string.Join("\n", listeners.Take(80).Select(l =>
                {
                    owners.TryGetValue($"{l.Address}:{l.Port}", out var proc);
                    owners.TryGetValue($"0.0.0.0:{l.Port}", out var any);
                    return $"{l.Address}:{l.Port}  {proc ?? any ?? ""}";
                })),
                Remediation = "Anything bound to 0.0.0.0 or :: is reachable from other devices on the LAN (and the WAN, if port-forwarded).",
                Host = "this-pc"
            });

            foreach (var sock in exposed)
            {
                var profile = PortCatalog.Profile(sock.Port);
                if (profile.Risk < Severity.Medium && sock.Port > 49152) continue;
                owners.TryGetValue($"0.0.0.0:{sock.Port}", out var proc);
                owners.TryGetValue($"{sock.Address}:{sock.Port}", out var proc2);
                var process = proc2 ?? proc ?? "unknown process";
                findings.Add(new Finding
                {
                    Category = profile.Risk >= Severity.High ? FindingCategory.RemoteAccess : FindingCategory.Listening,
                    Severity = profile.Risk < Severity.Medium ? Severity.Medium : profile.Risk,
                    Title = $"{process} is listening on {sock.Address}:{sock.Port} ({profile.Service})",
                    Detail = profile.Reason,
                    Remediation = "If you do not need this service, stop it or bind it to 127.0.0.1. Restrict inbound rules in Windows Defender Firewall.",
                    Host = "this-pc",
                    Evidence = $"{process} {sock.Address}:{sock.Port}"
                });
            }
        }
        catch (Exception ex)
        {
            findings.Add(new Finding
            {
                Category = FindingCategory.Listening,
                Severity = Severity.Info,
                Title = "Could not enumerate listening sockets",
                Detail = ex.Message,
                Remediation = "Run Sentinel as Administrator for a complete listener list."
            });
        }
        return findings;
    }

    private static Dictionary<string, string> ParseNetstat()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var output = WinHelpers.Run("netstat", "-ano -p TCP");
        if (string.IsNullOrEmpty(output)) return map;
        foreach (var line in output.Split('\n'))
        {
            if (!line.Contains("LISTENING", StringComparison.OrdinalIgnoreCase)) continue;
            var cols = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (cols.Length < 4) continue;
            var local = cols[1];
            var pid = cols[^1];
            map[local] = "pid " + pid;
        }
        return map;
    }

    private static bool IsLoopback(string address) =>
        address is "127.0.0.1" or "::1" or "localhost" || address.StartsWith("127.");

    private static IEnumerable<Finding> Defender()
    {
        var disabled = WinHelpers.GetInt(RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
        var tamper = WinHelpers.GetInt(RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows Defender\Features", "TamperProtection");
        yield return new Finding
        {
            Category = FindingCategory.Hardening,
            Severity = disabled == 1 ? Severity.Critical : Severity.Info,
            Title = disabled == 1 ? "Microsoft Defender real-time protection is disabled" : "Defender real-time protection appears enabled (or not overridden)",
            Detail = $"DisableRealtimeMonitoring={disabled?.ToString() ?? "not set"}, TamperProtection={tamper?.ToString() ?? "unknown"}",
            Remediation = "Open Windows Security → Virus & threat protection and turn real-time protection on. Investigate anything that disabled it.",
            Host = "this-pc"
        };
    }

    private static IEnumerable<Finding> Firewall()
    {
        foreach (var (name, key) in new[]
                 {
                     ("Domain", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
                     ("Private", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
                     ("Public", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile")
                 })
        {
            var enabled = WinHelpers.GetInt(RegistryHive.LocalMachine, key, "EnableFirewall");
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = enabled == 0 ? Severity.High : Severity.Info,
                Title = enabled == 0 ? $"Windows Firewall is OFF on the {name} profile" : $"Windows Firewall is on ({name} profile)",
                Detail = $"{name} EnableFirewall={enabled?.ToString() ?? "unknown"}",
                Remediation = "Enable the firewall for every profile. Do not turn it off to 'fix' an app.",
                Host = "this-pc"
            };
        }
    }

    private static IEnumerable<Finding> UacAndAuth()
    {
        var lua = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
        var prompt = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
        var wdigest = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential");
        var lsa = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
        var lm = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel");
        var autoLogon = WinHelpers.GetString(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon");
        var alwaysInstall = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
                            ?? WinHelpers.GetInt(RegistryHive.CurrentUser, @"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated");

        yield return Flag("UAC (EnableLUA)", lua != 0, Severity.Critical,
            "User Account Control is disabled", "UAC is enabled",
            "Re-enable UAC. Disabling it lets any process elevate without a prompt.");
        if (prompt is 0)
        {
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.High,
                Title = "UAC is set to never notify",
                Detail = "ConsentPromptBehaviorAdmin=0",
                Remediation = "Set UAC to at least 'Notify me only when apps try to make changes'.",
                Host = "this-pc"
            };
        }
        if (wdigest == 1)
        {
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.Critical,
                Title = "WDigest is storing logon credentials in memory",
                Detail = "UseLogonCredential=1 lets tools like Mimikatz recover cleartext passwords.",
                Remediation = "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0 and reboot.",
                Host = "this-pc"
            };
        }
        yield return Flag("LSA protection", lsa is 1 or 2, Severity.Medium,
            "LSA protection (RunAsPPL) is not enabled",
            "LSA protection is enabled",
            "Enable RunAsPPL to make credential dumping harder.");
        if (lm is >= 0 and <= 2)
        {
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.High,
                Title = "LM / NTLMv1 authentication is allowed",
                Detail = $"LmCompatibilityLevel={lm}",
                Remediation = "Set LmCompatibilityLevel to 5 (send NTLMv2 only, refuse LM/NTLM).",
                Host = "this-pc"
            };
        }
        if (autoLogon is "1")
        {
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.High,
                Title = "Automatic administrator logon is enabled",
                Detail = "AutoAdminLogon=1 stores or applies a password at boot.",
                Remediation = "Disable AutoAdminLogon and remove DefaultPassword from Winlogon.",
                Host = "this-pc"
            };
        }
        if (alwaysInstall == 1)
        {
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.Critical,
                Title = "AlwaysInstallElevated is enabled",
                Detail = "Any user can install an MSI as SYSTEM.",
                Remediation = "Set AlwaysInstallElevated to 0 in both HKLM and HKCU installer policy keys.",
                Host = "this-pc"
            };
        }
    }

    private static IEnumerable<Finding> RemoteAccess()
    {
        var denyRdp = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
        var nla = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
        yield return new Finding
        {
            Category = FindingCategory.RemoteAccess,
            Severity = denyRdp == 0 ? Severity.High : Severity.Info,
            Title = denyRdp == 0 ? "Remote Desktop is enabled" : "Remote Desktop is disabled",
            Detail = $"fDenyTSConnections={denyRdp?.ToString() ?? "unknown"}, NLA={nla?.ToString() ?? "unknown"}",
            Remediation = denyRdp == 0
                ? "Disable RDP if unused. If required, enable NLA, restrict to named users, and do not expose 3389 to the internet."
                : "Keep RDP disabled unless you have a specific need.",
            Host = "this-pc"
        };
        if (denyRdp == 0 && nla == 0)
        {
            yield return new Finding
            {
                Category = FindingCategory.RemoteAccess,
                Severity = Severity.Critical,
                Title = "RDP is enabled without Network Level Authentication",
                Detail = "UserAuthentication=0 allows pre-auth RDP handshakes that are easier to brute-force.",
                Remediation = "Enable NLA on the RDP host.",
                Host = "this-pc"
            };
        }

        if (WinHelpers.IsWindows)
        {
            foreach (var svc in new[] { "TermService", "WinRM", "RemoteRegistry", "SSDPSRV", "upnphost", "TlntSvr", "ftpsvc" })
            {
                var state = ServiceState(svc);
                if (state is "Running" && svc is "RemoteRegistry" or "TlntSvr" or "WinRM")
                {
                    yield return new Finding
                    {
                        Category = FindingCategory.RemoteAccess,
                        Severity = svc == "TlntSvr" ? Severity.Critical : Severity.High,
                        Title = $"Service {svc} is running",
                        Detail = $"{svc} status={state}",
                        Remediation = $"Stop and disable {svc} if you do not need remote administration.",
                        Host = "this-pc"
                    };
                }
            }
        }
    }

    private static IEnumerable<Finding> SmbAndDiscovery()
    {
        var smb1 = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
        if (smb1 == 1)
        {
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.Critical,
                Title = "SMBv1 is enabled",
                Detail = "SMB1=1. WannaCry/EternalBlue-class worms used SMBv1.",
                Remediation = "Disable SMBv1 (optional features / registry) and reboot.",
                Host = "this-pc"
            };
        }

        var llmnr = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast");
        if (llmnr != 0)
        {
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.Medium,
                Title = "LLMNR multicast name resolution is allowed",
                Detail = "Attackers on the LAN can spoof LLMNR/NBT-NS and capture hashes.",
                Remediation = "Set EnableMulticast=0 under DNSClient policy, and disable NetBIOS on adapters if you do not need it.",
                Host = "this-pc"
            };
        }
    }

    private static IEnumerable<Finding> PowerShell()
    {
        var scriptBlock = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging");
        var exec = WinHelpers.GetString(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell", "ExecutionPolicy")
                   ?? WinHelpers.Run("powershell", "-NoProfile -Command \"Get-ExecutionPolicy\"")?.Trim();
        yield return new Finding
        {
            Category = FindingCategory.Hardening,
            Severity = scriptBlock == 1 ? Severity.Info : Severity.Low,
            Title = scriptBlock == 1 ? "PowerShell Script Block Logging is on" : "PowerShell Script Block Logging is not enforced",
            Detail = $"ExecutionPolicy={exec ?? "unknown"}",
            Remediation = "Enable Script Block Logging and Transcription via GPO for forensic visibility. ExecutionPolicy is not a security boundary.",
            Host = "this-pc"
        };
    }

    private static IEnumerable<Finding> BitLockerAndSecureBoot()
    {
        var bl = WinHelpers.Run("manage-bde", "-status C:");
        if (!string.IsNullOrEmpty(bl))
        {
            var off = bl.Contains("Protection Off", StringComparison.OrdinalIgnoreCase)
                      || bl.Contains("Fully Decrypted", StringComparison.OrdinalIgnoreCase);
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = off ? Severity.High : Severity.Info,
                Title = off ? "BitLocker protection is off on C:" : "BitLocker status was read for C:",
                Detail = WinHelpers.Truncate(bl, 1500),
                Remediation = "Turn on BitLocker for the system volume so a stolen disk is not readable.",
                Host = "this-pc"
            };
        }

        var secureBoot = WinHelpers.GetInt(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
        if (secureBoot is 0)
        {
            yield return new Finding
            {
                Category = FindingCategory.Hardening,
                Severity = Severity.Medium,
                Title = "UEFI Secure Boot is disabled",
                Detail = "UEFISecureBootEnabled=0",
                Remediation = "Enable Secure Boot in firmware so bootkits are harder to persist.",
                Host = "this-pc"
            };
        }
    }

    private static IEnumerable<Finding> Integrity()
    {
        var list = new List<Finding>();
        try
        {
            var hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"drivers\etc\hosts");
            if (File.Exists(hosts))
            {
                var lines = File.ReadAllLines(hosts)
                    .Select(l => l.Trim())
                    .Where(l => l.Length > 0 && !l.StartsWith('#') && !l.StartsWith("127.0.0.1") && !l.StartsWith("::1"))
                    .ToList();
                if (lines.Count > 0)
                {
                    list.Add(new Finding
                    {
                        Category = FindingCategory.Integrity,
                        Severity = Severity.High,
                        Title = $"Hosts file has {lines.Count} non-default mapping(s)",
                        Detail = string.Join("\n", lines.Take(40)),
                        Remediation = "Malware often redirects banks/AV/update hosts. Remove unexpected mappings from %SystemRoot%\\System32\\drivers\\etc\\hosts.",
                        Host = "this-pc",
                        Evidence = hosts
                    });
                }
            }
        }
        catch { /* ignore */ }

        var proxy = WinHelpers.GetInt(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyEnable");
        var proxyServer = WinHelpers.GetString(RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "ProxyServer");
        if (proxy == 1 && !string.IsNullOrWhiteSpace(proxyServer))
        {
            list.Add(new Finding
            {
                Category = FindingCategory.Integrity,
                Severity = Severity.High,
                Title = "A system proxy is configured",
                Detail = proxyServer!,
                Remediation = "Confirm you set this proxy. Stealers and corporate-spyware set user proxies to intercept traffic.",
                Host = "this-pc"
            });
        }
        return list;
    }

    private static IEnumerable<Finding> Shares()
    {
        var output = WinHelpers.Run("net", "share");
        if (string.IsNullOrWhiteSpace(output)) yield break;
        var interesting = output.Split('\n')
            .Select(l => l.TrimEnd())
            .Where(l => l.Contains('$') || l.StartsWith("C ", StringComparison.OrdinalIgnoreCase) || l.Contains("Default share"))
            .ToList();
        yield return new Finding
        {
            Category = FindingCategory.Hardening,
            Severity = Severity.Info,
            Title = "Local SMB shares",
            Detail = WinHelpers.Truncate(output, 2000),
            Remediation = "Remove unused shares. Administrative shares (C$, ADMIN$) are expected on some domain PCs but expand blast radius.",
            Host = "this-pc",
            Evidence = string.Join("\n", interesting)
        };
    }

    private static string? ServiceState(string name)
    {
        if (!WinHelpers.IsWindows) return null;
        try
        {
            using var sc = new ServiceController(name);
            return sc.Status.ToString();
        }
        catch
        {
            return null;
        }
    }

    private static Finding Flag(string _, bool good, Severity badSeverity, string badTitle, string goodTitle, string rem) =>
        new()
        {
            Category = FindingCategory.Hardening,
            Severity = good ? Severity.Info : badSeverity,
            Title = good ? goodTitle : badTitle,
            Detail = good ? goodTitle : badTitle,
            Remediation = rem,
            Host = "this-pc"
        };
}
