using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.ServiceProcess;
using Microsoft.Win32;
using Sentinel.Models;

namespace Sentinel.Services;

public static class PersistenceScanner
{
    private static readonly string[] RemoteTools =
    {
        "anydesk", "teamviewer", "splashtop", "screenconnect", "connectwise",
        "rustdesk", "vnc", "radmin", "ammyy", "ultraviewer", "supremo",
        "logmein", "gotomypc", "chrome_remote", "remotepc", "dwagent",
        "meshagent", "tacticalrmm", "atera", "n-able", "kaseya", "syncro"
    };

    public static List<Finding> Run(SignatureDatabase db, Action<ScanProgress>? progress = null)
    {
        var findings = new List<Finding>();
        progress?.Invoke(new ScanProgress { Phase = "Persistence", Completed = 0, Total = 5, StatusLine = "Run keys" });
        findings.AddRange(RunKeys(db));
        progress?.Invoke(new ScanProgress { Phase = "Persistence", Completed = 1, Total = 5, StatusLine = "Startup folders" });
        findings.AddRange(StartupFolders(db));
        progress?.Invoke(new ScanProgress { Phase = "Persistence", Completed = 2, Total = 5, StatusLine = "Services" });
        findings.AddRange(Services(db));
        progress?.Invoke(new ScanProgress { Phase = "Persistence", Completed = 3, Total = 5, StatusLine = "Scheduled tasks" });
        findings.AddRange(ScheduledTasks(db));
        progress?.Invoke(new ScanProgress { Phase = "Persistence", Completed = 4, Total = 5, StatusLine = "Winlogon / IFEO" });
        findings.AddRange(WinlogonAndIfeo());
        return findings;
    }

    private static IEnumerable<Finding> RunKeys(SignatureDatabase db)
    {
        var paths = new (RegistryHive Hive, string Key)[]
        {
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (RegistryHive.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")
        };

        var items = new List<(string Source, string Name, string Command)>();
        foreach (var (hive, key) in paths)
        {
            if (!WinHelpers.IsWindows) break;
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var opened = baseKey.OpenSubKey(key);
                if (opened == null) continue;
                foreach (var name in opened.GetValueNames())
                {
                    var val = opened.GetValue(name)?.ToString();
                    if (!string.IsNullOrWhiteSpace(val))
                        items.Add(($"{hive}\\{key}", name, val));
                }
            }
            catch { /* ignore */ }
        }

        yield return new Finding
        {
            Category = FindingCategory.Persistence,
            Severity = Severity.Info,
            Title = $"Enumerated {items.Count} Run / RunOnce value(s)",
            Detail = string.Join("\n", items.Take(50).Select(i => $"{i.Name} = {i.Command}")),
            Remediation = "Remove leftover autoruns after uninstalling software. Unknown publishers in HKCU Run are a common malware foothold."
        };

        foreach (var item in items)
        {
            foreach (var finding in Judge(db, "Run key " + item.Name, item.Command, item.Source))
                yield return finding;
        }
    }

    private static IEnumerable<Finding> StartupFolders(SignatureDatabase db)
    {
        var folders = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
        };
        foreach (var folder in folders.Where(Directory.Exists))
        {
            foreach (var file in Directory.EnumerateFiles(folder))
            {
                var ext = Path.GetExtension(file).ToLowerInvariant();
                if (ext is ".ini") continue;
                foreach (var finding in Judge(db, "Startup folder item " + Path.GetFileName(file), file, folder))
                    yield return finding;
            }
        }
    }

    private static IEnumerable<Finding> Services(SignatureDatabase db)
    {
        if (!WinHelpers.IsWindows) yield break;
        ServiceController[]? services = null;
        try { services = ServiceController.GetServices(); } catch { yield break; }
        if (services is null) yield break;

        var weak = new List<string>();
        foreach (var svc in services)
        {
            string? image = null;
            try
            {
                image = WinHelpers.GetString(RegistryHive.LocalMachine,
                    $@"SYSTEM\CurrentControlSet\Services\{svc.ServiceName}", "ImagePath");
            }
            catch { /* ignore */ }
            if (string.IsNullOrWhiteSpace(image)) continue;

            var expanded = WinHelpers.Expand(image);
            if (image.Contains(' ') && !image.TrimStart().StartsWith('"') && expanded.Contains(' ') && !File.Exists(image.Trim('"')))
            {
                weak.Add($"{svc.ServiceName}: {image}");
            }

            if (svc.StartType == ServiceStartMode.Automatic)
            {
                foreach (var finding in Judge(db, "Service " + svc.ServiceName, image, svc.ServiceName, onlySuspicious: true))
                    yield return finding;
            }
        }

        if (weak.Count > 0)
        {
            yield return new Finding
            {
                Category = FindingCategory.Persistence,
                Severity = Severity.High,
                Title = $"{weak.Count} service(s) have unquoted paths with spaces",
                Detail = string.Join("\n", weak.Take(30)),
                Remediation = "Unquoted service paths can be hijacked by planting an .exe earlier on the path. Quote ImagePath or rename folders so they contain no spaces.",
                Host = "this-pc"
            };
        }
    }

    private static IEnumerable<Finding> ScheduledTasks(SignatureDatabase db)
    {
        var csv = WinHelpers.Run("schtasks", "/query /fo CSV /nh", 20000);
        if (string.IsNullOrWhiteSpace(csv)) yield break;

        var rows = csv.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0).Take(400).ToList();
        yield return new Finding
        {
            Category = FindingCategory.Persistence,
            Severity = Severity.Info,
            Title = $"Enumerated scheduled tasks (showing {Math.Min(rows.Count, 40)} of {rows.Count})",
            Detail = string.Join("\n", rows.Take(40)),
            Remediation = "Review tasks that run from user-writable paths or call powershell/cmd/wscript/mshta.",
            Host = "this-pc"
        };

        foreach (var row in rows)
        {
            var lower = row.ToLowerInvariant();
            if (lower.Contains("\\appdata\\") || lower.Contains("\\temp\\") || lower.Contains("powershell")
                || lower.Contains("wscript") || lower.Contains("mshta") || lower.Contains("cmd /c")
                || lower.Contains("\\users\\public\\"))
            {
                yield return new Finding
                {
                    Category = FindingCategory.Persistence,
                    Severity = Severity.High,
                    Title = "Suspicious scheduled task",
                    Detail = row,
                    Remediation = "Open Task Scheduler and delete tasks you did not create, especially those launching scripts from AppData or Temp.",
                    Host = "this-pc",
                    Evidence = row
                };
            }
        }
    }

    private static IEnumerable<Finding> WinlogonAndIfeo()
    {
        var shell = WinHelpers.GetString(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell");
        var userinit = WinHelpers.GetString(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit");
        if (!string.IsNullOrEmpty(shell) && !shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase)
            && !shell.Trim().EndsWith("\\explorer.exe", StringComparison.OrdinalIgnoreCase))
        {
            yield return new Finding
            {
                Category = FindingCategory.Persistence,
                Severity = Severity.Critical,
                Title = "Winlogon Shell is not explorer.exe",
                Detail = shell,
                Remediation = "Restore Shell to explorer.exe. This is a classic persistence/hijack technique.",
                Host = "this-pc"
            };
        }
        if (!string.IsNullOrEmpty(userinit) && !userinit.Contains("userinit.exe", StringComparison.OrdinalIgnoreCase))
        {
            yield return new Finding
            {
                Category = FindingCategory.Persistence,
                Severity = Severity.Critical,
                Title = "Winlogon Userinit does not include userinit.exe",
                Detail = userinit,
                Remediation = "Restore Userinit to C:\\Windows\\system32\\userinit.exe,",
                Host = "this-pc"
            };
        }
        else if (!string.IsNullOrEmpty(userinit) && userinit.Contains(',') &&
                 userinit.Split(',').Select(s => s.Trim()).Any(s => s.Length > 0 && !s.Contains("userinit.exe", StringComparison.OrdinalIgnoreCase)))
        {
            yield return new Finding
            {
                Category = FindingCategory.Persistence,
                Severity = Severity.Critical,
                Title = "Winlogon Userinit has extra programs",
                Detail = userinit,
                Remediation = "Remove unexpected entries after userinit.exe.",
                Host = "this-pc"
            };
        }

        var appInit = WinHelpers.GetString(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs");
        if (!string.IsNullOrWhiteSpace(appInit))
        {
            yield return new Finding
            {
                Category = FindingCategory.Persistence,
                Severity = Severity.High,
                Title = "AppInit_DLLs is set",
                Detail = appInit,
                Remediation = "Clear AppInit_DLLs unless a known security product requires it. This injects DLLs into many processes.",
                Host = "this-pc"
            };
        }

        if (WinHelpers.IsWindows)
        {
            foreach (var finding in IfeoDebuggers())
                yield return finding;
        }
    }

    private static List<Finding> IfeoDebuggers()
    {
        var list = new List<Finding>();
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var ifeo = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options");
            if (ifeo == null) return list;
            foreach (var sub in ifeo.GetSubKeyNames())
            {
                using var child = ifeo.OpenSubKey(sub);
                var debugger = child?.GetValue("Debugger")?.ToString();
                if (string.IsNullOrWhiteSpace(debugger)) continue;
                list.Add(new Finding
                {
                    Category = FindingCategory.Persistence,
                    Severity = Severity.Critical,
                    Title = $"IFEO debugger set on {sub}",
                    Detail = debugger,
                    Remediation = "Image File Execution Options debuggers launch instead of the real program. Remove unexpected Debugger values.",
                    Host = "this-pc",
                    Evidence = $@"HKLM\...\Image File Execution Options\{sub}"
                });
            }
        }
        catch { /* ignore */ }
        return list;
    }

    private static IEnumerable<Finding> Judge(SignatureDatabase db, string title, string command, string source, bool onlySuspicious = false)
    {
        var path = WinHelpers.Expand(command);
        var reasons = new List<string>();
        if (WinHelpers.LooksTemp(path) || WinHelpers.LooksTemp(command)) reasons.Add("lives in a temp / public path");
        if (command.Contains("powershell", StringComparison.OrdinalIgnoreCase) &&
            (command.Contains("-enc", StringComparison.OrdinalIgnoreCase) || command.Contains("-e ", StringComparison.OrdinalIgnoreCase)
             || command.Contains("FromBase64", StringComparison.OrdinalIgnoreCase) || command.Contains("IEX", StringComparison.OrdinalIgnoreCase)
             || command.Contains("hidden", StringComparison.OrdinalIgnoreCase)))
            reasons.Add("encoded or hidden PowerShell");
        if (command.Contains("mshta", StringComparison.OrdinalIgnoreCase) || command.Contains("wscript", StringComparison.OrdinalIgnoreCase)
            || command.Contains("cscript", StringComparison.OrdinalIgnoreCase) || command.Contains("regsvr32", StringComparison.OrdinalIgnoreCase)
            || command.Contains("rundll32", StringComparison.OrdinalIgnoreCase) && command.Contains("javascript", StringComparison.OrdinalIgnoreCase))
            reasons.Add("living-off-the-land script host");
        if (path.Contains("\\appdata\\", StringComparison.OrdinalIgnoreCase) && path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            reasons.Add("unsigned-looking exe from AppData");

        string? hash = null;
        if (File.Exists(path)) hash = SignatureDatabase.Sha256File(path);
        reasons.AddRange(db.Match(path.Length > 0 ? path : command, hash, title));

        var lower = (path + " " + command).ToLowerInvariant();
        if (RemoteTools.Any(t => lower.Contains(t)))
            reasons.Add("remote-access / RMM tool — confirm you installed it");

        if (onlySuspicious && reasons.Count == 0) yield break;
        if (reasons.Count == 0) yield break;

        var critical = reasons.Any(r => r.Contains("SHA-256", StringComparison.OrdinalIgnoreCase) || r.Contains("known malware"));
        yield return new Finding
        {
            Category = critical ? FindingCategory.Malware : FindingCategory.Persistence,
            Severity = critical ? Severity.Critical : (reasons.Any(r => r.Contains("PowerShell") || r.Contains("temp")) ? Severity.High : Severity.Medium),
            Title = "Suspicious persistence: " + title,
            Detail = string.Join("\n", reasons) + "\n" + command,
            Remediation = "Do not run the program. Disable the Run key / task / service, quarantine the file, and investigate the vendor.",
            Host = "this-pc",
            Evidence = source + " :: " + command
        };
    }
}
