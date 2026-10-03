using System;
using System.Collections.Generic;
using System.Linq;
using Sentinel.Models;

namespace Sentinel.Services;

public static class AccountScanner
{
    public static List<Finding> Run(Action<ScanProgress>? progress = null)
    {
        progress?.Invoke(new ScanProgress { Phase = "Accounts", Completed = 0, Total = 1, StatusLine = "Local users and admins" });
        var findings = new List<Finding>();

        var users = WinHelpers.Run("net", "user");
        var admins = WinHelpers.Run("net", "localgroup administrators");
        if (!string.IsNullOrWhiteSpace(users))
        {
            findings.Add(new Finding
            {
                Category = FindingCategory.Identity,
                Severity = Severity.Info,
                Title = "Local user accounts",
                Detail = WinHelpers.Truncate(users, 2000),
                Remediation = "Disable unused local accounts. Rename the built-in Administrator if it is enabled.",
                Host = "this-pc"
            });
        }

        if (!string.IsNullOrWhiteSpace(admins))
        {
            var extra = admins.Split('\n')
                .Select(l => l.Trim())
                .Where(l => l.Length > 0 && !l.StartsWith('-') && !l.Contains("completed", StringComparison.OrdinalIgnoreCase)
                            && !l.StartsWith("Alias", StringComparison.OrdinalIgnoreCase)
                            && !l.StartsWith("Comment", StringComparison.OrdinalIgnoreCase)
                            && !l.StartsWith("Members", StringComparison.OrdinalIgnoreCase)
                            && !l.StartsWith("The command", StringComparison.OrdinalIgnoreCase))
                .ToList();
            findings.Add(new Finding
            {
                Category = FindingCategory.Identity,
                Severity = extra.Count > 3 ? Severity.Medium : Severity.Info,
                Title = $"Local Administrators group has {extra.Count} listed member(s)",
                Detail = string.Join("\n", extra),
                Remediation = "Keep the admin group tiny. Unexpected members are a persistence technique.",
                Host = "this-pc"
            });
        }

        var guest = WinHelpers.Run("net", "user Guest");
        if (!string.IsNullOrEmpty(guest) && guest.Contains("Account active", StringComparison.OrdinalIgnoreCase)
            && guest.Contains("Yes", StringComparison.OrdinalIgnoreCase)
            && !guest.Contains("Account active               No", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new Finding
            {
                Category = FindingCategory.Identity,
                Severity = Severity.High,
                Title = "Guest account is active",
                Detail = WinHelpers.Truncate(guest, 800),
                Remediation = "Disable the Guest account: net user Guest /active:no",
                Host = "this-pc"
            });
        }

        var cached = WinHelpers.Run("cmdkey", "/list");
        if (!string.IsNullOrWhiteSpace(cached) && cached.Contains("Target:", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new Finding
            {
                Category = FindingCategory.Identity,
                Severity = Severity.Medium,
                Title = "Saved credentials are present in Windows Credential Manager",
                Detail = WinHelpers.Truncate(cached, 1500),
                Remediation = "Remove leftover entries with cmdkey /delete. Saved RDP/SMB creds are stolen by infostealers.",
                Host = "this-pc"
            });
        }

        if (!WinHelpers.IsAdministrator)
        {
            findings.Add(new Finding
            {
                Category = FindingCategory.Identity,
                Severity = Severity.Info,
                Title = "Sentinel is not running elevated",
                Detail = "Some services, Security event logs, and Defender policy keys are only visible to Administrators.",
                Remediation = "Right-click Sentinel.exe → Run as administrator for a deeper pass."
            });
        }

        return findings;
    }
}
