using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using Sentinel.Models;

namespace Sentinel.Services;

public static class EventLogScanner
{
    public static List<Finding> Run(Action<ScanProgress>? progress = null)
    {
        progress?.Invoke(new ScanProgress { Phase = "Event log", Completed = 0, Total = 1, StatusLine = "Reading recent Security / System events" });
        var findings = new List<Finding>();
        if (!WinHelpers.IsWindows)
        {
            findings.Add(new Finding
            {
                Category = FindingCategory.Events,
                Severity = Severity.Info,
                Title = "Event log triage is Windows-only",
                Detail = "Security 4625/4624, service installs, and PowerShell events are queried on Windows.",
                Remediation = "Run the Windows build on the target PC."
            });
            return findings;
        }

        findings.AddRange(Query("Security", "*[System[(EventID=4625)]]", TimeSpan.FromHours(24),
            "failed logon(s) in the last 24 hours",
            "Repeated 4625 events mean password guessing. Enable lockout and do not expose RDP.",
            Severity.Medium, FindingCategory.Events, 8, Severity.High));

        findings.AddRange(Query("Security", "*[System[(EventID=4624)]] and *[EventData[Data[@Name='LogonType']='10']]",
            TimeSpan.FromHours(24),
            "successful RDP logon(s) in the last 24 hours",
            "Confirm each Type-10 logon was you. Unexpected RDP success is a compromise signal.",
            Severity.Medium, FindingCategory.RemoteAccess, 1, Severity.Medium));

        findings.AddRange(Query("System", "*[System[(EventID=7045)]]", TimeSpan.FromDays(7),
            "new service install(s) in the last 7 days",
            "Event 7045 is how many droppers persist. Review ImagePath for user-writable locations.",
            Severity.Medium, FindingCategory.Persistence, 1, Severity.Medium));

        findings.AddRange(Query("Microsoft-Windows-PowerShell/Operational", "*[System[(EventID=4104)]]",
            TimeSpan.FromHours(24),
            "PowerShell script-block event(s) in the last 24 hours",
            "Useful for hunting encoded IEX. Enable Script Block Logging if this query failed.",
            Severity.Info, FindingCategory.Events, 200, Severity.Low));

        return findings;
    }

    private static IEnumerable<Finding> Query(
        string log, string xpath, TimeSpan window, string label, string rem,
        Severity baseSeverity, FindingCategory category, int escalateAt, Severity escalated)
    {
        var list = new List<Finding>();
        try
        {
            var since = DateTime.Now.Subtract(window);
            var query = new EventLogQuery(log, PathType.LogName, xpath)
            {
                ReverseDirection = true
            };
            using var reader = new EventLogReader(query);
            var n = 0;
            var samples = new List<string>();
            for (var rec = reader.ReadEvent(); rec != null && n < 500; rec = reader.ReadEvent())
            {
                using (rec)
                {
                    if (rec.TimeCreated < since) break;
                    n++;
                    if (samples.Count < 8)
                        samples.Add($"{rec.TimeCreated:u} id={rec.Id} {WinHelpers.Truncate(rec.FormatDescription(), 160)}");
                }
            }

            if (n == 0)
            {
                list.Add(new Finding
                {
                    Category = category,
                    Severity = Severity.Info,
                    Title = $"No {label}",
                    Detail = $"Queried {log}.",
                    Remediation = rem,
                    Host = "this-pc"
                });
            }
            else
            {
                list.Add(new Finding
                {
                    Category = category,
                    Severity = n >= escalateAt ? escalated : baseSeverity,
                    Title = $"{n} {label}",
                    Detail = string.Join("\n", samples),
                    Remediation = rem,
                    Host = "this-pc"
                });
            }
        }
        catch (Exception ex)
        {
            list.Add(new Finding
            {
                Category = FindingCategory.Events,
                Severity = Severity.Info,
                Title = $"Could not read {log}",
                Detail = ex.Message,
                Remediation = "Run as Administrator and ensure the log exists. Security log requires elevation.",
                Host = "this-pc"
            });
        }
        return list;
    }
}
