using System;
using System.Collections.Generic;

namespace Sentinel.Models;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum FindingCategory
{
    Network,
    RemoteAccess,
    Listening,
    Hardening,
    Malware,
    Persistence,
    Signature,
    Identity,
    Integrity,
    Events
}

public sealed class Finding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public FindingCategory Category { get; set; }
    public Severity Severity { get; set; }
    public string Title { get; set; } = "";
    public string Detail { get; set; } = "";
    public string Remediation { get; set; } = "";
    public string? Host { get; set; }
    public string? Evidence { get; set; }
    public DateTime ScannedAt { get; set; } = DateTime.Now;

    public string SeverityLabel => Severity.ToString().ToUpperInvariant();
    public string CategoryLabel => Category switch
    {
        FindingCategory.Network => "Network",
        FindingCategory.RemoteAccess => "Remote Access",
        FindingCategory.Listening => "Listening Service",
        FindingCategory.Hardening => "Windows Hardening",
        FindingCategory.Malware => "Malware",
        FindingCategory.Persistence => "Persistence",
        FindingCategory.Signature => "Signatures",
        FindingCategory.Identity => "Accounts",
        FindingCategory.Integrity => "Integrity",
        FindingCategory.Events => "Event Log",
        _ => Category.ToString()
    };
}

public sealed class OpenPort
{
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string Service { get; set; } = "";
    public Severity Risk { get; set; }
    public string? Banner { get; set; }
    public string Reason { get; set; } = "";
}

public sealed class DiscoveredHost
{
    public string Ip { get; set; } = "";
    public string? Hostname { get; set; }
    public List<OpenPort> Ports { get; set; } = new();
    public bool IsLocalMachine { get; set; }
}

public sealed class NetworkSnapshot
{
    public string InterfaceName { get; set; } = "";
    public string IpAddress { get; set; } = "";
    public string Netmask { get; set; } = "";
    public int Cidr { get; set; }
    public string Broadcast { get; set; } = "";
    public string? Gateway { get; set; }
    public List<string> Hosts { get; set; } = new();
}

public sealed class ScanProgress
{
    public string Phase { get; set; } = "";
    public int Completed { get; set; }
    public int Total { get; set; }
    public string StatusLine { get; set; } = "";
    public double Fraction => Total <= 0 ? 0 : Math.Min(1, (double)Completed / Total);
}

public sealed class SignatureStats
{
    public int HashCount { get; set; }
    public int FilenameCount { get; set; }
    public int PathCount { get; set; }
    public DateTime? LastUpdated { get; set; }
    public List<string> Sources { get; set; } = new();
}

public sealed class UpdateResult
{
    public string Name { get; set; } = "";
    public int AddedHashes { get; set; }
    public string Note { get; set; } = "";
    public bool Succeeded { get; set; }
}

public sealed class PortProfile
{
    public string Service { get; set; } = "unknown";
    public Severity Risk { get; set; } = Severity.Low;
    public string Reason { get; set; } = "";
    public bool HttpHead { get; set; }
}
