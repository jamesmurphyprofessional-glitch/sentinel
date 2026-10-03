using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using Sentinel.Models;

namespace Sentinel.Services;

public static class ReportWriter
{
    public static string Markdown(IEnumerable<Finding> findings, NetworkSnapshot? net, SignatureStats stats)
    {
        var list = findings.ToList();
        var sb = new StringBuilder();
        sb.AppendLine("# Sentinel 2.0 assessment");
        sb.AppendLine();
        sb.AppendLine($"Generated {DateTime.Now:u}");
        if (net != null)
            sb.AppendLine($"Network: `{net.InterfaceName}` `{net.IpAddress}/{net.Cidr}` gateway `{net.Gateway}`");
        sb.AppendLine($"Signatures: {stats.HashCount} hashes, {stats.FilenameCount} names, updated {stats.LastUpdated?.ToString("u") ?? "seed only"}");
        sb.AppendLine();
        sb.AppendLine("| Severity | Count |");
        sb.AppendLine("|---|---|");
        foreach (var sev in Enum.GetValues<Severity>().Reverse())
            sb.AppendLine($"| {sev} | {list.Count(f => f.Severity == sev)} |");
        sb.AppendLine();
        foreach (var f in list.OrderByDescending(f => f.Severity).ThenBy(f => f.CategoryLabel))
        {
            sb.AppendLine($"## [{f.SeverityLabel}] {f.Title}");
            sb.AppendLine();
            sb.AppendLine($"- Category: {f.CategoryLabel}");
            if (!string.IsNullOrEmpty(f.Host)) sb.AppendLine($"- Host: `{f.Host}`");
            sb.AppendLine();
            sb.AppendLine(f.Detail);
            sb.AppendLine();
            sb.AppendLine($"**Remediation:** {f.Remediation}");
            if (!string.IsNullOrEmpty(f.Evidence))
            {
                sb.AppendLine();
                sb.AppendLine("```");
                sb.AppendLine(f.Evidence);
                sb.AppendLine("```");
            }
            sb.AppendLine();
        }
        sb.AppendLine("---");
        sb.AppendLine("Defensive identification only. Sentinel does not exploit services, try passwords, or send attack payloads.");
        return sb.ToString();
    }

    public static string Html(IEnumerable<Finding> findings, NetworkSnapshot? net, SignatureStats stats)
    {
        var list = findings.ToList();
        string Esc(string? s) => WebUtility.HtmlEncode(s ?? "");
        var sb = new StringBuilder();
        sb.AppendLine("<!doctype html><meta charset='utf-8'><title>Sentinel 2.0 report</title>");
        sb.AppendLine("<style>body{font-family:Segoe UI,sans-serif;background:#0b1014;color:#e8eef4;margin:32px;max-width:1100px} h1{color:#3ddc97} .c{color:#ff5d5d}.h{color:#f5a524}.m{color:#5bb5f5} .i{color:#8ea0ad} pre{background:#141b22;padding:12px;overflow:auto;border:1px solid #2a3440} .card{border:1px solid #2a3440;background:#141b22;padding:14px;margin:12px 0;border-radius:8px}</style>");
        sb.AppendLine("<h1>Sentinel 2.0 assessment</h1>");
        sb.AppendLine($"<p>{Esc(DateTime.Now.ToString("u"))}</p>");
        if (net != null) sb.AppendLine($"<p>{Esc(net.InterfaceName)} {Esc(net.IpAddress)}/{net.Cidr}</p>");
        sb.AppendLine($"<p>Signatures: {stats.HashCount} hashes · {stats.FilenameCount} names</p>");
        foreach (var f in list.OrderByDescending(f => f.Severity))
        {
            var cls = f.Severity >= Severity.Critical ? "c" : f.Severity >= Severity.High ? "h" : f.Severity >= Severity.Medium ? "m" : "i";
            sb.AppendLine($"<div class='card'><div class='{cls}'><b>{Esc(f.SeverityLabel)}</b> · {Esc(f.CategoryLabel)}</div><h3>{Esc(f.Title)}</h3><pre>{Esc(f.Detail)}</pre><p>{Esc(f.Remediation)}</p></div>");
        }
        return sb.ToString();
    }
}
