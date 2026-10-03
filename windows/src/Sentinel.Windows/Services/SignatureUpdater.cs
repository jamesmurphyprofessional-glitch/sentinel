using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Sentinel.Models;

namespace Sentinel.Services;

public static class SignatureUpdater
{
    private static readonly HttpClient Http = new()
    {
        Timeout = TimeSpan.FromSeconds(45)
    };

    static SignatureUpdater()
    {
        Http.DefaultRequestHeaders.UserAgent.ParseAdd("Sentinel/2.0 (defensive IOC refresh; +https://abuse.ch)");
    }

    public static async Task<(SignatureDatabase Db, List<UpdateResult> Results)> UpdateAsync(SignatureDatabase existing)
    {
        var db = existing;
        var results = new List<UpdateResult>();

        results.Add(await PullText("MalwareBazaar recent SHA-256",
            "https://bazaar.abuse.ch/export/txt/sha256/recent/",
            line => IsSha256(line) ? line.Trim().ToLowerInvariant() : null,
            hashes => db.HashesSha256.UnionWith(hashes)));

        foreach (var tag in new[] { "Win32", "Windows", "exe" })
        {
            results.Add(await PullBazaarTag(tag, db));
        }

        results.Add(await PullThreatFox(db));
        results.Add(await PullUrlhaus(db));

        if (!db.Sources.Contains("public feeds (abuse.ch)"))
            db.Sources.Add("public feeds (abuse.ch)");
        db.LastUpdated = DateTime.Now;
        try { db.Save(); } catch { /* ignore */ }
        return (db, results);
    }

    private static async Task<UpdateResult> PullText(string name, string url, Func<string, string?> pick, Action<HashSet<string>> apply)
    {
        try
        {
            var text = await Http.GetStringAsync(url).ConfigureAwait(false);
            var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var line in text.Split('\n'))
            {
                var v = pick(line);
                if (v != null) set.Add(v);
            }
            apply(set);
            return new UpdateResult { Name = name, AddedHashes = set.Count, Note = $"parsed {set.Count} indicators", Succeeded = true };
        }
        catch (Exception ex)
        {
            return new UpdateResult { Name = name, Note = ex.Message, Succeeded = false };
        }
    }

    private static async Task<UpdateResult> PullBazaarTag(string tag, SignatureDatabase db)
    {
        try
        {
            using var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["query"] = "get_taginfo",
                ["tag"] = tag
            });
            using var resp = await Http.PostAsync("https://mb-api.abuse.ch/api/v1/", content).ConfigureAwait(false);
            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            var added = 0;
            foreach (Match m in Regex.Matches(json, "\"sha256_hash\"\\s*:\\s*\"([a-fA-F0-9]{64})\""))
            {
                if (db.HashesSha256.Add(m.Groups[1].Value.ToLowerInvariant())) added++;
            }
            return new UpdateResult { Name = $"MalwareBazaar tag {tag}", AddedHashes = added, Note = $"added {added}", Succeeded = true };
        }
        catch (Exception ex)
        {
            return new UpdateResult { Name = $"MalwareBazaar tag {tag}", Note = ex.Message, Succeeded = false };
        }
    }

    private static async Task<UpdateResult> PullThreatFox(SignatureDatabase db)
    {
        try
        {
            using var content = new StringContent("{\"query\":\"get_iocs\",\"days\":7}", System.Text.Encoding.UTF8, "application/json");
            using var resp = await Http.PostAsync("https://threatfox-api.abuse.ch/api/v1/", content).ConfigureAwait(false);
            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            var added = 0;
            foreach (Match m in Regex.Matches(json, "\"ioc\"\\s*:\\s*\"([a-fA-F0-9]{64})\""))
            {
                if (db.HashesSha256.Add(m.Groups[1].Value.ToLowerInvariant())) added++;
            }
            return new UpdateResult { Name = "ThreatFox SHA-256", AddedHashes = added, Note = $"added {added}", Succeeded = true };
        }
        catch (Exception ex)
        {
            return new UpdateResult { Name = "ThreatFox SHA-256", Note = ex.Message, Succeeded = false };
        }
    }

    private static async Task<UpdateResult> PullUrlhaus(SignatureDatabase db)
    {
        try
        {
            var text = await Http.GetStringAsync("https://urlhaus.abuse.ch/downloads/csv_recent/").ConfigureAwait(false);
            var added = 0;
            foreach (var line in text.Split('\n'))
            {
                if (line.StartsWith('#') || string.IsNullOrWhiteSpace(line)) continue;
                var parts = line.Split(',');
                foreach (var part in parts)
                {
                    var token = part.Trim().Trim('"');
                    if (token.Contains('.') && token.Length is > 4 and < 80
                        && (token.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                            || token.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                            || token.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase)
                            || token.EndsWith(".js", StringComparison.OrdinalIgnoreCase)))
                    {
                        if (db.Filenames.Add(System.IO.Path.GetFileName(token))) added++;
                    }
                }
            }
            return new UpdateResult { Name = "URLhaus payload names", AddedHashes = added, Note = $"added {added} filenames", Succeeded = true };
        }
        catch (Exception ex)
        {
            return new UpdateResult { Name = "URLhaus payload names", Note = ex.Message, Succeeded = false };
        }
    }

    private static bool IsSha256(string line)
    {
        var t = line.Trim();
        if (t.StartsWith('#') || t.Length != 64) return false;
        return t.All(Uri.IsHexDigit);
    }
}
