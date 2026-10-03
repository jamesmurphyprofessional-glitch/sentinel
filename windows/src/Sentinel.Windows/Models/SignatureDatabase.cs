using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Models;

public sealed class SignatureDatabase
{
    public HashSet<string> HashesSha256 { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Filenames { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> PathFragments { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Labels { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Sources { get; set; } = new();
    public DateTime? LastUpdated { get; set; }

    public SignatureStats Stats => new()
    {
        HashCount = HashesSha256.Count,
        FilenameCount = Filenames.Count,
        PathCount = PathFragments.Count,
        LastUpdated = LastUpdated,
        Sources = Sources.ToList()
    };

    public void Merge(SignatureDatabase other)
    {
        foreach (var h in other.HashesSha256) HashesSha256.Add(h.ToLowerInvariant());
        foreach (var f in other.Filenames) Filenames.Add(f);
        foreach (var p in other.PathFragments) PathFragments.Add(p);
        foreach (var l in other.Labels) Labels.Add(l);
        foreach (var s in other.Sources)
        {
            if (!Sources.Contains(s)) Sources.Add(s);
        }
        LastUpdated = DateTime.Now;
    }

    public List<string> Match(string path, string? sha256, string? label)
    {
        var hits = new List<string>();
        var name = Path.GetFileName(path);
        var lower = path.Replace('/', '\\').ToLowerInvariant();

        if (!string.IsNullOrEmpty(sha256) && HashesSha256.Contains(sha256))
            hits.Add("SHA-256 listed in malware hash feed");
        if (!string.IsNullOrEmpty(name) && Filenames.Contains(name))
            hits.Add($"filename matches known malware / PUP indicator: {name}");
        foreach (var fragment in PathFragments.Where(f => f.Length > 2 && lower.Contains(f.ToLowerInvariant())))
            hits.Add($"path contains known indicator \"{fragment}\"");
        if (!string.IsNullOrEmpty(label) && Labels.Contains(label))
            hits.Add($"persistence label {label} matches a known-bad indicator");
        return hits;
    }

    public static string StoreDirectory
    {
        get
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Sentinel");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    public static string StorePath => Path.Combine(StoreDirectory, "signatures.json");

    public static SignatureDatabase Load()
    {
        var db = LoadSeed();
        try
        {
            if (File.Exists(StorePath))
            {
                var stored = JsonSerializer.Deserialize<SignatureDto>(File.ReadAllText(StorePath), Json);
                if (stored != null) db.Merge(FromDto(stored));
            }
        }
        catch
        {
            // keep seed
        }
        return db;
    }

    public void Save()
    {
        var dto = new SignatureDto
        {
            HashesSha256 = HashesSha256.ToList(),
            Filenames = Filenames.ToList(),
            PathFragments = PathFragments.ToList(),
            Labels = Labels.ToList(),
            Sources = Sources,
            LastUpdated = LastUpdated
        };
        File.WriteAllText(StorePath, JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true }));
    }

    public static SignatureDatabase LoadSeed()
    {
        try
        {
            var asm = Assembly.GetExecutingAssembly();
            var name = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("seed_signatures.json", StringComparison.OrdinalIgnoreCase));
            if (name != null)
            {
                using var stream = asm.GetManifestResourceStream(name);
                if (stream != null)
                {
                    using var reader = new StreamReader(stream);
                    var dto = JsonSerializer.Deserialize<SignatureDto>(reader.ReadToEnd(), Json);
                    if (dto != null) return FromDto(dto);
                }
            }
        }
        catch
        {
            // ignore
        }
        return new SignatureDatabase();
    }

    public static string? Sha256File(string path, long maxBytes = 64L * 1024 * 1024)
    {
        try
        {
            using var fs = File.OpenRead(path);
            using var sha = SHA256.Create();
            var remaining = maxBytes;
            var buffer = new byte[1024 * 1024];
            while (remaining > 0)
            {
                var toRead = (int)Math.Min(remaining, buffer.Length);
                var n = fs.Read(buffer, 0, toRead);
                if (n <= 0) break;
                sha.TransformBlock(buffer, 0, n, null, 0);
                remaining -= n;
                if (n < toRead) break;
            }
            sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
            return Convert.ToHexString(sha.Hash!).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static SignatureDatabase FromDto(SignatureDto dto) => new()
    {
        HashesSha256 = new HashSet<string>(dto.HashesSha256.Select(s => s.ToLowerInvariant()), StringComparer.OrdinalIgnoreCase),
        Filenames = new HashSet<string>(dto.Filenames, StringComparer.OrdinalIgnoreCase),
        PathFragments = new HashSet<string>(dto.PathFragments, StringComparer.OrdinalIgnoreCase),
        Labels = new HashSet<string>(dto.Labels, StringComparer.OrdinalIgnoreCase),
        Sources = dto.Sources ?? new List<string>(),
        LastUpdated = dto.LastUpdated
    };

    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip
    };

    private sealed class SignatureDto
    {
        [JsonPropertyName("hashesSHA256")] public List<string> HashesSha256 { get; set; } = new();
        [JsonPropertyName("hashesSha256")] public List<string> HashesSha256Alt { set { if (value is { Count: > 0 }) HashesSha256 = value; } }
        public List<string> Filenames { get; set; } = new();
        public List<string> PathFragments { get; set; } = new();
        public List<string> Labels { get; set; } = new();
        public List<string> LaunchLabels { set { if (value is { Count: > 0 }) Labels = value; } }
        public List<string> Sources { get; set; } = new();
        public DateTime? LastUpdated { get; set; }
    }
}
