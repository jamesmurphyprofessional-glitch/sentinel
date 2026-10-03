using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32;

namespace Sentinel.Services;

internal static class WinHelpers
{
    public static bool IsWindows => OperatingSystem.IsWindows();

    public static bool IsAdministrator
    {
        get
        {
            if (!IsWindows) return false;
            try
            {
                using var id = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }

    public static string? Run(string file, string args, int timeoutMs = 15000)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                Arguments = args,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            using var p = Process.Start(psi);
            if (p == null) return null;
            var output = p.StandardOutput.ReadToEnd();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { /* ignore */ }
                return null;
            }
            return output;
        }
        catch
        {
            return null;
        }
    }

    public static object? GetValue(RegistryHive hive, string key, string name)
    {
        if (!IsWindows) return null;
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var opened = baseKey.OpenSubKey(key);
            return opened?.GetValue(name);
        }
        catch
        {
            return null;
        }
    }

    public static string? GetString(RegistryHive hive, string key, string name) =>
        GetValue(hive, key, name)?.ToString();

    public static int? GetInt(RegistryHive hive, string key, string name)
    {
        var v = GetValue(hive, key, name);
        return v switch
        {
            int i => i,
            long l => (int)l,
            string s when int.TryParse(s, out var i) => i,
            _ => null
        };
    }

    public static string Expand(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        var trimmed = path.Trim().Trim('"');
        // drop arguments after .exe/.dll/.sys
        foreach (var ext in new[] { ".exe", ".dll", ".sys", ".com", ".scr" })
        {
            var idx = trimmed.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
            if (idx > 0)
            {
                trimmed = trimmed[..(idx + ext.Length)];
                break;
            }
        }
        try { return Environment.ExpandEnvironmentVariables(trimmed).Trim('"'); }
        catch { return trimmed; }
    }

    public static bool LooksTemp(string path)
    {
        var p = path.Replace('/', '\\').ToLowerInvariant();
        return p.Contains("\\temp\\") || p.Contains("\\tmp\\") || p.Contains("\\appdata\\local\\temp")
               || p.Contains("\\users\\public\\") || p.Contains("\\programdata\\temp");
    }

    public static bool LooksUserWritable(string path)
    {
        var p = path.Replace('/', '\\').ToLowerInvariant();
        return p.Contains("\\appdata\\") || p.Contains("\\users\\") && !p.Contains("\\windows\\")
               || p.Contains("\\downloads\\") || p.Contains("\\desktop\\") || p.Contains("\\documents\\");
    }

    public static string Truncate(string? text, int max = 4000)
    {
        if (string.IsNullOrEmpty(text)) return "";
        return text.Length <= max ? text : text[..max] + "…";
    }

    public static string JoinLines(params string?[] lines) =>
        string.Join(Environment.NewLine, lines.Where(l => !string.IsNullOrWhiteSpace(l))!);
}
