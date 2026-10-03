using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Sentinel.Models;

namespace Sentinel.Services;

public static class NetworkScanner
{
    public static async Task<List<string>> DiscoverHostsAsync(
        NetworkSnapshot snapshot,
        Action<ScanProgress> progress,
        CancellationToken ct)
    {
        var live = new ConcurrentDictionary<string, byte>();
        live[snapshot.IpAddress] = 0;
        if (!string.IsNullOrEmpty(snapshot.Gateway)) live[snapshot.Gateway] = 0;

        var targets = snapshot.Hosts;
        var completed = 0;
        var total = targets.Count;
        using var gate = new SemaphoreSlim(96);

        var tasks = targets.Select(async ip =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                foreach (var port in PortCatalog.DiscoveryPorts)
                {
                    if (await IsOpen(ip, port, 500, ct).ConfigureAwait(false))
                    {
                        live[ip] = 0;
                        break;
                    }
                }
            }
            finally
            {
                gate.Release();
                var done = Interlocked.Increment(ref completed);
                if (done == 1 || done % 16 == 0 || done == total)
                {
                    progress(new ScanProgress
                    {
                        Phase = "Host discovery",
                        Completed = done,
                        Total = total,
                        StatusLine = $"Probing {done}/{total} addresses on {snapshot.IpAddress}/{snapshot.Cidr}"
                    });
                }
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return live.Keys.OrderBy(NetworkInfoService.ToUInt).ToList();
    }

    public static async Task<List<DiscoveredHost>> ScanPortsAsync(
        IReadOnlyList<string> hosts,
        IReadOnlyList<int> ports,
        string localIp,
        Action<ScanProgress> progress,
        CancellationToken ct)
    {
        var hits = new ConcurrentBag<OpenPort>();
        var jobs = hosts.SelectMany(h => ports.Select(p => (h, p))).ToList();
        var completed = 0;
        var total = jobs.Count;
        using var gate = new SemaphoreSlim(128);

        var tasks = jobs.Select(async job =>
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (!await IsOpen(job.h, job.p, 600, ct).ConfigureAwait(false)) return;
                var profile = PortCatalog.Profile(job.p);
                string? banner = null;
                try
                {
                    banner = profile.HttpHead
                        ? await HttpHead(job.h, job.p, ct).ConfigureAwait(false)
                        : await ReadBanner(job.h, job.p, ct).ConfigureAwait(false);
                }
                catch { /* identification only */ }

                hits.Add(new OpenPort
                {
                    Host = job.h,
                    Port = job.p,
                    Service = profile.Service,
                    Risk = profile.Risk,
                    Banner = banner,
                    Reason = profile.Reason
                });
            }
            finally
            {
                gate.Release();
                var done = Interlocked.Increment(ref completed);
                if (done == 1 || done % 64 == 0 || done == total)
                {
                    progress(new ScanProgress
                    {
                        Phase = "Port identification",
                        Completed = done,
                        Total = total,
                        StatusLine = $"Identifying services {done}/{total}"
                    });
                }
            }
        });

        await Task.WhenAll(tasks).ConfigureAwait(false);

        return hosts.Select(ip =>
        {
            string? name = null;
            try { name = Dns.GetHostEntry(ip).HostName; } catch { /* ignore */ }
            return new DiscoveredHost
            {
                Ip = ip,
                Hostname = name,
                IsLocalMachine = ip == localIp,
                Ports = hits.Where(h => h.Host == ip).OrderBy(h => h.Port).ToList()
            };
        }).ToList();
    }

    public static List<Finding> ToFindings(IEnumerable<DiscoveredHost> hosts, NetworkSnapshot snapshot)
    {
        var findings = new List<Finding>
        {
            new()
            {
                Category = FindingCategory.Network,
                Severity = Severity.Info,
                Title = $"Active interface {snapshot.InterfaceName} {snapshot.IpAddress}/{snapshot.Cidr}",
                Detail = $"Gateway {snapshot.Gateway ?? "unknown"}. Broadcast {snapshot.Broadcast}.",
                Remediation = "Confirm this is a network you own or have permission to assess.",
                Host = snapshot.IpAddress
            }
        };

        foreach (var host in hosts)
        {
            var exposed = host.Ports.Where(p => p.Risk >= Severity.High).ToList();
            if (host.Ports.Count == 0)
            {
                findings.Add(new Finding
                {
                    Category = FindingCategory.Network,
                    Severity = Severity.Info,
                    Title = $"{host.Ip} responded but no catalog ports were open",
                    Detail = host.Hostname ?? "",
                    Remediation = "Host is alive. No high-interest ports from the catalog were reachable.",
                    Host = host.Ip
                });
                continue;
            }

            findings.Add(new Finding
            {
                Category = FindingCategory.Network,
                Severity = exposed.Count == 0 ? Severity.Low : exposed.Max(p => p.Risk),
                Title = $"{host.Ip}{(host.IsLocalMachine ? " (this PC)" : "")} — {host.Ports.Count} open catalog port(s)",
                Detail = string.Join("\n", host.Ports.Select(p => $"{p.Port}/{p.Service} [{p.Risk}] {(p.Banner ?? "")}".Trim())),
                Remediation = "Close unused services, restrict by firewall, and require strong auth on anything that must stay open.",
                Host = host.Ip,
                Evidence = host.Hostname
            });

            foreach (var port in host.Ports.Where(p => p.Risk >= Severity.High))
            {
                findings.Add(new Finding
                {
                    Category = port.Service is "RDP" or "WinRM" or "SMB" or "Telnet" or "VNC" ? FindingCategory.RemoteAccess : FindingCategory.Network,
                    Severity = port.Risk,
                    Title = $"{host.Ip}:{port.Port} {port.Service} is reachable",
                    Detail = port.Reason + (string.IsNullOrEmpty(port.Banner) ? "" : $"\nBanner: {port.Banner}"),
                    Remediation = "If this service is not required, block it on the host firewall. Never expose RDP/WinRM/SMB to the whole LAN without Network Level Auth and account lockout.",
                    Host = host.Ip,
                    Evidence = $"{host.Ip}:{port.Port} {port.Banner}"
                });
            }
        }

        return findings;
    }

    private static async Task<bool> IsOpen(string host, int port, int timeoutMs, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            return client.Connected;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<string?> ReadBanner(string host, int port, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(700);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            client.ReceiveTimeout = 600;
            var stream = client.GetStream();
            var buf = new byte[256];
            if (stream.DataAvailable)
            {
                var n = await stream.ReadAsync(buf.AsMemory(0, buf.Length), cts.Token).ConfigureAwait(false);
                return Sanitize(Encoding.ASCII.GetString(buf, 0, n));
            }
            await Task.Delay(150, cts.Token).ConfigureAwait(false);
            if (stream.DataAvailable)
            {
                var n = await stream.ReadAsync(buf.AsMemory(0, buf.Length), cts.Token).ConfigureAwait(false);
                return Sanitize(Encoding.ASCII.GetString(buf, 0, n));
            }
        }
        catch { /* identification only */ }
        return null;
    }

    private static async Task<string?> HttpHead(string host, int port, CancellationToken ct)
    {
        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(900);
            await client.ConnectAsync(host, port, cts.Token).ConfigureAwait(false);
            var stream = client.GetStream();
            var req = Encoding.ASCII.GetBytes($"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(req, cts.Token).ConfigureAwait(false);
            var buf = new byte[512];
            var n = await stream.ReadAsync(buf.AsMemory(0, buf.Length), cts.Token).ConfigureAwait(false);
            return Sanitize(Encoding.ASCII.GetString(buf, 0, n));
        }
        catch { return null; }
    }

    private static string Sanitize(string s)
    {
        var cleaned = new string(s.Where(c => !char.IsControl(c) || c is '\n' or '\r' or '\t').ToArray());
        return WinHelpers.Truncate(cleaned.Replace("\r", "").Trim(), 240);
    }
}
