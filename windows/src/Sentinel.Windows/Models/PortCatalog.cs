using System.Collections.Generic;
using System.Linq;

namespace Sentinel.Models;

public static class PortCatalog
{
    public static readonly Dictionary<int, PortProfile> Profiles = Build();

    public static readonly int[] DiscoveryPorts = { 22, 80, 135, 139, 443, 445, 3389, 5357, 5985, 8080 };

    public static int[] DefaultScanPorts => Profiles.Keys.Concat(new[] { 21, 22, 23, 80, 135, 139, 443, 445, 3389, 5985 }).Distinct().OrderBy(p => p).ToArray();

    public static PortProfile Profile(int port) =>
        Profiles.TryGetValue(port, out var p)
            ? p
            : new PortProfile
            {
                Service = "unknown",
                Risk = Severity.Low,
                Reason = "Unlisted port. Identify the process and close it if it is not required."
            };

    private static Dictionary<int, PortProfile> Build()
    {
        var map = new Dictionary<int, PortProfile>();
        void Add(int[] ports, string service, Severity risk, string reason, bool http = false)
        {
            foreach (var port in ports)
            {
                map[port] = new PortProfile { Service = service, Risk = risk, Reason = reason, HttpHead = http };
            }
        }

        Add(new[] { 21 }, "FTP", Severity.High, "FTP is unencrypted and frequently targeted for credential theft.");
        Add(new[] { 22 }, "SSH", Severity.Medium, "Remote shell. Risky if exposed with password authentication.");
        Add(new[] { 23, 2323 }, "Telnet", Severity.Critical, "Telnet is unencrypted remote access and should never be reachable.");
        Add(new[] { 135 }, "RPC Endpoint Mapper", Severity.High, "Windows RPC mapper is a classic worm and lateral-movement surface.");
        Add(new[] { 139 }, "NetBIOS", Severity.High, "Legacy Windows file/printer sharing transport.");
        Add(new[] { 445 }, "SMB", Severity.High, "File sharing / SMB is a classic worm and ransomware path.");
        Add(new[] { 3389 }, "RDP", Severity.Critical, "Remote Desktop is a primary ransomware and brute-force target.");
        Add(new[] { 5985, 5986 }, "WinRM", Severity.Critical, "Windows remote management — full administrative remote execution if reachable.");
        Add(new[] { 47001 }, "WinRM HTTP alt", Severity.High, "Alternate WinRM listener.");
        Add(new[] { 5900, 5901, 5902 }, "VNC", Severity.High, "Graphical remote desktop, often weakly authenticated.");
        Add(new[] { 4899 }, "Radmin", Severity.High, "Third-party remote-control software.");
        Add(new[] { 5938 }, "TeamViewer", Severity.Medium, "Remote-control software. Confirm you expect it.");
        Add(new[] { 7070 }, "AnyDesk / alt", Severity.Medium, "Common remote-support port.");
        Add(new[] { 2375 }, "Docker API (plaintext)", Severity.Critical, "Unauthenticated Docker API can give SYSTEM on the host.");
        Add(new[] { 2376 }, "Docker API (TLS)", Severity.Medium, "Docker API should not be reachable from untrusted hosts.");
        Add(new[] { 6443, 10250 }, "Kubernetes", Severity.High, "Kubernetes API / kubelet exposure can lead to cluster takeover.");
        Add(new[] { 2379, 2380 }, "etcd", Severity.Critical, "etcd often holds cluster secrets.");
        Add(new[] { 80, 8080, 8000, 8008, 8888, 5000, 3000 }, "HTTP", Severity.Medium, "Unencrypted web / admin UI.", true);
        Add(new[] { 443, 8443, 4443 }, "HTTPS", Severity.Low, "Encrypted web. Still review for exposed admin panels.", true);
        Add(new[] { 81, 82, 8082 }, "IoT / camera HTTP", Severity.High, "Consumer cameras and IoT admin pages are a common LAN foothold.", true);
        Add(new[] { 3306 }, "MySQL / MariaDB", Severity.High, "Database should not be reachable beyond the app host.");
        Add(new[] { 5432 }, "PostgreSQL", Severity.High, "Database should not be reachable beyond the app host.");
        Add(new[] { 1433, 1434 }, "MSSQL", Severity.High, "SQL Server is a frequent ransomware staging target.");
        Add(new[] { 27017 }, "MongoDB", Severity.Critical, "Historically left unauthenticated; ransomware and data theft target.");
        Add(new[] { 6379 }, "Redis", Severity.Critical, "Often unauthenticated and can lead to remote code execution.");
        Add(new[] { 11211 }, "Memcached", Severity.High, "Unauthenticated memory cache.");
        Add(new[] { 9200, 9300 }, "Elasticsearch", Severity.High, "Search cluster APIs frequently exposed without auth.");
        Add(new[] { 5601 }, "Kibana", Severity.Medium, "Ops dashboard.");
        Add(new[] { 5672 }, "AMQP / RabbitMQ", Severity.High, "Message broker; default guest/guest is well known.");
        Add(new[] { 15672 }, "RabbitMQ management", Severity.High, "Broker admin UI.");
        Add(new[] { 1883 }, "MQTT", Severity.Medium, "IoT message bus; often no authentication on LAN.");
        Add(new[] { 161, 162 }, "SNMP", Severity.High, "SNMP can leak configuration; community strings are often public/private.");
        Add(new[] { 1900 }, "UPnP / SSDP", Severity.Medium, "UPnP can punch WAN holes.");
        Add(new[] { 5357 }, "WSDAPI / Network Discovery", Severity.Low, "Windows network discovery.");
        Add(new[] { 88 }, "Kerberos", Severity.Medium, "Authentication service; useful when mapping a domain.");
        Add(new[] { 389 }, "LDAP", Severity.Medium, "Directory service may leak users and computers.");
        Add(new[] { 636 }, "LDAPS", Severity.Low, "Encrypted directory service.");
        Add(new[] { 3268, 3269 }, "Global Catalog", Severity.Medium, "AD global catalog.");
        Add(new[] { 53 }, "DNS", Severity.Medium, "Open resolvers can be abused; also maps internal names.");
        Add(new[] { 25, 587, 465 }, "SMTP", Severity.Medium, "Mail transfer; open relays are abused for spam.");
        Add(new[] { 110, 995 }, "POP3", Severity.Low, "Mail retrieval.");
        Add(new[] { 143, 993 }, "IMAP", Severity.Low, "Mail retrieval.");
        Add(new[] { 1723 }, "PPTP", Severity.High, "Broken VPN protocol.");
        Add(new[] { 1194, 51820 }, "OpenVPN / WireGuard", Severity.Info, "VPN endpoint. Unexpected if you do not run a VPN.");
        Add(new[] { 500, 4500 }, "IPsec / IKE", Severity.Info, "VPN endpoint.");
        Add(new[] { 16992, 16993 }, "Intel AMT", Severity.Critical, "Out-of-band management can outlive the OS.");
        Add(new[] { 623 }, "IPMI", Severity.Critical, "BMC / IPMI; default passwords are common.");
        Add(new[] { 10000 }, "Webmin / NDMP", Severity.High, "Webmin and backup services are frequently targeted.");
        Add(new[] { 8161 }, "ActiveMQ", Severity.High, "Message-broker web console.");
        Add(new[] { 8500 }, "Consul", Severity.High, "Service discovery; can expose cluster membership and KV secrets.");
        Add(new[] { 8200 }, "Vault", Severity.Medium, "Secrets manager. Should not be open to the whole LAN.");
        Add(new[] { 7001 }, "WebLogic", Severity.High, "Enterprise app server admin.");
        Add(new[] { 4848 }, "GlassFish admin", Severity.High, "App-server admin console.");
        Add(new[] { 554, 8554 }, "RTSP", Severity.Medium, "Camera streams are frequently unauthenticated.");
        Add(new[] { 5060, 5061 }, "SIP", Severity.Medium, "VoIP signaling; often abused for toll fraud.");
        Add(new[] { 2049, 111 }, "NFS / rpcbind", Severity.High, "NFS exports can share files without strong auth.");
        Add(new[] { 873 }, "rsync", Severity.High, "rsync modules are often unauthenticated.");
        Add(new[] { 2222 }, "SSH alt", Severity.Medium, "Non-standard SSH port still provides remote shell access.");
        Add(new[] { 5353 }, "mDNS", Severity.Info, "Multicast DNS advertises devices on the LAN.");
        return map;
    }
}
