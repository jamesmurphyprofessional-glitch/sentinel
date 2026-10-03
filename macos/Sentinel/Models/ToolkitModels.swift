import Foundation

enum ToolCategory: String, CaseIterable, Identifiable, Sendable {
    case discovery
    case dns
    case web
    case tls
    case identity
    case services
    case advisory
    case reference

    var id: String { rawValue }

    var label: String {
        switch self {
        case .discovery: return "Discovery"
        case .dns: return "DNS"
        case .web: return "Web"
        case .tls: return "TLS / Certs"
        case .identity: return "Windows / Auth"
        case .services: return "Services"
        case .advisory: return "Advisories"
        case .reference: return "Reference"
        }
    }

    var systemImage: String {
        switch self {
        case .discovery: return "dot.radiowaves.left.and.right"
        case .dns: return "globe"
        case .web: return "safari"
        case .tls: return "lock.shield"
        case .identity: return "person.2"
        case .services: return "externaldrive.connected.to.line.below"
        case .advisory: return "exclamationmark.triangle"
        case .reference: return "book"
        }
    }

    var blurb: String {
        switch self {
        case .discovery: return "Find live hosts and paths on the LAN"
        case .dns: return "Names, zone data, and common hostnames"
        case .web: return "HTTP fingerprint, paths, and headers"
        case .tls: return "Certificates and protocol support"
        case .identity: return "NetBIOS, SMB, LDAP, FTP, SMTP"
        case .services: return "Banners and protocol greetings"
        case .advisory: return "Misconfig and version notes"
        case .reference: return "Lookups that do not touch the network"
        }
    }
}

struct ToolDefinition: Identifiable, Hashable, Sendable {
    let id: String
    let name: String
    let inspiredBy: String
    let category: ToolCategory
    let summary: String
    let needsNetwork: Bool
    let needsPort: Bool
    let defaultPort: UInt16?

    static let catalog: [ToolDefinition] = [
        ToolDefinition(id: "nmap", name: "Official nmap", inspiredBy: "nmap 7.x", category: .discovery, summary: "Real nmap connect-scan: -sT -Pn -sV --script=banner,http-title,ssl-cert. Default ports 80,443.", needsNetwork: true, needsPort: true, defaultPort: 443),
        ToolDefinition(id: "ping", name: "Ping", inspiredBy: "ping / nping", category: .discovery, summary: "ICMP echo, latency, and TTL (nmap -PE).", needsNetwork: true, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "traceroute", name: "Traceroute", inspiredBy: "traceroute / nmap --traceroute", category: .discovery, summary: "ICMP hop path to the target.", needsNetwork: true, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "mtr", name: "MTR lite", inspiredBy: "mtr", category: .discovery, summary: "Traceroute plus a second ping of each hop.", needsNetwork: true, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "arp", name: "ARP table", inspiredBy: "arp-scan / netdiscover", category: .discovery, summary: "Local ARP cache with IEEE OUI vendors.", needsNetwork: false, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "whois", name: "WHOIS", inspiredBy: "whois", category: .discovery, summary: "Public registration / RIR record for an IP or domain.", needsNetwork: true, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "revdns", name: "Reverse DNS", inspiredBy: "dig -x / nmap -R", category: .discovery, summary: "PTR lookup for an address.", needsNetwork: true, needsPort: false, defaultPort: nil),

        ToolDefinition(id: "dns-records", name: "DNS records", inspiredBy: "dig / dnsrecon", category: .dns, summary: "A, AAAA, MX, NS, TXT, SOA, CNAME for a name.", needsNetwork: true, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "dns-axfr", name: "Zone transfer", inspiredBy: "dnsrecon AXFR", category: .dns, summary: "Ask each NS for a full zone transfer. Should fail on a healthy server.", needsNetwork: true, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "dns-srv", name: "SRV records", inspiredBy: "enum4linux / ldap-search", category: .dns, summary: "Common _ldap, _kerberos, _sip, _xmpp SRV lookups.", needsNetwork: true, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "dns-sweep", name: "Hostname sweep", inspiredBy: "fierce / dnsenum", category: .dns, summary: "Small wordlist of common LAN names against the target domain or resolver.", needsNetwork: true, needsPort: false, defaultPort: nil),

        ToolDefinition(id: "httpx", name: "HTTP probe", inspiredBy: "httpx", category: .web, summary: "Status, title, Server, redirects.", needsNetwork: true, needsPort: true, defaultPort: 80),
        ToolDefinition(id: "whatweb", name: "Tech fingerprint", inspiredBy: "whatweb", category: .web, summary: "Headers and body clues for common stacks.", needsNetwork: true, needsPort: true, defaultPort: 80),
        ToolDefinition(id: "headers", name: "Security headers", inspiredBy: "securityheaders.com", category: .web, summary: "HSTS, CSP, X-Frame-Options, Referrer-Policy, and friends.", needsNetwork: true, needsPort: true, defaultPort: 443),
        ToolDefinition(id: "robots", name: "robots / sitemap", inspiredBy: "wget / nmap http-robots.txt", category: .web, summary: "Fetch robots.txt and sitemap.xml.", needsNetwork: true, needsPort: true, defaultPort: 80),
        ToolDefinition(id: "gobuster", name: "Common paths", inspiredBy: "gobuster / feroxbuster / dirb", category: .web, summary: "HEAD a short list of admin, backup, and API paths. No brute-force wordlist.", needsNetwork: true, needsPort: true, defaultPort: 80),
        ToolDefinition(id: "nikto", name: "Nikto lite", inspiredBy: "nikto", category: .web, summary: "Checks for phpinfo, .git, .env, server-status, and similar exposures.", needsNetwork: true, needsPort: true, defaultPort: 80),
        ToolDefinition(id: "waf", name: "WAF detect", inspiredBy: "wafw00f", category: .web, summary: "Identify Cloudflare, Akamai, AWS WAF, Sucuri from headers.", needsNetwork: true, needsPort: true, defaultPort: 443),
        ToolDefinition(id: "cors", name: "CORS check", inspiredBy: "nuclei cors", category: .web, summary: "OPTIONS with Origin to see if ACAO reflects * or any origin.", needsNetwork: true, needsPort: true, defaultPort: 80),
        ToolDefinition(id: "methods", name: "HTTP methods", inspiredBy: "nmap http-methods", category: .web, summary: "OPTIONS Allow: header.", needsNetwork: true, needsPort: true, defaultPort: 80),
        ToolDefinition(id: "wordpress", name: "WordPress detect", inspiredBy: "wpscan (detect only)", category: .web, summary: "Looks for wp-content, wp-login, and generator tags. No login attempts.", needsNetwork: true, needsPort: true, defaultPort: 80),
        ToolDefinition(id: "cookies", name: "Cookie flags", inspiredBy: "Burp / ZAP passive", category: .web, summary: "Secure, HttpOnly, and SameSite on Set-Cookie.", needsNetwork: true, needsPort: true, defaultPort: 443),

        ToolDefinition(id: "ssl-cert", name: "Certificate", inspiredBy: "sslscan / testssl.sh", category: .tls, summary: "Subject, issuer, expiry, self-signed.", needsNetwork: true, needsPort: true, defaultPort: 443),
        ToolDefinition(id: "ssl-proto", name: "TLS protocols", inspiredBy: "sslscan --show-offline", category: .tls, summary: "Which of TLS 1.0–1.3 the service accepts.", needsNetwork: true, needsPort: true, defaultPort: 443),

        ToolDefinition(id: "nbstat", name: "NetBIOS names", inspiredBy: "nbtscan / nmap nbstat", category: .identity, summary: "UDP/137 wildcard name query.", needsNetwork: true, needsPort: false, defaultPort: 137),
        ToolDefinition(id: "smb", name: "SMB negotiate", inspiredBy: "enum4linux / smb-os-discovery", category: .identity, summary: "SMB2 dialect negotiate. No share crawl, no passwords.", needsNetwork: true, needsPort: true, defaultPort: 445),
        ToolDefinition(id: "ftp-syst", name: "FTP SYST", inspiredBy: "nmap ftp-syst", category: .identity, summary: "SYST/FEAT identification, no login.", needsNetwork: true, needsPort: true, defaultPort: 21),
        ToolDefinition(id: "ftp-anon", name: "FTP anonymous", inspiredBy: "nmap ftp-anon", category: .identity, summary: "One USER anonymous check. No file download.", needsNetwork: true, needsPort: true, defaultPort: 21),
        ToolDefinition(id: "smtp", name: "SMTP commands", inspiredBy: "nmap smtp-commands", category: .identity, summary: "EHLO capabilities. Does not send mail.", needsNetwork: true, needsPort: true, defaultPort: 25),
        ToolDefinition(id: "ldap", name: "LDAP rootDSE", inspiredBy: "ldapsearch / enum4linux", category: .identity, summary: "Anonymous rootDSE read if ldapsearch is present.", needsNetwork: true, needsPort: true, defaultPort: 389),
        ToolDefinition(id: "snmp", name: "SNMP public", inspiredBy: "snmpwalk / onesixtyone (public only)", category: .identity, summary: "Single sysDescr GET with community public.", needsNetwork: true, needsPort: false, defaultPort: 161),

        ToolDefinition(id: "banner", name: "Banner grab", inspiredBy: "netcat / nmap banner", category: .services, summary: "Read the first bytes on a TCP port.", needsNetwork: true, needsPort: true, defaultPort: 22),
        ToolDefinition(id: "redis", name: "Redis PING", inspiredBy: "nmap redis-info", category: .services, summary: "Sends PING. Reports if the instance answers without AUTH.", needsNetwork: true, needsPort: true, defaultPort: 6379),
        ToolDefinition(id: "mysql", name: "MySQL greeting", inspiredBy: "nmap mysql-info", category: .services, summary: "Parse the unauthenticated handshake version string.", needsNetwork: true, needsPort: true, defaultPort: 3306),
        ToolDefinition(id: "rdp", name: "RDP negotiate", inspiredBy: "nmap rdp-ntlm-info", category: .services, summary: "X.224 connection request only.", needsNetwork: true, needsPort: true, defaultPort: 3389),
        ToolDefinition(id: "ssh", name: "SSH banner", inspiredBy: "nmap ssh-hostkey", category: .services, summary: "SSH identification string.", needsNetwork: true, needsPort: true, defaultPort: 22),

        ToolDefinition(id: "advisories", name: "Banner advisories", inspiredBy: "nmap-vulners (local notes)", category: .advisory, summary: "Match last-scan banners to a local note table. Not a live CVE feed.", needsNetwork: false, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "panels", name: "Exposed panels", inspiredBy: "httpx + nuclei panel templates", category: .advisory, summary: "Highlight admin/UI ports from the last host inventory.", needsNetwork: false, needsPort: false, defaultPort: nil),

        ToolDefinition(id: "ports", name: "Port notes", inspiredBy: "nmap-services", category: .reference, summary: "What a port usually is and why it matters.", needsNetwork: false, needsPort: true, defaultPort: 22),
        ToolDefinition(id: "mac-lookup", name: "MAC vendor", inspiredBy: "nmap-mac-prefixes", category: .reference, summary: "IEEE OUI lookup from the bundled table.", needsNetwork: false, needsPort: false, defaultPort: nil),
        ToolDefinition(id: "cidr", name: "CIDR helper", inspiredBy: "ipcalc / sipcalc", category: .reference, summary: "Network, broadcast, and host count for an address/mask.", needsNetwork: false, needsPort: false, defaultPort: nil)
    ]

    static func tool(id: String) -> ToolDefinition {
        catalog.first(where: { $0.id == id }) ?? catalog[0]
    }
}

struct ToolRun: Identifiable, Sendable {
    let id: UUID
    let toolID: String
    let toolName: String
    let target: String
    let started: Date
    var finished: Date?
    var output: String
    var findings: [Finding]
    var succeeded: Bool
    var running: Bool

    init(
        id: UUID = UUID(),
        toolID: String,
        toolName: String,
        target: String,
        started: Date = Date(),
        finished: Date? = nil,
        output: String = "",
        findings: [Finding] = [],
        succeeded: Bool = true,
        running: Bool = false
    ) {
        self.id = id
        self.toolID = toolID
        self.toolName = toolName
        self.target = target
        self.started = started
        self.finished = finished
        self.output = output
        self.findings = findings
        self.succeeded = succeeded
        self.running = running
    }
}

enum NetworkPane: String, CaseIterable, Identifiable {
    case setup = "Setup"
    case hosts = "Hosts"
    case compare = "Compare"

    var id: String { rawValue }
}
