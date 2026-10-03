import Foundation

/// Timing templates inspired by nmap `-T0`…`-T5`.
enum TimingTemplate: String, CaseIterable, Identifiable, Sendable {
    case polite
    case normal
    case aggressive
    case insane

    var id: String { rawValue }

    var label: String {
        switch self {
        case .polite: return "T2 Polite"
        case .normal: return "T3 Normal"
        case .aggressive: return "T4 Aggressive"
        case .insane: return "T5 Insane"
        }
    }

    var maxInFlight: Int {
        switch self {
        case .polite: return 24
        case .normal: return 72
        case .aggressive: return 140
        case .insane: return 256
        }
    }

    var connectTimeout: TimeInterval {
        switch self {
        case .polite: return 1.6
        case .normal: return 0.8
        case .aggressive: return 0.45
        case .insane: return 0.28
        }
    }

    var identifyTimeout: TimeInterval {
        switch self {
        case .polite: return 1.8
        case .normal: return 0.9
        case .aggressive: return 0.6
        case .insane: return 0.4
        }
    }

    var udpTimeout: TimeInterval {
        switch self {
        case .polite: return 1.8
        case .normal: return 1.0
        case .aggressive: return 0.7
        case .insane: return 0.45
        }
    }
}

enum PortSetKind: String, CaseIterable, Identifiable, Sendable {
    case fast
    case catalog
    case top100
    case top1000
    case custom

    var id: String { rawValue }

    var label: String {
        switch self {
        case .fast: return "Fast (−F / top 20)"
        case .catalog: return "Sentinel catalog"
        case .top100: return "Nmap top 100"
        case .top1000: return "Nmap top 1000"
        case .custom: return "Custom ports"
        }
    }
}

/// Presets modelled on Zenmap / nmap command-line profiles.
struct ScanProfile: Identifiable, Equatable, Hashable, Sendable {
    var id: String { name }
    var name: String
    var summary: String
    var nmapEquivalent: String
    var timing: TimingTemplate
    var portSet: PortSetKind
    var skipHostDiscovery: Bool
    var tcpPing: Bool
    var icmpPing: Bool
    var arpDiscovery: Bool
    var netbiosDiscovery: Bool
    var reverseDNS: Bool
    var udpScan: Bool
    var versionDetect: Bool
    var scriptScan: Bool
    var osDetect: Bool
    var traceroute: Bool
    var twoPhaseSweep: Bool

    static let pingSweep = ScanProfile(
        name: "Ping sweep",
        summary: "Host discovery only: ICMP, ARP cache, TCP ping, NetBIOS. No port scan.",
        nmapEquivalent: "nmap -sn -PE -PS22,80,443 --send-ip",
        timing: .aggressive,
        portSet: .fast,
        skipHostDiscovery: false,
        tcpPing: true,
        icmpPing: true,
        arpDiscovery: true,
        netbiosDiscovery: true,
        reverseDNS: true,
        udpScan: false,
        versionDetect: false,
        scriptScan: false,
        osDetect: false,
        traceroute: false,
        twoPhaseSweep: false
    )

    static let quick = ScanProfile(
        name: "Quick scan",
        summary: "Fast TCP connect on the most common ports. rustscan-style two-phase sweep.",
        nmapEquivalent: "nmap -T4 -F -sT",
        timing: .aggressive,
        portSet: .fast,
        skipHostDiscovery: false,
        tcpPing: true,
        icmpPing: true,
        arpDiscovery: true,
        netbiosDiscovery: false,
        reverseDNS: true,
        udpScan: false,
        versionDetect: false,
        scriptScan: false,
        osDetect: false,
        traceroute: false,
        twoPhaseSweep: true
    )

    static let regular = ScanProfile(
        name: "Regular scan",
        summary: "Default Sentinel catalog with banners. Closest to the original app.",
        nmapEquivalent: "nmap -sT -sV --version-light",
        timing: .normal,
        portSet: .catalog,
        skipHostDiscovery: false,
        tcpPing: true,
        icmpPing: true,
        arpDiscovery: true,
        netbiosDiscovery: true,
        reverseDNS: true,
        udpScan: false,
        versionDetect: true,
        scriptScan: false,
        osDetect: true,
        traceroute: false,
        twoPhaseSweep: true
    )

    static let intense = ScanProfile(
        name: "Intense scan",
        summary: "Top 100 ports, version detection, safe scripts, OS guess, traceroute.",
        nmapEquivalent: "nmap -T4 -A -sT --top-ports 100 --script=safe,default",
        timing: .aggressive,
        portSet: .top100,
        skipHostDiscovery: false,
        tcpPing: true,
        icmpPing: true,
        arpDiscovery: true,
        netbiosDiscovery: true,
        reverseDNS: true,
        udpScan: false,
        versionDetect: true,
        scriptScan: true,
        osDetect: true,
        traceroute: true,
        twoPhaseSweep: true
    )

    static let intenseUDP = ScanProfile(
        name: "Intense + UDP",
        summary: "Intense TCP plus nmap-style UDP payload probes (DNS, SNMP, NTP, SSDP, IKE…).",
        nmapEquivalent: "nmap -T4 -A -sT -sU --top-ports 100",
        timing: .aggressive,
        portSet: .top100,
        skipHostDiscovery: false,
        tcpPing: true,
        icmpPing: true,
        arpDiscovery: true,
        netbiosDiscovery: true,
        reverseDNS: true,
        udpScan: true,
        versionDetect: true,
        scriptScan: true,
        osDetect: true,
        traceroute: true,
        twoPhaseSweep: true
    )

    static let comprehensive = ScanProfile(
        name: "Comprehensive",
        summary: "Nmap top 1000, UDP, scripts, OS, traceroute. Slowest, most complete native pass.",
        nmapEquivalent: "nmap -T4 -A -sT -sU --top-ports 1000 --script=safe,default",
        timing: .normal,
        portSet: .top1000,
        skipHostDiscovery: false,
        tcpPing: true,
        icmpPing: true,
        arpDiscovery: true,
        netbiosDiscovery: true,
        reverseDNS: true,
        udpScan: true,
        versionDetect: true,
        scriptScan: true,
        osDetect: true,
        traceroute: true,
        twoPhaseSweep: true
    )

    static let presets: [ScanProfile] = [
        .pingSweep, .quick, .regular, .intense, .intenseUDP, .comprehensive
    ]

    func ports(customSpec: String) -> [UInt16] {
        switch portSet {
        case .fast: return NmapPortLists.top20
        case .catalog: return PortCatalog.defaultScanPorts
        case .top100: return NmapPortLists.top100
        case .top1000: return NmapPortLists.top1000
        case .custom: return PortSpec.parse(customSpec)
        }
    }
}

enum PortSpec {
    /// nmap-style `22,80,443,8000-8100`.
    static func parse(_ spec: String) -> [UInt16] {
        var ports = Set<UInt16>()
        let cleaned = spec.replacingOccurrences(of: " ", with: "")
        guard !cleaned.isEmpty else { return NmapPortLists.top20 }
        for token in cleaned.split(separator: ",") {
            if let dash = token.firstIndex(of: "-") {
                let lo = UInt32(token[..<dash]) ?? 0
                let hi = UInt32(token[token.index(after: dash)...]) ?? 0
                guard lo >= 1, hi <= 65535, lo <= hi else { continue }
                let capped = min(hi, lo + 4095)
                for value in lo...capped {
                    if let port = UInt16(exactly: value) { ports.insert(port) }
                }
            } else if let port = UInt16(token), port > 0 {
                ports.insert(port)
            }
        }
        return ports.sorted()
    }
}

struct HostHint: Sendable {
    let ip: String
    var method: String
    var mac: String?
    var vendor: String?
    var latencyMS: Double?
    var ttl: Int?
    var netbiosName: String?
    var workgroup: String?
    var hostname: String?
}

enum NmapScriptName {
    static let banner = "banner"
    static let httpTitle = "http-title"
    static let httpHeaders = "http-headers"
    static let httpAuth = "http-auth"
    static let httpMethods = "http-methods"
    static let httpRobots = "http-robots.txt"
    static let sslCert = "ssl-cert"
    static let sslEnumCiphers = "ssl-enum-ciphers"
    static let sshHostkey = "ssh-hostkey"
    static let smtpCommands = "smtp-commands"
    static let ftpSyst = "ftp-syst"
    static let dnsRecursion = "dns-recursion"
    static let ntpInfo = "ntp-info"
    static let upnpInfo = "upnp-info"
    static let nbstat = "nbstat"
    static let smbOS = "smb-os-discovery"
    static let mysqlInfo = "mysql-info"
    static let redisInfo = "redis-info"
    static let mongodbInfo = "mongodb-info"
    static let rdpInfo = "rdp-ntlm-info"
    static let sipMethods = "sip-methods"
    static let ikeVersion = "ike-version"
    static let snmpInfo = "snmp-info"
}
