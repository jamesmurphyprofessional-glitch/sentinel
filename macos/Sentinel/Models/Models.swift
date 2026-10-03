import Foundation

enum Severity: String, Codable, CaseIterable, Comparable, Sendable {
    case info
    case low
    case medium
    case high
    case critical

    private var rank: Int {
        switch self {
        case .info: return 0
        case .low: return 1
        case .medium: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    static func < (lhs: Severity, rhs: Severity) -> Bool {
        lhs.rank < rhs.rank
    }

    var label: String {
        switch self {
        case .info: return "OK"
        case .low: return "Tip"
        case .medium: return "Should fix"
        case .high: return "Important"
        case .critical: return "Fix now"
        }
    }

    var needsAttention: Bool { self >= .medium }
}

enum FindingCategory: String, Codable, CaseIterable, Sendable {
    case network
    case remoteAccess
    case listening
    case hardening
    case service

    var label: String {
        switch self {
        case .network: return "Your Wi-Fi"
        case .remoteAccess: return "Remote access"
        case .listening: return "Sharing from this Mac"
        case .hardening: return "This Mac"
        case .service: return "Open on a device"
        }
    }
}

struct Finding: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    let category: FindingCategory
    let severity: Severity
    let title: String
    let detail: String
    let remediation: String
    let host: String?
    let evidence: String?
    let scannedAt: Date

    init(
        id: UUID = UUID(),
        category: FindingCategory,
        severity: Severity,
        title: String,
        detail: String,
        remediation: String,
        host: String? = nil,
        evidence: String? = nil,
        scannedAt: Date = Date()
    ) {
        self.id = id
        self.category = category
        self.severity = severity
        self.title = title
        self.detail = detail
        self.remediation = remediation
        self.host = host
        self.evidence = evidence
        self.scannedAt = scannedAt
    }
}

enum TransportProtocol: String, Codable, Sendable {
    case tcp
    case udp
}

enum PortState: String, Codable, Sendable {
    case open
    case closed
    case filtered
    case openFiltered = "open|filtered"

    var label: String { rawValue }
}

struct ScriptOutput: Identifiable, Codable, Hashable, Sendable {
    var id: String { name }
    let name: String
    let output: String
}

struct OSGuess: Codable, Hashable, Sendable {
    let name: String
    let accuracy: Int
    let evidence: [String]

    var summary: String { name }
}

struct TraceHop: Identifiable, Codable, Hashable, Sendable {
    var id: Int { ttl }
    let ttl: Int
    let address: String?
    let hostname: String?
    let rttMS: Double?
}

struct OpenPort: Identifiable, Codable, Hashable, Sendable {
    var id: String { "\(host):\(transport.rawValue)/\(port)" }
    let host: String
    let port: UInt16
    var service: String
    let risk: Severity
    var banner: String?
    let reason: String
    var transport: TransportProtocol
    var state: PortState
    var product: String?
    var version: String?
    var extraInfo: String?
    var scripts: [ScriptOutput]

    init(
        host: String,
        port: UInt16,
        service: String,
        risk: Severity,
        banner: String?,
        reason: String,
        transport: TransportProtocol = .tcp,
        state: PortState = .open,
        product: String? = nil,
        version: String? = nil,
        extraInfo: String? = nil,
        scripts: [ScriptOutput] = []
    ) {
        self.host = host
        self.port = port
        self.service = service
        self.risk = risk
        self.banner = banner
        self.reason = reason
        self.transport = transport
        self.state = state
        self.product = product
        self.version = version
        self.extraInfo = extraInfo
        self.scripts = scripts
    }

    var serviceLabel: String {
        var parts = [service]
        if let product, !product.isEmpty { parts.append(product) }
        if let version, !version.isEmpty { parts.append(version) }
        return parts.joined(separator: " ")
    }
}

struct DiscoveredHost: Identifiable, Codable, Hashable, Sendable {
    var id: String { ip }
    let ip: String
    var hostname: String?
    var ports: [OpenPort]
    var bonjourNames: [String]
    var isLocalMachine: Bool
    var macAddress: String?
    var vendor: String?
    var osGuess: OSGuess?
    var latencyMS: Double?
    var ttl: Int?
    var traceroute: [TraceHop]
    var discoveryMethod: String?
    var netbiosName: String?
    var workgroup: String?
    var reason: String?

    init(
        ip: String,
        hostname: String?,
        ports: [OpenPort],
        bonjourNames: [String],
        isLocalMachine: Bool,
        macAddress: String? = nil,
        vendor: String? = nil,
        osGuess: OSGuess? = nil,
        latencyMS: Double? = nil,
        ttl: Int? = nil,
        traceroute: [TraceHop] = [],
        discoveryMethod: String? = nil,
        netbiosName: String? = nil,
        workgroup: String? = nil,
        reason: String? = nil
    ) {
        self.ip = ip
        self.hostname = hostname
        self.ports = ports
        self.bonjourNames = bonjourNames
        self.isLocalMachine = isLocalMachine
        self.macAddress = macAddress
        self.vendor = vendor
        self.osGuess = osGuess
        self.latencyMS = latencyMS
        self.ttl = ttl
        self.traceroute = traceroute
        self.discoveryMethod = discoveryMethod
        self.netbiosName = netbiosName
        self.workgroup = workgroup
        self.reason = reason
    }
}

struct ScanDelta: Sendable {
    let appearedHosts: [String]
    let disappearedHosts: [String]
    let newPorts: [String]
    let closedPorts: [String]
    let summary: String
}

struct NetworkSnapshot: Sendable {
    let interfaceName: String
    let ipAddress: String
    let netmask: String
    let cidr: Int
    let broadcast: String
    let gateway: String?
    let ssid: String?
    let hosts: [String]
}

struct ListeningSocket: Identifiable, Hashable, Sendable {
    var id: String { "\(address):\(port):\(process)" }
    let address: String
    let port: UInt16
    let process: String
    let pid: String
    let exposed: Bool
}

struct ScanProgress: Sendable {
    var phase: String
    var completed: Int
    var total: Int
    var statusLine: String

    var fraction: Double {
        guard total > 0 else { return 0 }
        return min(1, Double(completed) / Double(total))
    }
}

enum HomeScanMode: String, CaseIterable, Identifiable, Sendable {
    case quick
    case thorough

    var id: String { rawValue }

    var title: String {
        switch self {
        case .quick: return "Quick look"
        case .thorough: return "Thorough check"
        }
    }

    var summary: String {
        switch self {
        case .quick:
            return "Finds devices on your Wi-Fi and checks the usual ways they share files or let someone connect. Usually about a minute."
        case .thorough:
            return "Looks at more services on each device. Takes longer, but is better at spotting extra sharing and admin pages."
        }
    }

    var profile: ScanProfile {
        switch self {
        case .quick: return .quick
        case .thorough: return .regular
        }
    }
}

enum DeviceGuide {
    static func kind(_ host: DiscoveredHost, gateway: String?) -> String {
        if host.isLocalMachine { return "This Mac" }
        if let gateway, host.ip == gateway { return "Your router" }

        let blob = [
            host.hostname,
            host.vendor,
            host.netbiosName,
            host.osGuess?.name,
            host.bonjourNames.joined(separator: " ")
        ]
        .compactMap { $0 }
        .joined(separator: " ")
        .lowercased()

        if blob.contains("iphone") || blob.contains("ipad") { return "iPhone or iPad" }
        if blob.contains("apple tv") || blob.contains("appletv") || blob.contains("airplay") { return "Apple TV" }
        if blob.contains("homepod") || blob.contains("speaker") || blob.contains("sonos") { return "Speaker" }
        if blob.contains("printer") || blob.contains("ipp") || host.ports.contains(where: { [631, 9100].contains($0.port) }) {
            return "Printer"
        }
        if blob.contains("camera") || blob.contains("ring") || blob.contains("nest") || host.ports.contains(where: { [554, 8554].contains($0.port) }) {
            return "Camera"
        }
        if blob.contains("tv") || blob.contains("roku") || blob.contains("fire tv") || blob.contains("chromecast") {
            return "TV or streaming box"
        }
        if blob.contains("amazon") || blob.contains("echo") || blob.contains("alexa") { return "Smart speaker" }
        if blob.contains("nas") || blob.contains("synology") || blob.contains("qnap") { return "Home file storage" }
        if blob.contains("watch") { return "Apple Watch" }
        if blob.contains("mac") || blob.contains("imac") || blob.contains("macbook") { return "Another Mac" }
        if blob.contains("windows") || blob.contains("microsoft") || blob.contains("pc") { return "Windows PC" }
        if blob.contains("android") || blob.contains("samsung") || blob.contains("pixel") { return "Phone or tablet" }
        if host.vendor != nil { return "A device on your network" }
        return "Unknown device"
    }

    static func blurb(_ host: DiscoveredHost, gateway: String?) -> String {
        let kind = kind(host, gateway: gateway)
        switch kind {
        case "This Mac":
            return "This is the computer you are using right now."
        case "Your router":
            return "This box creates your Wi-Fi. Protect it with a unique password and keep its software up to date."
        case "Printer":
            return "Printers are normal on home Wi-Fi. You usually do not need remote access turned on."
        case "Camera":
            return "Cameras should stay on your home Wi-Fi, not be reachable from the public internet."
        case "Apple TV", "Speaker", "TV or streaming box", "Smart speaker", "Apple Watch":
            return "Everyday household gadget. Fine on your Wi-Fi; just keep it updated."
        case "Home file storage":
            return "This stores files. Turn off guest sharing and use a strong password."
        default:
            if host.ports.contains(where: { [22, 23, 3389, 5900].contains($0.port) }) {
                return "This device is offering remote access. Only keep that on if you really use it."
            }
            if host.ports.contains(where: { [445, 139, 548].contains($0.port) }) {
                return "This device is sharing files. Confirm you meant to share them."
            }
            return "If you do not recognize this device, it may be a guest phone, a smart gadget, or something you should look into."
        }
    }
}

enum SentinelError: LocalizedError {
    case noActiveInterface
    case scanInProgress
    case unauthorizedNetwork

    var errorDescription: String? {
        switch self {
        case .noActiveInterface:
            return "This Mac does not look connected to a network. Join Wi-Fi or plug in Ethernet, then try again."
        case .scanInProgress:
            return "A check is already running."
        case .unauthorizedNetwork:
            return "Please confirm this is your network before we look at other devices."
        }
    }
}
