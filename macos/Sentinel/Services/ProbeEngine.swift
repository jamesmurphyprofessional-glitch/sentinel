import Foundation
import Network
import Security

/// Service detection (`-sV`), UDP payloads (`-sU`), TLS inspection (sslscan-like),
/// and a safe subset of NSE / whatweb / httpx / enum4linux-lite scripts.
actor ProbeEngine {
    func enrich(
        hosts: [DiscoveredHost],
        profile: ScanProfile,
        progress: @escaping @Sendable (ScanProgress) -> Void
    ) async -> [DiscoveredHost] {
        var updated = hosts
        let work = updated.enumerated().flatMap { index, host in
            host.ports.enumerated().map { portIndex, _ in (index, portIndex) }
        }
        let total = max(work.count, 1)
        var completed = 0

        for (hostIndex, portIndex) in work {
            var port = updated[hostIndex].ports[portIndex]
            if profile.versionDetect || profile.scriptScan {
                port = await identify(port: port, scripts: profile.scriptScan)
            }
            updated[hostIndex].ports[portIndex] = port
            completed += 1
            if completed == 1 || completed % 6 == 0 || completed == total {
                progress(ScanProgress(
                    phase: "Service / scripts",
                    completed: completed,
                    total: total,
                    statusLine: "Looking closer at open services \(completed)/\(total)"
                ))
            }
        }

        if profile.udpScan {
            let udpTargets = updated.map(\.ip)
            let udpHits = await UDPScanner.scan(hosts: udpTargets, timeout: profile.timing.udpTimeout) { done, all in
                progress(ScanProgress(
                    phase: "UDP scan",
                    completed: done,
                    total: all,
                    statusLine: "Checking extra services \(done)/\(all)"
                ))
            }
            for (index, host) in updated.enumerated() {
                let extras = udpHits.filter { $0.host == host.ip }
                if extras.isEmpty == false {
                    updated[index].ports.append(contentsOf: extras)
                    updated[index].ports.sort { lhs, rhs in
                        if lhs.port == rhs.port { return lhs.transport.rawValue < rhs.transport.rawValue }
                        return lhs.port < rhs.port
                    }
                }
            }
        }

        if profile.osDetect {
            for index in updated.indices {
                updated[index].osGuess = OSFingerprint.guess(host: updated[index])
            }
        }

        if profile.traceroute {
            let cap = min(updated.count, profile.portSet == .top1000 ? 16 : 6)
            for (offset, host) in updated.prefix(cap).enumerated() {
                progress(ScanProgress(
                    phase: "Traceroute",
                    completed: offset,
                    total: cap,
                    statusLine: "Tracing the path to \(host.ip)"
                ))
                updated[offset].traceroute = await PathTracer.trace(host: host.ip)
            }
        }

        return updated
    }

    private func identify(port: OpenPort, scripts: Bool) async -> OpenPort {
        var next = port
        switch port.transport {
        case .udp:
            return next
        case .tcp:
            break
        }

        if [80, 81, 82, 8000, 8008, 8080, 8081, 8082, 8090, 8888, 3000, 5000, 4173, 9090, 10000].contains(port.port) {
            if let http = await HTTPFingerprint.fetch(host: port.host, port: port.port, tls: false) {
                applyHTTP(&next, http, scripts: scripts)
            }
        } else if [443, 8443, 4443, 9443, 10443].contains(port.port) {
            if let tls = await TLSInspector.inspect(host: port.host, port: port.port, runHTTP: true) {
                applyTLS(&next, tls, scripts: scripts)
            }
        } else if port.port == 22 || port.port == 2222 || port.port == 2200 {
            next = await SSHProbe.enrich(next, scripts: scripts)
        } else if port.port == 21 {
            next = await FTPProbe.enrich(next, scripts: scripts)
        } else if [25, 587].contains(port.port) {
            next = await SMTPProbe.enrich(next, scripts: scripts)
        } else if port.port == 445 || port.port == 139 {
            next = await SMBProbe.enrich(next, scripts: scripts)
        } else if port.port == 3389 {
            next = await RDPProbe.enrich(next, scripts: scripts)
        } else if port.port == 3306 {
            next = await MySQLProbe.enrich(next)
        } else if port.port == 6379 {
            next = await RedisProbe.enrich(next, scripts: scripts)
        } else if port.port == 27017 {
            next = await MongoProbe.enrich(next, scripts: scripts)
        } else if port.port == 5432 {
            next = await BannerGrab.enrich(next, send: nil)
        } else {
            next = await BannerGrab.enrich(next, send: nil)
        }
        return next
    }

    private func applyHTTP(_ port: inout OpenPort, _ http: HTTPFingerprint.Result, scripts: Bool) {
        if port.banner == nil { port.banner = http.summary }
        if let server = http.server { port.product = server }
        if let title = http.title { port.extraInfo = title }
        if scripts {
            if let title = http.title {
                port.scripts.append(ScriptOutput(name: NmapScriptName.httpTitle, output: title))
            }
            if !http.headers.isEmpty {
                port.scripts.append(ScriptOutput(name: NmapScriptName.httpHeaders, output: http.headers.joined(separator: "\n")))
            }
            if let auth = http.authenticate {
                port.scripts.append(ScriptOutput(name: NmapScriptName.httpAuth, output: auth))
            }
            if let methods = http.methods {
                port.scripts.append(ScriptOutput(name: NmapScriptName.httpMethods, output: methods))
            }
            if let robots = http.robots {
                port.scripts.append(ScriptOutput(name: NmapScriptName.httpRobots, output: robots))
            }
            if !http.tech.isEmpty {
                port.scripts.append(ScriptOutput(name: "http-tech (whatweb/httpx)", output: http.tech.joined(separator: ", ")))
            }
        }
    }

    private func applyTLS(_ port: inout OpenPort, _ tls: TLSInspector.Result, scripts: Bool) {
        if let http = tls.http {
            applyHTTP(&port, http, scripts: scripts)
        }
        port.product = port.product ?? tls.subject
        port.version = tls.protocolVersion
        port.extraInfo = [tls.subject, tls.issuer, tls.expires].compactMap { $0 }.joined(separator: " | ")
        if scripts {
            port.scripts.append(ScriptOutput(name: NmapScriptName.sslCert, output: tls.certificateText))
            if !tls.supportedVersions.isEmpty {
                port.scripts.append(ScriptOutput(
                    name: NmapScriptName.sslEnumCiphers,
                    output: "Negotiated / accepted: " + tls.supportedVersions.joined(separator: ", ")
                ))
            }
        }
    }
}

// MARK: - UDP

enum UDPScanner {
    static func scan(
        hosts: [String],
        timeout: TimeInterval,
        progress: @escaping @Sendable (Int, Int) -> Void
    ) async -> [OpenPort] {
        let jobs = hosts.flatMap { host in NmapPortLists.udpProbePorts.map { (host, $0) } }
        var hits: [OpenPort] = []
        let total = jobs.count
        var completed = 0

        await withTaskGroup(of: OpenPort?.self) { group in
            var iterator = jobs.makeIterator()
            var inFlight = 0
            let cap = 48

            func enqueue(_ host: String, _ port: UInt16) {
                inFlight += 1
                group.addTask {
                    await probe(host: host, port: port, timeout: timeout)
                }
            }

            while inFlight < cap, let next = iterator.next() { enqueue(next.0, next.1) }
            for await hit in group {
                inFlight -= 1
                completed += 1
                if let hit { hits.append(hit) }
                if completed == 1 || completed % 12 == 0 || completed == total {
                    progress(completed, total)
                }
                if let next = iterator.next() { enqueue(next.0, next.1) }
            }
        }
        return hits
    }

    private static func probe(host: String, port: UInt16, timeout: TimeInterval) async -> OpenPort? {
        guard let payload = payload(for: port) else { return nil }
        guard let data = await UDPProbe.send(host: host, port: port, payload: payload, timeout: timeout) else {
            return nil
        }
        let text = decode(data)
        let parsed = parseUDP(port: port, data: data, text: text)
        return OpenPort(
            host: host,
            port: port,
            service: parsed.service,
            risk: parsed.risk,
            banner: parsed.banner,
            reason: parsed.reason,
            transport: .udp,
            state: .open,
            product: parsed.product,
            version: parsed.version,
            extraInfo: parsed.extra,
            scripts: parsed.scripts
        )
    }

    private static func payload(for port: UInt16) -> Data? {
        switch port {
        case 53, 5353, 5355:
            return DNSPacket.recursionQuery(name: port == 53 ? "example.com" : "_services._dns-sd._udp.local")
        case 123:
            var packet = [UInt8](repeating: 0, count: 48)
            packet[0] = 0x1B
            return Data(packet)
        case 137:
            return NetBIOSQuery.packet()
        case 161:
            return SNMPPacket.getPublic()
        case 1900:
            return Data("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".utf8)
        case 500, 4500:
            return IKEPacket.header()
        case 5060:
            return Data("OPTIONS sip:nm SIP/2.0\r\nVia: SIP/2.0/UDP nm;branch=z9hG4bK1\r\nFrom: <sip:nm@nm>;tag=1\r\nTo: <sip:nm2@nm2>\r\nCall-ID: 1@nm\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n".utf8)
        case 69:
            return Data([0x00, 0x01]) + Data("nonexistent".utf8) + Data([0x00]) + Data("octet".utf8) + Data([0x00])
        case 1434:
            return Data([0x02])
        case 11211:
            return Data("stats\r\n".utf8)
        case 514:
            return Data("<14>Sentinel identification probe\n".utf8)
        case 5683:
            // CoAP GET /.well-known/core (empty confirmable GET)
            return Data([0x40, 0x01, 0x12, 0x34])
        default:
            return Data([0x00])
        }
    }

    private static func parseUDP(port: UInt16, data: Data, text: String) -> (
        service: String, risk: Severity, banner: String?, reason: String,
        product: String?, version: String?, extra: String?, scripts: [ScriptOutput]
    ) {
        var scripts: [ScriptOutput] = []
        switch port {
        case 53, 5353, 5355:
            let recursion = data.count > 3 && (data[2] & 0x80) != 0
            if recursion {
                scripts.append(ScriptOutput(name: NmapScriptName.dnsRecursion, output: "Recursion available / answered"))
            }
            return ("dns", .medium, text.prefix(120).description, "UDP DNS/mDNS answered an identification query.", "DNS", nil, recursion ? "recursion" : nil, scripts)
        case 123:
            scripts.append(ScriptOutput(name: NmapScriptName.ntpInfo, output: "NTP reply \(data.count) bytes, LI/VN/Mode=\(data.first.map { String(format: "0x%02x", $0) } ?? "?")"))
            return ("ntp", .low, "NTP reply \(data.count)B", "NTP answered a client packet.", "NTP", nil, nil, scripts)
        case 137:
            if let name = NetBIOSProbe.parsePublic(data) {
                scripts.append(ScriptOutput(name: NmapScriptName.nbstat, output: "\(name.name) workgroup=\(name.workgroup ?? "-")"))
                return ("netbios-ns", .medium, name.name, "NetBIOS name service answered (nbtscan).", name.name, nil, name.workgroup, scripts)
            }
            return ("netbios-ns", .medium, text.prefix(80).description, "NetBIOS name service answered.", nil, nil, nil, scripts)
        case 161:
            scripts.append(ScriptOutput(name: NmapScriptName.snmpInfo, output: text.isEmpty ? "SNMP reply \(data.count) bytes to community public" : text))
            return ("snmp", .high, text.prefix(160).description, "SNMP responded to a public-community GET (nmap snmp-info).", "SNMP", nil, "community=public", scripts)
        case 1900:
            scripts.append(ScriptOutput(name: NmapScriptName.upnpInfo, output: text))
            return ("upnp", .medium, text.prefix(160).description, "SSDP/UPnP answered M-SEARCH.", "UPnP", nil, nil, scripts)
        case 500, 4500:
            scripts.append(ScriptOutput(name: NmapScriptName.ikeVersion, output: "IKE reply \(data.count) bytes"))
            return ("isakmp", .info, "IKE reply \(data.count)B", "IKE/IPsec endpoint answered (ike-scan style).", "IKE", nil, nil, scripts)
        case 5060:
            scripts.append(ScriptOutput(name: NmapScriptName.sipMethods, output: text))
            return ("sip", .medium, text.prefix(160).description, "SIP answered OPTIONS.", "SIP", nil, nil, scripts)
        case 69:
            return ("tftp", .high, text.prefix(80).description, "TFTP answered a dummy RRQ.", "TFTP", nil, nil, [])
        default:
            return (PortCatalog.profile(for: port).service, PortCatalog.profile(for: port).risk, text.prefix(120).description, "UDP service answered an identification payload.", nil, nil, nil, [])
        }
    }

    private static func decode(_ data: Data) -> String {
        String(data: data, encoding: .utf8)
            ?? String(data: data, encoding: .isoLatin1)
            ?? data.map { String(format: "%02x", $0) }.prefix(32).joined(separator: " ")
    }
}

enum UDPProbe {
    static func send(host: String, port: UInt16, payload: Data, timeout: TimeInterval) async -> Data? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .udp)
        let box = ResumeBox()

        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    connection.send(content: payload, completion: .contentProcessed { _ in
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 1500) { data, _, _, _ in
                            if box.complete() {
                                continuation.resume(returning: data)
                            }
                            connection.cancel()
                        }
                    })
                case .failed, .cancelled:
                    if box.complete() {
                        continuation.resume(returning: nil)
                    }
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .utility))
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                if box.complete() {
                    continuation.resume(returning: nil)
                }
                connection.cancel()
            }
        }
    }
}

enum NetBIOSQuery {
    static func packet() -> Data {
        var bytes: [UInt8] = [
            0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20
        ]
        bytes.append(contentsOf: "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".utf8)
        bytes.append(contentsOf: [0x00, 0x00, 0x21, 0x00, 0x01])
        return Data(bytes)
    }
}

extension NetBIOSProbe {
    static func parsePublic(_ data: Data) -> Name? {
        // Re-use parser by sending through a thin wrapper.
        nbstatFrom(data)
    }

    fileprivate static func nbstatFrom(_ data: Data) -> Name? {
        var names: [(String, UInt8)] = []
        let bytes = [UInt8](data)
        var index = 57
        while index + 18 <= bytes.count {
            let slice = bytes[index..<(index + 15)]
            if let raw = String(bytes: slice, encoding: .ascii) {
                let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\0"))
                let suffix = bytes[index + 15]
                if trimmed.count >= 2 {
                    names.append((trimmed, suffix))
                }
            }
            index += 18
            if names.count > 8 { break }
        }
        guard let workstation = names.first(where: { $0.1 == 0x00 })?.0 ?? names.first?.0 else { return nil }
        let workgroup = names.first(where: { $0.1 == 0x00 && $0.0 != workstation })?.0
        return Name(name: workstation, workgroup: workgroup)
    }
}

enum DNSPacket {
    static func recursionQuery(name: String) -> Data {
        var data = Data([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8)
            data.append(UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01])
        return data
    }
}

enum SNMPPacket {
    /// SNMPv1 GET iso.3.6.1.2.1.1.1.0 (sysDescr) community `public`.
    static func getPublic() -> Data {
        Data([
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
            0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
            0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
            0x05, 0x00
        ])
    }
}

enum IKEPacket {
    static func header() -> Data {
        var bytes = [UInt8](repeating: 0, count: 28)
        bytes[0] = 0x12; bytes[1] = 0x34; bytes[2] = 0x56; bytes[3] = 0x78
        bytes[4] = 0x9a; bytes[5] = 0xbc; bytes[6] = 0xde; bytes[7] = 0xf0
        bytes[16] = 0x01 // IKEv1
        bytes[17] = 0x10 // flags / version
        bytes[18] = 0x02 // exchange SA
        bytes[24] = 0x00; bytes[25] = 0x00; bytes[26] = 0x00; bytes[27] = 0x1c
        return Data(bytes)
    }
}

// MARK: - HTTP / whatweb / httpx

enum HTTPFingerprint {
    struct Result: Sendable {
        var status: Int?
        var title: String?
        var server: String?
        var poweredBy: String?
        var authenticate: String?
        var location: String?
        var methods: String?
        var robots: String?
        var headers: [String]
        var tech: [String]
        var summary: String
    }

    static func fetch(host: String, port: UInt16, tls: Bool) async -> Result? {
        let request = "GET / HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: Sentinel-Identifier (nmap-http-title)\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        guard let body = await RawTCP.transact(host: host, port: port, send: Data(request.utf8), timeout: 1.2, tls: tls) else {
            return nil
        }
        let text = String(data: body, encoding: .utf8) ?? String(data: body, encoding: .isoLatin1) ?? ""
        var result = parse(text)
        if let options = await methods(host: host, port: port, tls: tls) {
            result.methods = options
        }
        if let robots = await robots(host: host, port: port, tls: tls) {
            result.robots = robots
        }
        return result
    }

    static func parse(_ text: String) -> Result {
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        var headers: [String] = []
        var server: String?
        var powered: String?
        var auth: String?
        var location: String?
        var status: Int?
        var cookies: [String] = []

        if let first = lines.first, first.uppercased().hasPrefix("HTTP/") {
            let parts = first.split(separator: " ")
            if parts.count >= 2 { status = Int(parts[1]) }
            headers.append(first)
        }
        for line in lines.dropFirst() {
            if line.isEmpty { break }
            headers.append(line)
            let lower = line.lowercased()
            if lower.hasPrefix("server:") { server = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
            if lower.hasPrefix("x-powered-by:") { powered = String(line.dropFirst(13)).trimmingCharacters(in: .whitespaces) }
            if lower.hasPrefix("www-authenticate:") { auth = String(line.dropFirst(17)).trimmingCharacters(in: .whitespaces) }
            if lower.hasPrefix("location:") { location = String(line.dropFirst(9)).trimmingCharacters(in: .whitespaces) }
            if lower.hasPrefix("set-cookie:") { cookies.append(String(line.dropFirst(11)).trimmingCharacters(in: .whitespaces)) }
        }

        let title = firstMatch(text, pattern: #"<title[^>]*>([^<]{1,120})</title>"#)?
            .trimmingCharacters(in: .whitespacesAndNewlines)

        var tech: [String] = []
        if let server { tech.append(server) }
        if let powered { tech.append(powered) }
        let blob = text.lowercased()
        if blob.contains("wp-content") || blob.contains("wordpress") { tech.append("WordPress") }
        if blob.contains("phpmyadmin") { tech.append("phpMyAdmin") }
        if blob.contains("router") && (blob.contains("login") || blob.contains("admin")) { tech.append("Router admin") }
        if blob.contains("synology") { tech.append("Synology") }
        if blob.contains("unifi") { tech.append("UniFi") }
        if blob.contains("grafana") { tech.append("Grafana") }
        if blob.contains("kibana") { tech.append("Kibana") }
        if blob.contains("nginx") { tech.append("nginx") }
        if blob.contains("apache") { tech.append("Apache") }
        if blob.contains("iis/") { tech.append("IIS") }
        if blob.contains("tomcat") { tech.append("Tomcat") }
        if !cookies.isEmpty { tech.append("cookies") }

        let summaryParts = [
            status.map { "HTTP \($0)" },
            server,
            title
        ].compactMap { $0 }

        return Result(
            status: status,
            title: title,
            server: server,
            poweredBy: powered,
            authenticate: auth,
            location: location,
            methods: nil,
            robots: nil,
            headers: Array(headers.prefix(16)),
            tech: Array(Set(tech)).sorted(),
            summary: summaryParts.joined(separator: " · ")
        )
    }

    private static func methods(host: String, port: UInt16, tls: Bool) async -> String? {
        let request = "OPTIONS / HTTP/1.0\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
        guard let body = await RawTCP.transact(host: host, port: port, send: Data(request.utf8), timeout: 0.8, tls: tls),
              let text = String(data: body, encoding: .utf8) ?? String(data: body, encoding: .isoLatin1) else { return nil }
        return firstMatch(text, pattern: #"(?i)allow:\s*([^\r\n]+)"#)
    }

    private static func robots(host: String, port: UInt16, tls: Bool) async -> String? {
        let request = "GET /robots.txt HTTP/1.0\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
        guard let body = await RawTCP.transact(host: host, port: port, send: Data(request.utf8), timeout: 0.8, tls: tls),
              let text = String(data: body, encoding: .utf8) ?? String(data: body, encoding: .isoLatin1),
              text.lowercased().contains("user-agent") || text.lowercased().contains("disallow") else { return nil }
        return String(text.prefix(400))
    }

    private static func firstMatch(_ text: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let match = regex.firstMatch(in: text, range: range), match.numberOfRanges > 1,
              let swift = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[swift])
    }
}

// MARK: - TLS / sslscan lite

enum TLSInspector {
    struct Result: Sendable {
        var protocolVersion: String?
        var cipher: String?
        var subject: String?
        var issuer: String?
        var expires: String?
        var sans: [String]
        var selfSigned: Bool
        var supportedVersions: [String]
        var certificateText: String
        var http: HTTPFingerprint.Result?
    }

    static func inspect(host: String, port: UInt16, runHTTP: Bool) async -> Result? {
        guard var result = await performHandshake(host: host, port: port, min: .TLSv12, max: .TLSv13, http: runHTTP) else {
            return nil
        }

        var versions: [String] = []
        if await performHandshake(host: host, port: port, min: .TLSv10, max: .TLSv10, http: false) != nil { versions.append("TLSv1.0") }
        if await performHandshake(host: host, port: port, min: .TLSv11, max: .TLSv11, http: false) != nil { versions.append("TLSv1.1") }
        if await performHandshake(host: host, port: port, min: .TLSv12, max: .TLSv12, http: false) != nil { versions.append("TLSv1.2") }
        if await performHandshake(host: host, port: port, min: .TLSv13, max: .TLSv13, http: false) != nil { versions.append("TLSv1.3") }
        result.supportedVersions = versions
        return result
    }

    private enum TLSBand {
        case TLSv10, TLSv11, TLSv12, TLSv13
    }

    private static func performHandshake(host: String, port: UInt16, min: TLSBand, max: TLSBand, http: Bool) async -> Result? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, tlsVersion(min))
        sec_protocol_options_set_max_tls_protocol_version(tls.securityProtocolOptions, tlsVersion(max))

        let captured = TLSCapture()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { metadata, trustRef, complete in
            captured.ingest(metadata: metadata, trustRef: trustRef)
            complete(true)
        }, DispatchQueue.global(qos: .utility))

        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        let box = ResumeBox()

        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    Task {
                        var result = captured.result()
                        if let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata {
                            let proto = sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata.securityProtocolMetadata)
                            result.protocolVersion = stringifyTLS(proto)
                            let suite = sec_protocol_metadata_get_negotiated_tls_ciphersuite(metadata.securityProtocolMetadata)
                            result.cipher = String(suite.rawValue)
                        }
                        if http {
                            let head = "HEAD / HTTP/1.0\r\nHost: \(host)\r\nConnection: close\r\n\r\n"
                            if let data = await RawTCP.receiveAfterSend(connection: connection, payload: Data(head.utf8), timeout: 0.8) {
                                let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) ?? ""
                                result.http = HTTPFingerprint.parse(text)
                            }
                        }
                        if box.complete() {
                            continuation.resume(returning: result.subject == nil && result.protocolVersion == nil ? result : result)
                        }
                        connection.cancel()
                    }
                case .failed, .cancelled:
                    if box.complete() {
                        continuation.resume(returning: nil)
                    }
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .utility))
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 2.0) {
                if box.complete() {
                    continuation.resume(returning: nil)
                }
                connection.cancel()
            }
        }
    }

    private static func tlsVersion(_ band: TLSBand) -> tls_protocol_version_t {
        switch band {
        case .TLSv10: return .TLSv10
        case .TLSv11: return .TLSv11
        case .TLSv12: return .TLSv12
        case .TLSv13: return .TLSv13
        }
    }

    private static func stringifyTLS(_ value: tls_protocol_version_t) -> String {
        switch value {
        case .TLSv10: return "TLSv1.0"
        case .TLSv11: return "TLSv1.1"
        case .TLSv12: return "TLSv1.2"
        case .TLSv13: return "TLSv1.3"
        case .DTLSv10: return "DTLSv1.0"
        case .DTLSv12: return "DTLSv1.2"
        default: return "TLS"
        }
    }
}

private final class TLSCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var subject: String?
    private var issuer: String?
    private var expires: String?
    private var sans: [String] = []
    private var selfSigned = false
    private var text = ""

    func ingest(metadata: sec_protocol_metadata_t, trustRef: sec_trust_t) {
        let trust = sec_trust_copy_ref(trustRef).takeRetainedValue()
        lock.lock()
        defer { lock.unlock() }
        let count = SecTrustGetCertificateCount(trust)
        guard count > 0, let cert = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = cert.first else { return }
        var error: Unmanaged<CFError>?
        if let values = SecCertificateCopyValues(leaf, nil, &error) as? [CFString: Any] {
            subject = stringValue(values, kSecOIDX509V1SubjectName) ?? subjectSummary(leaf)
            issuer = stringValue(values, kSecOIDX509V1IssuerName)
            expires = stringValue(values, kSecOIDX509V1ValidityNotAfter)
            selfSigned = subject != nil && subject == issuer
        } else {
            subject = subjectSummary(leaf)
        }
        text = [
            subject.map { "Subject: \($0)" },
            issuer.map { "Issuer: \($0)" },
            expires.map { "Not after: \($0)" },
            selfSigned ? "Self-signed: yes" : nil
        ].compactMap { $0 }.joined(separator: "\n")
        _ = metadata
    }

    func result() -> TLSInspector.Result {
        lock.lock(); defer { lock.unlock() }
        return TLSInspector.Result(
            protocolVersion: nil,
            cipher: nil,
            subject: subject,
            issuer: issuer,
            expires: expires,
            sans: sans,
            selfSigned: selfSigned,
            supportedVersions: [],
            certificateText: text.isEmpty ? "TLS handshake succeeded" : text,
            http: nil
        )
    }

    private func subjectSummary(_ cert: SecCertificate) -> String? {
        SecCertificateCopySubjectSummary(cert) as String?
    }

    private func stringValue(_ values: [CFString: Any], _ key: CFString) -> String? {
        guard let entry = values[key] as? [CFString: Any] else { return nil }
        if let value = entry[kSecPropertyKeyValue] as? String { return value }
        if let array = entry[kSecPropertyKeyValue] as? [[CFString: Any]] {
            return array.compactMap { item in
                let label = item[kSecPropertyKeyLabel] as? String
                let value = item[kSecPropertyKeyValue] as? String
                if let label, let value { return "\(label)=\(value)" }
                return value
            }.joined(separator: ", ")
        }
        if let date = entry[kSecPropertyKeyValue] as? Date {
            return ISO8601DateFormatter().string(from: date)
        }
        if let number = entry[kSecPropertyKeyValue] as? NSNumber {
            let date = Date(timeIntervalSinceReferenceDate: number.doubleValue)
            return ISO8601DateFormatter().string(from: date)
        }
        return nil
    }
}

// MARK: - Service probes

enum BannerGrab {
    static func enrich(_ port: OpenPort, send: Data?) async -> OpenPort {
        var next = port
        if let data = await RawTCP.transact(host: port.host, port: port.port, send: send, timeout: 0.8, tls: false) {
            let text = decode(data)
            if next.banner == nil { next.banner = text }
            if let parsed = ServiceVersion.parse(text, port: port.port) {
                next.product = next.product ?? parsed.product
                next.version = next.version ?? parsed.version
            }
        }
        return next
    }

    static func decode(_ data: Data) -> String {
        let text = String(data: data, encoding: .utf8)
            ?? String(data: data, encoding: .isoLatin1)
            ?? ""
        return text
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

enum ServiceVersion {
    static func parse(_ banner: String, port: UInt16) -> (product: String, version: String?)? {
        if let match = match(banner, #"OpenSSH[_\s-]+([0-9][0-9.\w]+)"#) {
            return ("OpenSSH", match)
        }
        if let match = match(banner, #"Dropbear[_\s-]+([0-9.]+)"#) {
            return ("Dropbear", match)
        }
        if let match = match(banner, #"(nginx)/([0-9.]+)"#) {
            return ("nginx", match)
        }
        if let match = match(banner, #"Apache/([0-9.]+)"#) {
            return ("Apache", match)
        }
        if let match = match(banner, #"Microsoft-IIS/([0-9.]+)"#) {
            return ("Microsoft-IIS", match)
        }
        if let match = match(banner, #"OpenSSL/([0-9.]+[a-z]?)"#) {
            return ("OpenSSL", match)
        }
        if banner.lowercased().contains("vsftpd") { return ("vsftpd", match(banner, #"vsftpd\s+([0-9.]+)"#)) }
        if banner.lowercased().contains("proftpd") { return ("ProFTPD", match(banner, #"ProFTPD\s+([0-9.]+)"#)) }
        if banner.uppercased().hasPrefix("SSH-") { return ("SSH", String(banner.prefix(40))) }
        if port == 25 && banner.uppercased().contains("ESMTP") { return ("SMTP", String(banner.prefix(60))) }
        return nil
    }

    private static func match(_ text: String, _ pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let found = regex.firstMatch(in: text, range: range) else { return nil }
        if found.numberOfRanges > 2, let swift = Range(found.range(at: 2), in: text) { return String(text[swift]) }
        if found.numberOfRanges > 1, let swift = Range(found.range(at: 1), in: text) { return String(text[swift]) }
        return nil
    }
}

enum SSHProbe {
    static func enrich(_ port: OpenPort, scripts: Bool) async -> OpenPort {
        var next = await BannerGrab.enrich(port, send: nil)
        if scripts, let banner = next.banner {
            next.scripts.append(ScriptOutput(name: NmapScriptName.sshHostkey, output: banner))
            next.scripts.append(ScriptOutput(name: NmapScriptName.banner, output: banner))
        }
        return next
    }
}

enum FTPProbe {
    static func enrich(_ port: OpenPort, scripts: Bool) async -> OpenPort {
        var next = await BannerGrab.enrich(port, send: Data("SYST\r\nFEAT\r\n".utf8))
        if scripts, let banner = next.banner {
            next.scripts.append(ScriptOutput(name: NmapScriptName.ftpSyst, output: banner))
        }
        return next
    }
}

enum SMTPProbe {
    static func enrich(_ port: OpenPort, scripts: Bool) async -> OpenPort {
        var next = await BannerGrab.enrich(port, send: Data("EHLO sentinel.local\r\n".utf8))
        if scripts, let banner = next.banner {
            next.scripts.append(ScriptOutput(name: NmapScriptName.smtpCommands, output: banner))
        }
        return next
    }
}

enum MySQLProbe {
    static func enrich(_ port: OpenPort) async -> OpenPort {
        var next = port
        guard let data = await RawTCP.transact(host: port.host, port: port.port, send: nil, timeout: 0.9, tls: false),
              data.count > 5 else { return next }
        // Protocol version at byte 4, then NULL-terminated version string.
        let slice = data.dropFirst(5)
        if let end = slice.firstIndex(of: 0) {
            let version = String(bytes: slice[slice.startIndex..<end], encoding: .utf8)
            next.product = "MySQL"
            next.version = version
            next.banner = next.banner ?? version
        }
        return next
    }
}

enum RedisProbe {
    static func enrich(_ port: OpenPort, scripts: Bool) async -> OpenPort {
        var next = port
        guard let data = await RawTCP.transact(host: port.host, port: port.port, send: Data("PING\r\n".utf8), timeout: 0.7, tls: false) else {
            return next
        }
        let text = BannerGrab.decode(data)
        next.banner = text
        if text.contains("PONG") {
            next.product = "Redis"
            next.extraInfo = "unauthenticated PING accepted"
            if scripts {
                next.scripts.append(ScriptOutput(name: NmapScriptName.redisInfo, output: "PING -> \(text)"))
            }
        }
        return next
    }
}

enum MongoProbe {
    static func enrich(_ port: OpenPort, scripts: Bool) async -> OpenPort {
        var next = port
        // OP_QUERY isMaster on admin.$cmd — identification only.
        let payload = mongoIsMaster()
        guard let data = await RawTCP.transact(host: port.host, port: port.port, send: payload, timeout: 0.9, tls: false) else {
            return next
        }
        let text = String(data: data, encoding: .utf8) ?? String(data: data, encoding: .isoLatin1) ?? ""
        next.product = "MongoDB"
        next.banner = next.banner ?? String(text.prefix(120))
        if scripts {
            next.scripts.append(ScriptOutput(name: NmapScriptName.mongodbInfo, output: "hello/isMaster reply \(data.count) bytes"))
        }
        return next
    }

    private static func mongoIsMaster() -> Data {
        // Minimal OP_MSG hello document: { hello: 1 }
        // Fall back to a tiny OP_QUERY header most Mongo versions still accept.
        var body = Data()
        func cstring(_ s: String) { body.append(contentsOf: s.utf8); body.append(0) }
        func int32(_ v: Int32) {
            var le = v.littleEndian
            withUnsafeBytes(of: &le) { body.append(contentsOf: $0) }
        }
        let start = body.count
        int32(0)
        cstring("admin.$cmd")
        int32(0) // skip
        int32(-1) // nreturn
        // BSON { isMaster: 1 }
        let bsonStart = body.count
        int32(0)
        body.append(0x10) // int32
        cstring("isMaster")
        int32(1)
        body.append(0)
        let bsonLen = Int32(body.count - bsonStart)
        body.replaceSubrange(bsonStart..<(bsonStart + 4), with: withUnsafeBytes(of: bsonLen.littleEndian, Array.init))

        var header = Data()
        func hint32(_ v: Int32) {
            var le = v.littleEndian
            withUnsafeBytes(of: &le) { header.append(contentsOf: $0) }
        }
        hint32(0)
        hint32(1)
        hint32(0)
        hint32(2004) // OP_QUERY
        header.append(body)
        let total = Int32(header.count)
        header.replaceSubrange(0..<4, with: withUnsafeBytes(of: total.littleEndian, Array.init))
        _ = start
        return header
    }
}

enum SMBProbe {
    static func enrich(_ port: OpenPort, scripts: Bool) async -> OpenPort {
        var next = port
        guard let data = await RawTCP.transact(host: port.host, port: port.port, send: smb2Negotiate(), timeout: 1.0, tls: false),
              data.count > 8 else { return next }
        next.product = next.product ?? "SMB"
        next.banner = next.banner ?? "SMB dialect negotiate reply \(data.count)B"
        if scripts {
            var lines = ["SMB negotiate reply \(data.count) bytes"]
            if data.count > 40 {
                lines.append("Looks like SMBv2/3 header present")
            }
            next.scripts.append(ScriptOutput(name: NmapScriptName.smbOS, output: lines.joined(separator: "\n")))
        }
        return next
    }

    private static func smb2Negotiate() -> Data {
        // NetBIOS session + SMB2 NEGOTIATE asking for 0x0202 / 0x0210 / 0x0300 / 0x0311
        var smb = Data()
        // SMB2 header 64 bytes
        smb.append(contentsOf: [0xFE, 0x53, 0x4D, 0x42]) // protocol
        smb.append(contentsOf: [0x40, 0x00]) // header length
        smb.append(contentsOf: [UInt8](repeating: 0, count: 6))
        smb.append(contentsOf: [0x00, 0x00]) // command NEGOTIATE
        smb.append(contentsOf: [UInt8](repeating: 0, count: 50))
        // Negotiate request
        smb.append(contentsOf: [0x24, 0x00]) // structure size
        smb.append(contentsOf: [0x04, 0x00]) // dialect count
        smb.append(contentsOf: [0x00, 0x00]) // security mode
        smb.append(contentsOf: [0x00, 0x00])
        smb.append(contentsOf: [UInt8](repeating: 0, count: 4 + 16 + 4 + 4 + 2 + 2))
        smb.append(contentsOf: [0x02, 0x02, 0x10, 0x02, 0x00, 0x03, 0x11, 0x03])
        var packet = Data([0x00, 0x00])
        let length = UInt16(smb.count)
        packet.append(UInt8((length >> 8) & 0xFF))
        packet.append(UInt8(length & 0xFF))
        packet.append(smb)
        return packet
    }
}

enum RDPProbe {
    static func enrich(_ port: OpenPort, scripts: Bool) async -> OpenPort {
        var next = port
        guard let data = await RawTCP.transact(host: port.host, port: port.port, send: x224(), timeout: 1.0, tls: false) else {
            return next
        }
        next.product = next.product ?? "RDP"
        next.banner = next.banner ?? "X.224 reply \(data.count)B"
        if scripts {
            next.scripts.append(ScriptOutput(name: NmapScriptName.rdpInfo, output: "RDP negotiation reply \(data.count) bytes"))
        }
        return next
    }

    private static func x224() -> Data {
        // X.224 Connection Request with RDP negotiation cookie
        Data([
            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b,
            0x00, 0x00, 0x00
        ])
    }
}

enum RawTCP {
    static func transact(host: String, port: UInt16, send: Data?, timeout: TimeInterval, tls: Bool) async -> Data? {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else { return nil }
        let parameters: NWParameters
        if tls {
            let tlsOptions = NWProtocolTLS.Options()
            sec_protocol_options_set_verify_block(tlsOptions.securityProtocolOptions, { _, _, complete in
                complete(true)
            }, DispatchQueue.global(qos: .utility))
            parameters = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        } else {
            parameters = .tcp
        }
        parameters.expiredDNSBehavior = .allow
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        let box = ResumeBox()

        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    Task {
                        let data = await receiveAfterSend(connection: connection, payload: send, timeout: timeout)
                        if box.complete() {
                            continuation.resume(returning: data)
                        }
                        connection.cancel()
                    }
                case .failed, .cancelled:
                    if box.complete() {
                        continuation.resume(returning: nil)
                    }
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .utility))
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout + 0.4) {
                if box.complete() {
                    continuation.resume(returning: nil)
                }
                connection.cancel()
            }
        }
    }

    static func receiveAfterSend(connection: NWConnection, payload: Data?, timeout: TimeInterval) async -> Data? {
        if let payload {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                connection.send(content: payload, completion: .contentProcessed { _ in
                    continuation.resume()
                })
            }
        }
        return await withCheckedContinuation { continuation in
            let box = ResumeBox()
            connection.receive(minimumIncompleteLength: 1, maximumLength: 4096) { data, _, _, _ in
                if box.complete() {
                    continuation.resume(returning: data)
                }
            }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                if box.complete() {
                    continuation.resume(returning: nil)
                }
            }
        }
    }
}
