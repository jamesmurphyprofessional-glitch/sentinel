import Foundation
import AppKit

/// nmap-compatible writers (`-oX`, `-oG`, `-oN`, `-oJ`) plus ndiff-style comparison.
enum NmapExport {
    static func xml(hosts: [DiscoveredHost], snapshot: NetworkSnapshot?, profile: ScanProfile) -> String {
        let start = Int(Date().timeIntervalSince1970)
        var xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE nmaprun>
        <nmaprun scanner="Sentinel" args="\(escape(profile.nmapEquivalent))" start="\(start)" version="2.0.0" xmloutputversion="1.04">
        <scaninfo type="connect" protocol="tcp" numservices="\(profile.ports(customSpec: "").count)"/>
        <verbose level="1"/>
        <debugging level="0"/>

        """
        if let snapshot {
            xml += "<!-- interface \(snapshot.interfaceName) \(snapshot.ipAddress)/\(snapshot.cidr) gateway \(snapshot.gateway ?? "-") -->\n"
        }
        for host in hosts {
            xml += hostXML(host)
        }
        xml += "<runstats><finished time=\"\(Int(Date().timeIntervalSince1970))\" timestr=\"\(ISO8601DateFormatter().string(from: Date()))\" exit=\"success\"/>"
        xml += "<hosts up=\"\(hosts.count)\" down=\"0\" total=\"\(hosts.count)\"/></runstats>\n</nmaprun>\n"
        return xml
    }

    static func greppable(hosts: [DiscoveredHost]) -> String {
        hosts.map { host in
            let name = host.hostname ?? ""
            let ports = host.ports.map { port in
                let extra = [port.product, port.version].compactMap { $0 }.joined(separator: " ")
                return "\(port.port)/\(port.state.label)/\(port.transport.rawValue)//\(port.service)//\(extra)/"
            }.joined(separator: ", ")
            return "Host: \(host.ip) (\(name)) Ports: \(ports) Status: Up"
        }.joined(separator: "\n") + "\n"
    }

    static func normal(hosts: [DiscoveredHost], profile: ScanProfile) -> String {
        var lines = [
            "# Sentinel native nmap-style report",
            "# Equivalent: \(profile.nmapEquivalent)",
            "# \(ISO8601DateFormatter().string(from: Date()))",
            ""
        ]
        for host in hosts {
            lines.append("Nmap scan report for \(host.hostname.map { "\($0) (\(host.ip))" } ?? host.ip)")
            lines.append("Host is up\(host.latencyMS.map { String(format: " (%.2fms latency)", $0) } ?? "").")
            if let mac = host.macAddress {
                lines.append("MAC Address: \(mac)\(host.vendor.map { " (\($0))" } ?? "")")
            }
            if let os = host.osGuess {
                lines.append("OS guess: \(os.summary)")
            }
            if host.ports.isEmpty {
                lines.append("All scanned ports are closed or filtered.")
            } else {
                lines.append("PORT      STATE  SERVICE          VERSION")
                for port in host.ports {
                    let left = "\(port.port)/\(port.transport.rawValue)".padding(toLength: 10, withPad: " ", startingAt: 0)
                    let state = port.state.label.padding(toLength: 7, withPad: " ", startingAt: 0)
                    let service = port.service.padding(toLength: 17, withPad: " ", startingAt: 0)
                    lines.append("\(left)\(state)\(service)\(port.serviceLabel)")
                    for script in port.scripts {
                        lines.append("| \(script.name):")
                        for line in script.output.split(separator: "\n") {
                            lines.append("|   \(line)")
                        }
                    }
                }
            }
            if !host.traceroute.isEmpty {
                lines.append("TRACEROUTE")
                for hop in host.traceroute {
                    let addr = hop.address ?? "*"
                    let rtt = hop.rttMS.map { String(format: "%.2f ms", $0) } ?? ""
                    lines.append("\(hop.ttl) \(addr) \(rtt)")
                }
            }
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }

    static func json(hosts: [DiscoveredHost], findings: [Finding], profile: ScanProfile) -> String {
        let payload: [String: Any] = [
            "scanner": "Sentinel",
            "equivalent": profile.nmapEquivalent,
            "generated": ISO8601DateFormatter().string(from: Date()),
            "hosts": hosts.map { host in
                [
                    "ip": host.ip,
                    "hostname": host.hostname as Any,
                    "mac": host.macAddress as Any,
                    "vendor": host.vendor as Any,
                    "os": host.osGuess?.name as Any,
                    "latency_ms": host.latencyMS as Any,
                    "discovery": host.discoveryMethod as Any,
                    "netbios": host.netbiosName as Any,
                    "ports": host.ports.map { port in
                        [
                            "port": port.port,
                            "proto": port.transport.rawValue,
                            "state": port.state.label,
                            "service": port.service,
                            "product": port.product as Any,
                            "version": port.version as Any,
                            "banner": port.banner as Any,
                            "scripts": port.scripts.map { ["id": $0.name, "output": $0.output] }
                        ] as [String: Any]
                    }
                ] as [String: Any]
            },
            "findings": findings.map { finding in
                [
                    "severity": finding.severity.rawValue,
                    "category": finding.category.rawValue,
                    "title": finding.title,
                    "detail": finding.detail,
                    "host": finding.host as Any
                ] as [String: Any]
            }
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys]),
              let text = String(data: data, encoding: .utf8) else { return "{}" }
        return text
    }

    static func write(_ text: String, name: String) -> URL? {
        let url = ExportStore.supportDirectory.appendingPathComponent(name)
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            return url
        } catch {
            return nil
        }
    }

    static func diff(previous: [DiscoveredHost], current: [DiscoveredHost]) -> ScanDelta {
        let prevHosts = Set(previous.map(\.ip))
        let currHosts = Set(current.map(\.ip))
        let appeared = currHosts.subtracting(prevHosts).sorted()
        let disappeared = prevHosts.subtracting(currHosts).sorted()

        func portKeys(_ hosts: [DiscoveredHost]) -> Set<String> {
            Set(hosts.flatMap { host in
                host.ports.map { "\($0.host):\($0.transport.rawValue)/\($0.port)" }
            })
        }
        let newPorts = portKeys(current).subtracting(portKeys(previous)).sorted()
        let closedPorts = portKeys(previous).subtracting(portKeys(current)).sorted()
        let summary = "ndiff: +\(appeared.count) host(s), -\(disappeared.count) host(s), +\(newPorts.count) port(s), -\(closedPorts.count) port(s)"
        return ScanDelta(
            appearedHosts: appeared,
            disappearedHosts: disappeared,
            newPorts: newPorts,
            closedPorts: closedPorts,
            summary: summary
        )
    }

    private static func hostXML(_ host: DiscoveredHost) -> String {
        var xml = "<host>\n<status state=\"up\" reason=\"\(escape(host.reason ?? host.discoveryMethod ?? "syn-ack"))\"/>\n"
        xml += "<address addr=\"\(host.ip)\" addrtype=\"ipv4\"/>\n"
        if let mac = host.macAddress {
            xml += "<address addr=\"\(mac)\" addrtype=\"mac\" vendor=\"\(escape(host.vendor ?? ""))\"/>\n"
        }
        xml += "<hostnames>\n"
        if let name = host.hostname {
            xml += "<hostname name=\"\(escape(name))\" type=\"PTR\"/>\n"
        }
        xml += "</hostnames>\n<ports>\n"
        for port in host.ports {
            xml += "<port protocol=\"\(port.transport.rawValue)\" portid=\"\(port.port)\">\n"
            xml += "<state state=\"\(port.state.label)\" reason=\"syn-ack\"/>\n"
            xml += "<service name=\"\(escape(port.service))\" product=\"\(escape(port.product ?? ""))\" version=\"\(escape(port.version ?? ""))\" method=\"probed\"/>\n"
            for script in port.scripts {
                xml += "<script id=\"\(escape(script.name))\" output=\"\(escape(script.output))\"/>\n"
            }
            xml += "</port>\n"
        }
        xml += "</ports>\n"
        if let os = host.osGuess {
            xml += "<os><osmatch name=\"\(escape(os.name))\" accuracy=\"\(os.accuracy)\"/></os>\n"
        }
        if !host.traceroute.isEmpty {
            xml += "<trace>\n"
            for hop in host.traceroute {
                xml += "<hop ttl=\"\(hop.ttl)\" ipaddr=\"\(hop.address ?? "*")\" rtt=\"\(hop.rttMS.map { String(format: "%.2f", $0) } ?? "-")\"/>\n"
            }
            xml += "</trace>\n"
        }
        xml += "</host>\n"
        return xml
    }

    private static func escape(_ text: String) -> String {
        text
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
    }
}

enum NmapBinary {
    static func locate() -> String? {
        var candidates: [String] = []
        if let bundled = Bundle.main.resourceURL?
            .appendingPathComponent("nmap/bin/nmap").path {
            candidates.append(bundled)
        }
        candidates.append(contentsOf: [
            "/opt/homebrew/bin/nmap",
            "/usr/local/bin/nmap",
            "/opt/local/bin/nmap",
            "/usr/bin/nmap"
        ])
        if let which = Shell.run("/usr/bin/which", ["nmap"], timeout: 2) {
            let path = which.trimmingCharacters(in: .whitespacesAndNewlines)
            if !path.isEmpty { candidates.append(path) }
        }
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    static func versionLine() -> String {
        guard let binary = locate() else { return "nmap not found" }
        let text = Shell.run(binary, ["--version"], timeout: 4) ?? ""
        return text.split(separator: "\n").first.map(String.init) ?? text
    }

    /// Limited connect-scan + version + safe identification scripts.
    static func scan(target: String, ports: String, timeout: TimeInterval = 70) -> String {
        guard let binary = locate() else {
            return "nmap is not installed. The installer can run: brew install nmap"
        }
        let output = Shell.run(
            binary,
            [
                "-sT", "-Pn", "-n", "-T4",
                "-p", ports,
                "-sV", "--version-light",
                "--script", "banner,http-title,ssl-cert",
                "--host-timeout", "45s",
                target
            ],
            timeout: timeout
        ) ?? ""
        let header = "\(versionLine())\n\(binary)\nnmap -sT -Pn -sV --script=banner,http-title,ssl-cert -p \(ports) \(target)\n\n"
        return header + (output.isEmpty ? "nmap produced no output." : output)
    }

    /// Optional enrichment: run installed nmap on already-live hosts and merge XML.
    static func enrich(hosts: [String], ports: [UInt16]) async -> [DiscoveredHost] {
        guard let binary = locate(), !hosts.isEmpty else { return [] }
        let portList = ports.prefix(200).map(String.init).joined(separator: ",")
        let xmlPath = FileManager.default.temporaryDirectory.appendingPathComponent("sentinel-nmap.xml")
        _ = Shell.run(
            binary,
            [
                "-sT", "-Pn", "-n", "-T4",
                "-p", portList,
                "-sV", "--version-light",
                "--script", "safe,default",
                "--host-timeout", "25s",
                "-oX", xmlPath.path
            ] + Array(hosts.prefix(32)),
            timeout: 90
        )
        guard let data = try? Data(contentsOf: xmlPath) else { return [] }
        return NmapXMLParser.parse(data)
    }
}

enum NmapXMLParser {
    static func parse(_ data: Data) -> [DiscoveredHost] {
        let text = String(data: data, encoding: .utf8) ?? ""
        var hosts: [DiscoveredHost] = []
        let hostBlocks = text.components(separatedBy: "<host ")
        for block in hostBlocks.dropFirst() {
            let chunk = "<host " + block
            guard let ip = first(chunk, pattern: #"addr="(\d+\.\d+\.\d+\.\d+)" addrtype="ipv4""#) else { continue }
            let hostname = first(chunk, pattern: #"hostname name="([^"]+)""#)
            let mac = first(chunk, pattern: #"addr="([0-9A-Fa-f:]+)" addrtype="mac""#)
            let vendor = first(chunk, pattern: #"addrtype="mac" vendor="([^"]*)""#)
            let os = first(chunk, pattern: #"osmatch name="([^"]+)" accuracy="(\d+)""#)
            let accuracy = Int(first(chunk, pattern: #"osmatch name="[^"]+" accuracy="(\d+)""#) ?? "") ?? 0
            var ports: [OpenPort] = []
            let portRegex = try? NSRegularExpression(pattern: #"<port protocol="(tcp|udp)" portid="(\d+)">[\s\S]*?<state state="([^"]+)"[\s\S]*?(?:<service name="([^"]*)"[^>]*product="([^"]*)"[^>]*version="([^"]*)")?"#)
            let ns = chunk as NSString
            portRegex?.enumerateMatches(in: chunk, range: NSRange(location: 0, length: ns.length)) { match, _, _ in
                guard let match, match.numberOfRanges >= 4 else { return }
                let proto = ns.substring(with: match.range(at: 1))
                let port = UInt16(ns.substring(with: match.range(at: 2))) ?? 0
                let state = ns.substring(with: match.range(at: 3))
                let service = match.numberOfRanges > 4 && match.range(at: 4).location != NSNotFound ? ns.substring(with: match.range(at: 4)) : "unknown"
                let product = match.numberOfRanges > 5 && match.range(at: 5).location != NSNotFound ? ns.substring(with: match.range(at: 5)) : nil
                let version = match.numberOfRanges > 6 && match.range(at: 6).location != NSNotFound ? ns.substring(with: match.range(at: 6)) : nil
                guard state.contains("open"), port > 0 else { return }
                let profile = PortCatalog.profile(for: port)
                ports.append(
                    OpenPort(
                        host: ip,
                        port: port,
                        service: service.isEmpty ? profile.service : service,
                        risk: profile.risk,
                        banner: [product, version].compactMap { $0 }.joined(separator: " "),
                        reason: "Imported from nmap XML",
                        transport: proto == "udp" ? .udp : .tcp,
                        state: .open,
                        product: product?.isEmpty == true ? nil : product,
                        version: version?.isEmpty == true ? nil : version
                    )
                )
            }
            hosts.append(
                DiscoveredHost(
                    ip: ip,
                    hostname: hostname,
                    ports: ports,
                    bonjourNames: [],
                    isLocalMachine: false,
                    macAddress: mac.map(MACVendors.normalize),
                    vendor: vendor?.isEmpty == true ? mac.flatMap { MACVendors.vendor(for: $0) } : vendor,
                    osGuess: os.map { OSGuess(name: $0, accuracy: accuracy, evidence: ["nmap -O / osmatch"]) }
                )
            )
        }
        return hosts
    }

    private static func first(_ text: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let match = regex.firstMatch(in: text, range: range), match.numberOfRanges > 1,
              let swift = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[swift])
    }
}

enum ScanFileExport {
    static func reveal(_ url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}
