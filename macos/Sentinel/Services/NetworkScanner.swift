import Foundation
import Network

/// Unauthenticated TCP connect-scan and banner identification.
/// Does not attempt logins, default credentials, or exploit payloads.
actor NetworkScanner {
    private let discovery = DiscoveryEngine()
    private let probes = ProbeEngine()

    func discoverHosts(
        snapshot: NetworkSnapshot,
        profile: ScanProfile,
        progress: @escaping @Sendable (ScanProgress) -> Void
    ) async -> [HostHint] {
        if profile.skipHostDiscovery {
            return snapshot.hosts.map { HostHint(ip: $0, method: "skipped (-Pn)") }
        }
        var hints = await discovery.discover(snapshot: snapshot, profile: profile, progress: progress)
        if hints.isEmpty {
            hints = [
                HostHint(ip: snapshot.ipAddress, method: "local-interface"),
            ]
            if let gateway = snapshot.gateway {
                hints.append(HostHint(ip: gateway, method: "default-route"))
            }
        }
        return hints
    }

    func scanPorts(
        hints: [HostHint],
        ports: [UInt16],
        localIP: String,
        profile: ScanProfile,
        progress: @escaping @Sendable (ScanProgress) -> Void
    ) async -> [DiscoveredHost] {
        if profile.name == ScanProfile.pingSweep.name {
            return hints.map { hint in
                host(from: hint, ports: [], localIP: localIP)
            }
        }

        let hosts = hints.map(\.ip)
        let openPairs = await sweep(hosts: hosts, ports: ports, profile: profile, progress: progress)

        var grouped: [String: [OpenPort]] = [:]
        for pair in openPairs {
            let catalog = PortCatalog.profile(for: pair.port)
            grouped[pair.host, default: []].append(
                OpenPort(
                    host: pair.host,
                    port: pair.port,
                    service: catalog.service,
                    risk: catalog.risk,
                    banner: pair.banner,
                    reason: catalog.reason,
                    transport: .tcp,
                    state: .open
                )
            )
        }

        var discovered = hints.map { hint in
            let ports = (grouped[hint.ip] ?? []).sorted { $0.port < $1.port }
            return host(from: hint, ports: ports, localIP: localIP)
        }

        if profile.versionDetect || profile.scriptScan || profile.udpScan || profile.osDetect || profile.traceroute {
            discovered = await probes.enrich(hosts: discovered, profile: profile, progress: progress)
        }

        return discovered
    }

    private struct Pair: Sendable {
        let host: String
        let port: UInt16
        let banner: String?
    }

    private func sweep(
        hosts: [String],
        ports: [UInt16],
        profile: ScanProfile,
        progress: @escaping @Sendable (ScanProgress) -> Void
    ) async -> [Pair] {
        let jobs: [(String, UInt16)] = hosts.flatMap { host in ports.map { (host, $0) } }
        let total = jobs.count
        var completed = 0
        var hits: [Pair] = []
        let timeout = profile.timing.connectTimeout
        let identify = profile.twoPhaseSweep == false
        let cap = profile.timing.maxInFlight

        await withTaskGroup(of: Pair?.self) { group in
            var iterator = jobs.makeIterator()
            var inFlight = 0

            func enqueue(_ host: String, _ port: UInt16) {
                inFlight += 1
                group.addTask {
                    if identify {
                        let catalog = PortCatalog.profile(for: port)
                        let result = await TCPProbe.identify(
                            host: host,
                            port: port,
                            timeout: timeout,
                            probe: catalog.identificationProbe
                        )
                        guard result.open else { return nil }
                        return Pair(host: host, port: port, banner: result.banner)
                    }
                    let open = await TCPProbe.isOpen(host: host, port: port, timeout: timeout)
                    return open ? Pair(host: host, port: port, banner: nil) : nil
                }
            }

            while inFlight < cap, let next = iterator.next() {
                enqueue(next.0, next.1)
            }

            for await hit in group {
                inFlight -= 1
                completed += 1
                if let hit { hits.append(hit) }
                if completed == 1 || completed % 80 == 0 || completed == total {
                    progress(ScanProgress(
                        phase: "TCP connect",
                        completed: completed,
                        total: total,
                        statusLine: "Checking sharing and remote access \(completed)/\(total)"
                    ))
                }
                if let next = iterator.next() {
                    enqueue(next.0, next.1)
                }
            }
        }

        return hits
    }

    private func host(from hint: HostHint, ports: [OpenPort], localIP: String) -> DiscoveredHost {
        DiscoveredHost(
            ip: hint.ip,
            hostname: hint.hostname ?? NetworkInfo.reverseName(for: hint.ip),
            ports: ports,
            bonjourNames: [],
            isLocalMachine: hint.ip == localIP,
            macAddress: hint.mac,
            vendor: hint.vendor ?? hint.mac.flatMap { MACVendors.vendor(for: $0) },
            latencyMS: hint.latencyMS,
            ttl: hint.ttl,
            discoveryMethod: hint.method,
            netbiosName: hint.netbiosName,
            workgroup: hint.workgroup,
            reason: hint.method
        )
    }

    static func findings(from hosts: [DiscoveredHost], snapshot: NetworkSnapshot, profile: ScanProfile) -> [Finding] {
        _ = profile
        var findings: [Finding] = []
        let wifiName = snapshot.ssid.map { "your Wi-Fi “\($0)”" } ?? "this network"
        let live = hosts.filter { !$0.ports.isEmpty || $0.isLocalMachine || $0.macAddress != nil || $0.latencyMS != nil }

        findings.append(
            Finding(
                category: .network,
                severity: .info,
                title: "We found \(live.count) device\(live.count == 1 ? "" : "s") on \(wifiName)",
                detail: live.map { host in
                    let kind = DeviceGuide.kind(host, gateway: snapshot.gateway)
                    let name = host.hostname.map { " (\($0))" } ?? ""
                    return "\(kind): \(host.ip)\(name)"
                }.joined(separator: "\n"),
                remediation: "If a device is a mystery, it may be a guest phone, a smart gadget, or something to unplug. Compare the list with what you own."
            )
        )

        for host in hosts {
            let kind = DeviceGuide.kind(host, gateway: snapshot.gateway)
            let who = host.hostname.map { "\($0) (\(host.ip))" } ?? "\(kind) at \(host.ip)"
            for port in host.ports {
                let guide = PortCatalog.homeGuide(for: port.port, onThisMac: host.isLocalMachine)
                let category: FindingCategory = {
                    if Self.remoteAccessPorts.contains(port.port) { return .remoteAccess }
                    return .network
                }()
                findings.append(
                    Finding(
                        category: category,
                        severity: port.risk,
                        title: "\(guide.headline) — \(who)",
                        detail: guide.meaning,
                        remediation: guide.fix,
                        host: host.ip,
                        evidence: "\(port.transport.rawValue)/\(port.port) \(port.serviceLabel)"
                    )
                )
            }
        }

        if let gateway = snapshot.gateway,
           let gwHost = hosts.first(where: { $0.ip == gateway }) {
            let adminPorts = gwHost.ports.filter { [80, 443, 8080, 8443, 22, 23, 8291, 161].contains($0.port) }
            if !adminPorts.isEmpty {
                findings.append(
                    Finding(
                        category: .network,
                        severity: .medium,
                        title: "Your router has a settings page on the Wi-Fi",
                        detail: "That is normal. The risk is a leftover default password (admin / admin, or the one printed on the sticker).",
                        remediation: "Open a browser to \(gateway), sign in, change the admin password, turn off remote management, and check for a firmware update.",
                        host: gateway
                    )
                )
            }
        }

        return findings
    }

    private static let remoteAccessPorts: Set<UInt16> = [
        22, 23, 2323, 2222, 3389, 5900, 5901, 5902, 3283,
        5985, 5986, 2375, 5555, 5938, 4899, 623, 16992, 16993
    ]
}

enum TCPProbe {
    struct Result: Sendable {
        let open: Bool
        let banner: String?
    }

    static func isOpen(host: String, port: UInt16, timeout: TimeInterval) async -> Bool {
        await identify(host: host, port: port, timeout: timeout, probe: .bannerOnly).open
    }

    static func identify(
        host: String,
        port: UInt16,
        timeout: TimeInterval,
        probe: IdentificationProbe
    ) async -> Result {
        guard let nwPort = NWEndpoint.Port(rawValue: port) else {
            return Result(open: false, banner: nil)
        }

        let parameters = NWParameters.tcp
        parameters.expiredDNSBehavior = .allow
        parameters.serviceClass = .responsiveData
        if let tcp = parameters.defaultProtocolStack.transportProtocol as? NWProtocolTCP.Options {
            tcp.enableKeepalive = false
            tcp.connectionTimeout = 1
        }

        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: parameters)
        let box = ResumeBox()

        return await withCheckedContinuation { continuation in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    Task {
                        let banner = await readIdentification(connection: connection, probe: probe)
                        if box.complete() {
                            continuation.resume(returning: Result(open: true, banner: banner))
                        }
                        connection.cancel()
                    }
                case .failed, .cancelled:
                    if box.complete() {
                        continuation.resume(returning: Result(open: false, banner: nil))
                    }
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .utility))

            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                if box.complete() {
                    continuation.resume(returning: Result(open: false, banner: nil))
                }
                connection.cancel()
            }
        }
    }

    /// Read a service greeting, or send a harmless HTTP HEAD for web ports.
    /// Never sends exploit payloads, malformed overflows, or credentials.
    private static func readIdentification(connection: NWConnection, probe: IdentificationProbe) async -> String? {
        if case .httpHead = probe {
            let head = "HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: Sentinel-Identifier\r\nConnection: close\r\n\r\n"
            await send(connection: connection, data: Data(head.utf8))
        }

        return await withCheckedContinuation { continuation in
            let box = ResumeBox()
            connection.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, _ in
                let text = data.flatMap { String(data: $0, encoding: .utf8) }
                    ?? data.flatMap { String(data: $0, encoding: .isoLatin1) }
                let cleaned = text?
                    .replacingOccurrences(of: "\r", with: " ")
                    .replacingOccurrences(of: "\n", with: " ")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if box.complete() {
                    continuation.resume(returning: cleaned?.isEmpty == false ? cleaned : nil)
                }
            }
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 0.25) {
                if box.complete() {
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    private static func send(connection: NWConnection, data: Data) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            connection.send(content: data, completion: .contentProcessed { _ in
                continuation.resume()
            })
        }
    }
}

final class ResumeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false

    func complete() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}
