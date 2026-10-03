import Foundation
import Network

/// Host discovery inspired by nmap `-sn` / `-PE` / `-PS` / ARP ping, plus
/// arp-scan / netdiscover (ARP cache) and nbtscan (NetBIOS names).
actor DiscoveryEngine {
    func discover(
        snapshot: NetworkSnapshot,
        profile: ScanProfile,
        progress: @escaping @Sendable (ScanProgress) -> Void
    ) async -> [HostHint] {
        var hints: [String: HostHint] = [:]

        func upsert(_ ip: String, method: String, mutate: (inout HostHint) -> Void = { _ in }) {
            var hint = hints[ip] ?? HostHint(ip: ip, method: method)
            if !hint.method.contains(method) {
                hint.method = hint.method == method ? method : "\(hint.method), \(method)"
            }
            mutate(&hint)
            hints[ip] = hint
        }

        upsert(snapshot.ipAddress, method: "local-interface") { hint in
            hint.hostname = "this-mac"
        }
        if let gateway = snapshot.gateway {
            upsert(gateway, method: "default-route")
        }

        if profile.arpDiscovery {
            progress(ScanProgress(phase: "Nearby devices", completed: 0, total: 1, statusLine: "Seeing who this Mac already knows on the network"))
            for entry in ARPTable.entries() {
                upsert(entry.ip, method: "arp-cache") { hint in
                    hint.mac = entry.mac
                    hint.vendor = entry.vendor
                }
            }
        }

        let targets = snapshot.hosts
        if profile.icmpPing {
            let results = await ICMPPing.sweep(hosts: targets, timeoutMS: 800) { done, total in
                progress(ScanProgress(
                    phase: "ICMP ping",
                    completed: done,
                    total: total,
                    statusLine: "Pinging devices \(done)/\(total)"
                ))
            }
            for result in results {
                upsert(result.ip, method: "icmp-echo") { hint in
                    hint.latencyMS = result.latencyMS
                    hint.ttl = result.ttl
                }
            }
        }

        if profile.tcpPing {
            let pingPorts: [UInt16] = [80, 443, 22, 445, 139, 135, 3389, 62078]
            let total = targets.count
            var completed = 0
            await withTaskGroup(of: (String, TimeInterval)?.self) { group in
                var iterator = targets.makeIterator()
                var inFlight = 0
                let cap = min(profile.timing.maxInFlight, 80)

                func enqueue(_ ip: String) {
                    inFlight += 1
                    group.addTask {
                        let start = Date()
                        for port in pingPorts {
                            if await TCPProbe.isOpen(host: ip, port: port, timeout: profile.timing.connectTimeout) {
                                return (ip, Date().timeIntervalSince(start) * 1000)
                            }
                        }
                        return nil
                    }
                }

                while inFlight < cap, let next = iterator.next() { enqueue(next) }
                for await result in group {
                    inFlight -= 1
                    completed += 1
                    if let result {
                        upsert(result.0, method: "tcp-synack") { hint in
                            if hint.latencyMS == nil { hint.latencyMS = result.1 }
                        }
                    }
                    if completed == 1 || completed % 20 == 0 || completed == total {
                        progress(ScanProgress(
                            phase: "TCP ping",
                            completed: completed,
                            total: total,
                            statusLine: "Checking devices \(completed)/\(total)"
                        ))
                    }
                    if let next = iterator.next() { enqueue(next) }
                }
            }
        }

        if profile.netbiosDiscovery {
            progress(ScanProgress(phase: "Names", completed: 0, total: 1, statusLine: "Asking devices for their names"))
            let sample = Array(Set(hints.keys + [snapshot.ipAddress, snapshot.gateway].compactMap { $0 })).sorted()
            let names = await NetBIOSProbe.query(hosts: sample)
            for (ip, name) in names {
                upsert(ip, method: "netbios-ns") { hint in
                    hint.netbiosName = name.name
                    hint.workgroup = name.workgroup
                    if hint.hostname == nil { hint.hostname = name.name }
                }
            }
        }

        if profile.arpDiscovery {
            for entry in ARPTable.entries() {
                upsert(entry.ip, method: "arp-cache") { hint in
                    if hint.mac == nil { hint.mac = entry.mac }
                    if hint.vendor == nil { hint.vendor = entry.vendor }
                }
            }
        }

        if profile.reverseDNS {
            let ips = Array(hints.keys)
            for (index, ip) in ips.enumerated() {
                if let name = NetworkInfo.reverseName(for: ip) {
                    upsert(ip, method: hints[ip]?.method ?? "ptr") { hint in
                        if hint.hostname == nil { hint.hostname = name }
                    }
                }
                if index % 25 == 0 {
                    progress(ScanProgress(
                        phase: "Reverse DNS",
                        completed: index,
                        total: ips.count,
                        statusLine: "Looking up names \(index)/\(ips.count)"
                    ))
                }
            }
        }

        return hints.values.sorted { NetworkInfo.ipv4Value($0.ip) < NetworkInfo.ipv4Value($1.ip) }
    }
}

enum ICMPPing {
    struct Result: Sendable {
        let ip: String
        let latencyMS: Double
        let ttl: Int?
    }

    static func sweep(
        hosts: [String],
        timeoutMS: Int,
        progress: @escaping @Sendable (Int, Int) -> Void
    ) async -> [Result] {
        var results: [Result] = []
        let total = hosts.count
        var completed = 0

        await withTaskGroup(of: Result?.self) { group in
            var iterator = hosts.makeIterator()
            var inFlight = 0
            let cap = 28

            func enqueue(_ ip: String) {
                inFlight += 1
                group.addTask {
                    ping(host: ip, timeoutMS: timeoutMS)
                }
            }

            while inFlight < cap, let next = iterator.next() { enqueue(next) }
            for await result in group {
                inFlight -= 1
                completed += 1
                if let result { results.append(result) }
                if completed == 1 || completed % 16 == 0 || completed == total {
                    progress(completed, total)
                }
                if let next = iterator.next() { enqueue(next) }
            }
        }
        return results
    }

    static func ping(host: String, timeoutMS: Int) -> Result? {
        let output = Shell.run("/sbin/ping", ["-c", "1", "-W", "\(timeoutMS)", "-t", "2", "-n", host], timeout: 3) ?? ""
        guard output.contains("bytes from") || output.contains("icmp_seq") else { return nil }
        let ttl = firstMatch(output, pattern: "ttl=(\\d+)")
            .flatMap { Int($0) }
        let time = firstMatch(output, pattern: "time=([0-9.]+)")
            .flatMap { Double($0) }
        return Result(ip: host, latencyMS: time ?? 0, ttl: ttl)
    }

    private static func firstMatch(_ text: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: .caseInsensitive) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let match = regex.firstMatch(in: text, options: [], range: range), match.numberOfRanges > 1,
              let swiftRange = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[swiftRange])
    }
}

enum ARPTable {
    struct Entry: Sendable {
        let ip: String
        let mac: String
        let vendor: String?
    }

    static func entries() -> [Entry] {
        let output = Shell.run("/usr/sbin/arp", ["-an"], timeout: 4) ?? ""
        var results: [Entry] = []
        // ? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
        let regex = try? NSRegularExpression(pattern: #"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)"#)
        let ns = output as NSString
        regex?.enumerateMatches(in: output, range: NSRange(location: 0, length: ns.length)) { match, _, _ in
            guard let match, match.numberOfRanges >= 3 else { return }
            let ip = ns.substring(with: match.range(at: 1))
            let mac = MACVendors.normalize(ns.substring(with: match.range(at: 2)))
            guard !mac.contains("FF:FF:FF"), mac != "INCOMPLETE", !mac.lowercased().contains("incomplete") else { return }
            results.append(Entry(ip: ip, mac: mac, vendor: MACVendors.vendor(for: mac)))
        }
        return results
    }
}

enum NetBIOSProbe {
    struct Name: Sendable {
        let name: String
        let workgroup: String?
    }

    static func query(hosts: [String]) async -> [String: Name] {
        var map: [String: Name] = [:]
        await withTaskGroup(of: (String, Name)?.self) { group in
            for host in hosts {
                group.addTask {
                    if let name = await nbstat(host: host) {
                        return (host, name)
                    }
                    return nil
                }
            }
            for await result in group {
                if let result { map[result.0] = result.1 }
            }
        }
        return map
    }

    /// nmap `nbstat` / nbtscan wildcard name query on UDP/137.
    static func nbstat(host: String) async -> Name? {
        let packet = nbstatQuery()
        guard let data = await UDPProbe.send(host: host, port: 137, payload: packet, timeout: 0.8), data.count > 56 else {
            return nil
        }
        return parseNBSTAT(data)
    }

    private static func nbstatQuery() -> Data {
        var bytes: [UInt8] = [
            0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20
        ]
        // First-level encoded "*" (space-padded) + NUL suffix type 0x00
        let encoded = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        bytes.append(contentsOf: encoded.utf8)
        bytes.append(contentsOf: [0x00, 0x00, 0x21, 0x00, 0x01])
        return Data(bytes)
    }

    private static func parseNBSTAT(_ data: Data) -> Name? {
        // Names start after a variable header; search for printable 15-char NetBIOS names.
        var names: [(String, UInt8)] = []
        let bytes = [UInt8](data)
        var index = 57
        while index + 18 <= bytes.count {
            let slice = bytes[index..<(index + 15)]
            if let raw = String(bytes: slice, encoding: .ascii) {
                let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                    .trimmingCharacters(in: CharacterSet(charactersIn: "\0"))
                let suffix = bytes[index + 15]
                if trimmed.count >= 2, trimmed.unicodeScalars.allSatisfy({ CharacterSet.alphanumerics.union(.whitespaces).union(CharacterSet(charactersIn: "-_")).contains($0) }) {
                    names.append((trimmed, suffix))
                }
            }
            index += 18
            if names.count > 8 { break }
        }
        let workstation = names.first(where: { $0.1 == 0x00 })?.0 ?? names.first?.0
        let workgroup = names.first(where: { $0.1 == 0x00 && $0.0 != workstation })?.0
            ?? names.first(where: { $0.1 == 0x1E || $0.1 == 0x1D })?.0
        guard let workstation else { return nil }
        return Name(name: workstation, workgroup: workgroup)
    }
}

enum PathTracer {
    static func trace(host: String, maxHops: Int = 12) async -> [TraceHop] {
        let output = Shell.run(
            "/usr/sbin/traceroute",
            ["-n", "-I", "-w", "1", "-q", "1", "-m", "\(maxHops)", host],
            timeout: 18
        ) ?? ""
        var hops: [TraceHop] = []
        for line in output.split(separator: "\n") {
            let text = String(line)
            guard let hopMatch = firstMatch(text, pattern: #"^\s*(\d+)"#), let ttl = Int(hopMatch) else { continue }
            if text.contains("*") && !text.contains(".") {
                hops.append(TraceHop(ttl: ttl, address: nil, hostname: nil, rttMS: nil))
                continue
            }
            let ip = firstMatch(text, pattern: #"(\d+\.\d+\.\d+\.\d+)"#)
            let rtt = firstMatch(text, pattern: #"([0-9.]+)\s*ms"#).flatMap { Double($0) }
            hops.append(TraceHop(ttl: ttl, address: ip, hostname: nil, rttMS: rtt))
        }
        return hops
    }

    private static func firstMatch(_ text: String, pattern: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return nil }
        let range = NSRange(text.startIndex..., in: text)
        guard let match = regex.firstMatch(in: text, range: range), match.numberOfRanges > 1,
              let swift = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[swift])
    }
}

enum OSFingerprint {
    /// Passive / banner / TTL guess modelled on nmap `-O` lite + p0f-style TTL buckets.
    static func guess(host: DiscoveredHost) -> OSGuess? {
        var evidence: [String] = []
        var scores: [String: Int] = [:]

        func add(_ name: String, _ points: Int, _ why: String) {
            scores[name, default: 0] += points
            evidence.append(why)
        }

        if let ttl = host.ttl {
            if ttl <= 64 {
                add("Linux / Unix / macOS", 40, "TTL \(ttl) (common initial TTL 64)")
            } else if ttl <= 128 {
                add("Windows", 45, "TTL \(ttl) (common initial TTL 128)")
            } else {
                add("Network OS / appliance", 35, "TTL \(ttl) (common initial TTL 255)")
            }
        }

        if let vendor = host.vendor {
            if vendor.contains("Apple") { add("Apple macOS / iOS / tvOS", 35, "MAC vendor \(vendor)") }
            else if vendor.contains("Cisco") || vendor.contains("MikroTik") || vendor.contains("Ubiquiti") {
                add("Network OS (\(vendor))", 40, "MAC vendor \(vendor)")
            } else if vendor.contains("Microsoft") || vendor.contains("Hyper-V") {
                add("Windows", 25, "MAC vendor \(vendor)")
            } else if vendor.contains("Raspberry") { add("Linux (Raspberry Pi)", 40, "MAC vendor \(vendor)") }
            else if vendor.contains("Espressif") { add("Embedded / IoT (ESP)", 40, "MAC vendor \(vendor)") }
            else { evidence.append("MAC vendor \(vendor)") }
        }

        for port in host.ports {
            let blob = ([port.banner, port.product, port.version, port.service].compactMap { $0 }).joined(separator: " ").lowercased()
            if blob.contains("openssh") { add("Linux / Unix / macOS", 20, "OpenSSH banner") }
            if blob.contains("dropbear") { add("Embedded Linux", 30, "Dropbear SSH") }
            if blob.contains("microsoft") || blob.contains("iis") || blob.contains("winrm") || blob.contains("rdp") {
                add("Windows", 30, "Microsoft service fingerprint")
            }
            if blob.contains("cisco") || blob.contains("ios") { add("Cisco IOS", 40, "Cisco banner") }
            if blob.contains("mikrotik") || blob.contains("routeros") { add("MikroTik RouterOS", 45, "MikroTik banner") }
            if blob.contains("synology") || blob.contains("diskstation") { add("Synology DSM (Linux)", 40, "NAS banner") }
            if blob.contains("ubuntu") { add("Ubuntu Linux", 40, "Ubuntu banner") }
            if blob.contains("debian") { add("Debian Linux", 40, "Debian banner") }
            if blob.contains("apple") || blob.contains("macos") || blob.contains("darwin") {
                add("Apple macOS / iOS", 35, "Apple service string")
            }
            if port.port == 62078 { add("Apple iOS / iPadOS / macOS", 30, "lockdownd / 62078") }
            if port.port == 548 { add("Apple macOS", 20, "AFP") }
            if port.port == 3389 || port.port == 5985 || port.port == 445 { add("Windows", 15, "Windows management port \(port.port)") }
        }

        if let nb = host.netbiosName { evidence.append("NetBIOS name \(nb)") }
        if let wg = host.workgroup { add("Windows / Samba", 10, "Workgroup \(wg)") }

        guard let best = scores.max(by: { $0.value < $1.value }) else {
            if evidence.isEmpty { return nil }
            return OSGuess(name: "Unknown", accuracy: 20, evidence: evidence)
        }
        let accuracy = min(95, 40 + best.value)
        return OSGuess(name: best.key, accuracy: accuracy, evidence: evidence)
    }
}
