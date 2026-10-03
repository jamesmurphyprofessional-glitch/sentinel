import Foundation

enum SignatureStore {
    static var supportDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let dir = base.appendingPathComponent("Sentinel", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    static var databaseURL: URL {
        supportDirectory.appendingPathComponent("signatures.json")
    }

    static func load() -> SignatureDatabase {
        var db = loadSeed()
        if let data = try? Data(contentsOf: databaseURL),
           let stored = try? JSONDecoder().decode(SignatureDatabase.self, from: data) {
            db.merge(stored)
        }
        return db
    }

    static func save(_ database: SignatureDatabase) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(database)
        try data.write(to: databaseURL, options: .atomic)
    }

    static func loadSeed() -> SignatureDatabase {
        let bundleCandidates = [
            Bundle.main.url(forResource: "seed_signatures", withExtension: "json"),
            Bundle.main.resourceURL?.appendingPathComponent("seed_signatures.json")
        ].compactMap { $0 }

        for url in bundleCandidates {
            if let data = try? Data(contentsOf: url),
               let seed = try? JSONDecoder().decode(SeedFile.self, from: data) {
                return SignatureDatabase(
                    hashesSHA256: Set(seed.hashesSHA256.map { $0.lowercased() }),
                    filenames: Set(seed.filenames.map { $0.lowercased() }),
                    pathFragments: Set(seed.pathFragments.map { $0.lowercased() }),
                    bundleIds: Set(seed.bundleIds.map { $0.lowercased() }),
                    launchLabels: Set(seed.launchLabels.map { $0.lowercased() }),
                    sources: ["bundled seed (public macOS malware / PUP indicators)"],
                    lastUpdated: nil
                )
            }
        }
        return .empty
    }
}

actor SignatureUpdater {
    struct SourceResult: Sendable {
        let name: String
        let addedHashes: Int
        let note: String
        let succeeded: Bool
    }

    func update(existing: SignatureDatabase) async -> (SignatureDatabase, [SourceResult]) {
        var db = existing
        var results: [SourceResult] = []

        let bazaar = await fetchMalwareBazaarRecent()
        results.append(bazaar.result)
        db.merge(bazaar.delta)

        let macOS = await fetchMalwareBazaarTag("MacOS")
        results.append(macOS.result)
        db.merge(macOS.delta)

        let osx = await fetchMalwareBazaarTag("osx")
        results.append(osx.result)
        db.merge(osx.delta)

        let threatfox = await fetchThreatFoxRecent()
        results.append(threatfox.result)
        db.merge(threatfox.delta)

        let urlhaus = await fetchURLHausRecent()
        results.append(urlhaus.result)
        db.merge(urlhaus.delta)

        db.lastUpdated = Date()
        if !db.sources.contains("public feeds (abuse.ch)") {
            db.sources.append("public feeds (abuse.ch)")
        }
        try? SignatureStore.save(db)
        return (db, results)
    }

    // MARK: MalwareBazaar

    private func fetchMalwareBazaarRecent() async -> (delta: SignatureDatabase, result: SourceResult) {
        let url = URL(string: "https://bazaar.abuse.ch/export/txt/sha256/recent/")!
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            try throwIfBad(response)
            let text = String(data: data, encoding: .utf8) ?? ""
            let hashes = parseHashList(text)
            var delta = SignatureDatabase.empty
            delta.hashesSHA256 = hashes
            delta.sources = ["MalwareBazaar recent SHA-256"]
            return (
                delta,
                SourceResult(
                    name: "MalwareBazaar recent SHA-256",
                    addedHashes: hashes.count,
                    note: "Free daily hash export from bazaar.abuse.ch",
                    succeeded: true
                )
            )
        } catch {
            return (
                .empty,
                SourceResult(
                    name: "MalwareBazaar recent SHA-256",
                    addedHashes: 0,
                    note: error.localizedDescription,
                    succeeded: false
                )
            )
        }
    }

    private func fetchMalwareBazaarTag(_ tag: String) async -> (delta: SignatureDatabase, result: SourceResult) {
        let url = URL(string: "https://mb-api.abuse.ch/api/v1/")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = "query=get_taginfo&tag=\(tag)&limit=1000".data(using: .utf8)
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            try throwIfBad(response)
            guard
                let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                let list = json["data"] as? [[String: Any]]
            else {
                throw SentinelError.updateFailed("Unexpected MalwareBazaar API payload for tag \(tag)")
            }
            var hashes = Set<String>()
            var names = Set<String>()
            for item in list {
                if let sha = item["sha256_hash"] as? String {
                    hashes.insert(sha.lowercased())
                }
                if let name = item["file_name"] as? String, !name.isEmpty, name != "unknown" {
                    names.insert(name.lowercased())
                }
            }
            var delta = SignatureDatabase.empty
            delta.hashesSHA256 = hashes
            delta.filenames = names
            delta.sources = ["MalwareBazaar tag:\(tag)"]
            return (
                delta,
                SourceResult(
                    name: "MalwareBazaar tag \(tag)",
                    addedHashes: hashes.count,
                    note: "\(names.count) filenames for macOS-related samples",
                    succeeded: true
                )
            )
        } catch {
            return (
                .empty,
                SourceResult(
                    name: "MalwareBazaar tag \(tag)",
                    addedHashes: 0,
                    note: error.localizedDescription,
                    succeeded: false
                )
            )
        }
    }

    // MARK: ThreatFox

    private func fetchThreatFoxRecent() async -> (delta: SignatureDatabase, result: SourceResult) {
        let url = URL(string: "https://threatfox-api.abuse.ch/api/v1/")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try? JSONSerialization.data(withJSONObject: [
            "query": "get_iocs",
            "days": 7
        ])
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            try throwIfBad(response)
            guard
                let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                let list = json["data"] as? [[String: Any]]
            else {
                throw SentinelError.updateFailed("Unexpected ThreatFox payload")
            }
            var hashes = Set<String>()
            for item in list {
                let type = (item["ioc_type"] as? String ?? "").lowercased()
                let ioc = (item["ioc"] as? String ?? "").lowercased()
                if type.contains("sha256") && ioc.count == 64 {
                    hashes.insert(ioc)
                }
            }
            var delta = SignatureDatabase.empty
            delta.hashesSHA256 = hashes
            delta.sources = ["ThreatFox recent IOCs"]
            return (
                delta,
                SourceResult(
                    name: "ThreatFox (7-day IOCs)",
                    addedHashes: hashes.count,
                    note: "SHA-256 indicators from threatfox.abuse.ch",
                    succeeded: true
                )
            )
        } catch {
            return (
                .empty,
                SourceResult(
                    name: "ThreatFox (7-day IOCs)",
                    addedHashes: 0,
                    note: error.localizedDescription,
                    succeeded: false
                )
            )
        }
    }

    // MARK: URLhaus — used as filename / path fragments only

    private func fetchURLHausRecent() async -> (delta: SignatureDatabase, result: SourceResult) {
        let url = URL(string: "https://urlhaus-api.abuse.ch/v1/urls/recent/")!
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            try throwIfBad(response)
            guard
                let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                let list = json["urls"] as? [[String: Any]]
            else {
                throw SentinelError.updateFailed("Unexpected URLhaus payload")
            }
            var names = Set<String>()
            for item in list {
                if let urlString = item["url"] as? String, let fileURL = URL(string: urlString) {
                    let name = fileURL.lastPathComponent.lowercased()
                    if name.count >= 5, name.contains("."), !name.hasSuffix(".html"), !name.hasSuffix(".php") {
                        names.insert(name)
                    }
                }
            }
            var delta = SignatureDatabase.empty
            delta.filenames = names
            delta.sources = ["URLhaus recent payloads"]
            return (
                delta,
                SourceResult(
                    name: "URLhaus recent payloads",
                    addedHashes: 0,
                    note: "\(names.count) payload filenames (not executed; used as name indicators only)",
                    succeeded: true
                )
            )
        } catch {
            return (
                .empty,
                SourceResult(
                    name: "URLhaus recent payloads",
                    addedHashes: 0,
                    note: error.localizedDescription,
                    succeeded: false
                )
            )
        }
    }

    private func parseHashList(_ text: String) -> Set<String> {
        var hashes = Set<String>()
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") || line.isEmpty { continue }
            let hash = line.lowercased()
            if hash.count == 64, hash.allSatisfy(\.isHexDigit) {
                hashes.insert(hash)
            }
        }
        return hashes
    }

    private func throwIfBad(_ response: URLResponse) throws {
        if let http = response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            throw SentinelError.updateFailed("HTTP \(http.statusCode)")
        }
    }
}

enum ReportExporter {
    static func markdown(findings: [Finding], hosts: [DiscoveredHost], stats: SignatureStats) -> String {
        var lines: [String] = []
        lines.append("# Sentinel assessment")
        lines.append("Generated \(ISO8601DateFormatter().string(from: Date()))")
        lines.append("")
        lines.append("This report is a defensive inventory. Sentinel does not exploit services or attempt logins.")
        lines.append("")
        lines.append("## Signature set")
        lines.append("- SHA-256 hashes: \(stats.hashCount)")
        lines.append("- Filenames: \(stats.filenameCount)")
        lines.append("- Last updated: \(stats.lastUpdated.map { ISO8601DateFormatter().string(from: $0) } ?? "bundled seed only")")
        lines.append("")
        lines.append("## Hosts")
        for host in hosts {
            let name = host.hostname.map { " (\($0))" } ?? ""
            lines.append("### \(host.ip)\(name)")
            if let mac = host.macAddress {
                lines.append("- MAC \(mac)\(host.vendor.map { " (\($0))" } ?? "")")
            }
            if let os = host.osGuess {
                lines.append("- OS guess: \(os.summary)")
            }
            if let method = host.discoveryMethod {
                lines.append("- Discovery: \(method)")
            }
            if host.ports.isEmpty {
                lines.append("- No scanned ports open")
            } else {
                for port in host.ports {
                    lines.append("- \(port.port)/\(port.transport.rawValue) \(port.serviceLabel) (\(port.risk.label) \(port.state.label))")
                    if let banner = port.banner {
                        lines.append("  - banner: \(banner.prefix(160))")
                    }
                    for script in port.scripts {
                        lines.append("  - \(script.name): \(script.output.prefix(200))")
                    }
                }
            }
            lines.append("")
        }
        lines.append("## Findings")
        for finding in findings.sorted(by: { $0.severity > $1.severity }) {
            lines.append("### [\(finding.severity.label)] \(finding.title)")
            lines.append(finding.detail)
            lines.append("")
            lines.append("**Remediation:** \(finding.remediation)")
            if let evidence = finding.evidence {
                lines.append("")
                lines.append("```")
                lines.append(evidence)
                lines.append("```")
            }
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }
}
