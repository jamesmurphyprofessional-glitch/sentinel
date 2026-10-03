import Foundation
import CryptoKit

struct SignatureDatabase: Codable, Sendable {
    var hashesSHA256: Set<String>
    var filenames: Set<String>
    var pathFragments: Set<String>
    var bundleIds: Set<String>
    var launchLabels: Set<String>
    var sources: [String]
    var lastUpdated: Date?

    static var empty: SignatureDatabase {
        SignatureDatabase(
            hashesSHA256: [],
            filenames: [],
            pathFragments: [],
            bundleIds: [],
            launchLabels: [],
            sources: [],
            lastUpdated: nil
        )
    }

    var stats: SignatureStats {
        SignatureStats(
            hashCount: hashesSHA256.count,
            filenameCount: filenames.count,
            pathCount: pathFragments.count,
            bundleIdCount: bundleIds.count,
            labelCount: launchLabels.count,
            lastUpdated: lastUpdated,
            sources: sources
        )
    }

    mutating func merge(_ other: SignatureDatabase) {
        hashesSHA256.formUnion(other.hashesSHA256)
        filenames.formUnion(other.filenames)
        pathFragments.formUnion(other.pathFragments)
        bundleIds.formUnion(other.bundleIds)
        launchLabels.formUnion(other.launchLabels)
        for source in other.sources where !sources.contains(source) {
            sources.append(source)
        }
        lastUpdated = Date()
    }

    func match(path: String, sha256: String?, bundleId: String?, label: String?) -> [String] {
        var hits: [String] = []
        let name = URL(fileURLWithPath: path).lastPathComponent.lowercased()
        let lowerPath = path.lowercased()

        if let sha256, hashesSHA256.contains(sha256.lowercased()) {
            hits.append("SHA-256 listed in malware hash feed")
        }
        if filenames.contains(name) {
            hits.append("filename matches known malware / PUP indicator: \(name)")
        }
        for fragment in pathFragments where !fragment.isEmpty && lowerPath.contains(fragment) {
            hits.append("path contains known indicator \"\(fragment)\"")
        }
        if let bundleId, bundleIds.contains(bundleId.lowercased()) {
            hits.append("bundle id \(bundleId) is a known adware/malware identifier")
        }
        if let label, launchLabels.contains(label.lowercased()) {
            hits.append("launchd label \(label) matches a known-bad agent")
        }
        return hits
    }
}

struct SeedFile: Codable {
    var hashesSHA256: [String]
    var filenames: [String]
    var pathFragments: [String]
    var bundleIds: [String]
    var launchLabels: [String]
}

enum SHA256Hash {
    static func hex(of url: URL, maxBytes: Int = 64 * 1_024 * 1_024) -> String? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }

        var hasher = SHA256()
        var remaining = maxBytes
        while remaining > 0 {
            let chunk = min(remaining, 1024 * 1024)
            let data: Data
            do {
                guard let piece = try handle.read(upToCount: chunk), !piece.isEmpty else { break }
                data = piece
            } catch {
                return nil
            }
            hasher.update(data: data)
            remaining -= data.count
            if data.count < chunk { break }
        }
        let digest = hasher.finalize()
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
