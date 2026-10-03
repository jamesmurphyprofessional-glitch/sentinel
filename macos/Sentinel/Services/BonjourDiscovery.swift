import Foundation
import Network

actor BonjourDiscovery {
    private struct BrowserHandle {
        let browser: NWBrowser
    }

    func discover(timeout: TimeInterval = 4.0) async -> [String: [String]] {
        let types = [
            "_ssh._tcp",
            "_sftp-ssh._tcp",
            "_afpovertcp._tcp",
            "_smb._tcp",
            "_rfb._tcp",
            "_rdp._tcp",
            "_vnc._tcp",
            "_telnet._tcp",
            "_ftp._tcp",
            "_http._tcp",
            "_https._tcp",
            "_ipp._tcp",
            "_printer._tcp",
            "_pdl-datastream._tcp",
            "_airplay._tcp",
            "_raop._tcp",
            "_adisk._tcp",
            "_eppc._tcp",
            "_nfs._tcp",
            "_workstation._tcp",
            "_companion-link._tcp",
            "_device-info._tcp",
            "_homekit._tcp",
            "_hap._tcp",
            "_spotify-connect._tcp",
            "_googlecast._tcp",
            "_scanner._tcp",
            "_daap._tcp",
            "_airdrop._tcp",
            "_apple-mobdev2._tcp"
        ]

        let collected = ResultBox<[String: Set<String>]>([:])
        var handles: [BrowserHandle] = []

        for type in types {
            let descriptor = NWBrowser.Descriptor.bonjour(type: type, domain: "local.")
            let browser = NWBrowser(for: descriptor, using: .tcp)
            browser.stateUpdateHandler = { _ in }
            browser.browseResultsChangedHandler = { results, _ in
                var snapshot = collected.value
                for result in results {
                    let endpoint = result.endpoint
                    let name: String
                    switch endpoint {
                    case .service(let serviceName, let serviceType, _, _):
                        name = "\(serviceName) (\(serviceType))"
                    default:
                        name = String(describing: endpoint)
                    }
                    let key = Self.endpointHost(result) ?? "advertised"
                    snapshot[key, default: []].insert(name)
                }
                collected.value = snapshot
            }
            browser.start(queue: .global(qos: .utility))
            handles.append(BrowserHandle(browser: browser))
        }

        try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
        handles.forEach { $0.browser.cancel() }

        return collected.value.mapValues { Array($0).sorted() }
    }

    func findings(map: [String: [String]]) -> [Finding] {
        var findings: [Finding] = []
        let remoteTypes = ["ssh", "rfb", "rdp", "vnc", "telnet", "eppc", "smb", "afp"]

        for (host, services) in map.sorted(by: { $0.key < $1.key }) {
            let joined = services.joined(separator: ", ")
            let isRemote = services.contains { service in
                remoteTypes.contains { service.lowercased().contains($0) }
            }
            findings.append(
                Finding(
                    category: isRemote ? .remoteAccess : .network,
                    severity: isRemote ? .high : .info,
                    title: isRemote
                        ? "A device named “\(host)” is advertising remote access"
                        : "“\(host)” is visible on your Wi-Fi",
                    detail: isRemote
                        ? "It is announcing \(joined). Anyone else on the same Wi-Fi can see that invitation."
                        : "This is how printers, Apple TVs, and speakers introduce themselves. Announcing: \(joined).",
                    remediation: isRemote
                        ? "If you do not use remote login, screen sharing, or file sharing, turn those off on that device."
                        : "If you do not recognize the name, look around the house (TV, speaker, printer) or check the router’s device list.",
                    host: host == "advertised" ? nil : host,
                    evidence: joined
                )
            )
        }
        return findings
    }

    private static func endpointHost(_ result: NWBrowser.Result) -> String? {
        if case let .bonjour(txtRecord) = result.metadata {
            let dict = txtRecord.dictionary
            if let ip = dict["ip"] ?? dict["IPv4"] { return ip }
        }
        switch result.endpoint {
        case .hostPort(let host, _):
            return "\(host)"
        case .service(let name, _, _, _):
            return name
        default:
            return nil
        }
    }
}

private final class ResultBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Value

    init(_ value: Value) {
        storage = value
    }

    var value: Value {
        get {
            lock.lock(); defer { lock.unlock() }
            return storage
        }
        set {
            lock.lock(); defer { lock.unlock() }
            storage = newValue
        }
    }
}
