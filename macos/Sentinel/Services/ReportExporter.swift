import Foundation
import AppKit

enum ExportStore {
    static var supportDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        let dir = base.appendingPathComponent("Sentinel", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
}

enum ReportExporter {
    static func markdown(findings: [Finding], hosts: [DiscoveredHost], snapshot: NetworkSnapshot?) -> String {
        var lines: [String] = []
        lines.append("# Sentinel safety report")
        lines.append("Created \(Date().formatted(date: .long, time: .shortened))")
        lines.append("")
        if let snapshot {
            let wifi = snapshot.ssid.map { "Wi-Fi: \($0)" } ?? "Connection: \(snapshot.interfaceName)"
            lines.append("\(wifi)")
            lines.append("This computer: \(snapshot.ipAddress)")
            if let gateway = snapshot.gateway {
                lines.append("Router: \(gateway)")
            }
            lines.append("")
        }

        let issues = findings.filter(\.severity.needsAttention)
        lines.append("## Things to fix (\(issues.count))")
        lines.append("")
        if issues.isEmpty {
            lines.append("Nothing urgent turned up. Keep the safety tips handy and re-check after you add devices.")
            lines.append("")
        } else {
            for finding in issues.sorted(by: { $0.severity > $1.severity }) {
                lines.append("### \(finding.severity.label): \(finding.title)")
                lines.append(finding.detail)
                lines.append("")
                lines.append("What to do: \(finding.remediation)")
                lines.append("")
            }
        }

        if !hosts.isEmpty {
            lines.append("## Devices we saw")
            lines.append("")
            for host in hosts {
                let kind = DeviceGuide.kind(host, gateway: snapshot?.gateway)
                let name = host.hostname.map { " — \($0)" } ?? ""
                lines.append("### \(kind): \(host.ip)\(name)")
                lines.append(DeviceGuide.blurb(host, gateway: snapshot?.gateway))
                if host.ports.isEmpty {
                    lines.append("No extra sharing turned up on the quick check.")
                } else {
                    for port in host.ports {
                        let guide = PortCatalog.homeGuide(for: port.port, onThisMac: host.isLocalMachine)
                        lines.append("- \(guide.headline)")
                    }
                }
                lines.append("")
            }
        }

        lines.append("## Looking good")
        let ok = findings.filter { !$0.severity.needsAttention }
        if ok.isEmpty {
            lines.append("Run “Check this Mac” to see built-in settings.")
        } else {
            for finding in ok {
                lines.append("- \(finding.title)")
            }
        }
        lines.append("")
        return lines.joined(separator: "\n")
    }
}

enum ScanFileReveal {
    static func reveal(_ url: URL) {
        NSWorkspace.shared.activateFileViewerSelecting([url])
    }
}
