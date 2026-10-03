import Foundation
import SwiftUI
import AppKit
import Combine

@MainActor
final class AppState: ObservableObject {
    enum Section: String, CaseIterable, Identifiable {
        case dashboard = "Home"
        case network = "Your Wi-Fi"
        case mac = "This Mac"
        case tips = "Safety tips"
        case findings = "What we found"

        var id: String { rawValue }

        var systemImage: String {
            switch self {
            case .dashboard: return "house.fill"
            case .network: return "wifi"
            case .mac: return "laptopcomputer"
            case .tips: return "lightbulb.fill"
            case .findings: return "checklist"
            }
        }

        var subtitle: String {
            switch self {
            case .dashboard: return "Start here"
            case .network: return "Who is on your network"
            case .mac: return "Settings to turn on"
            case .tips: return "Simple habits that help"
            case .findings: return "A plain-language list"
            }
        }
    }

    @Published var section: Section = .dashboard
    @Published var snapshot: NetworkSnapshot?
    @Published var hosts: [DiscoveredHost] = []
    @Published var findings: [Finding] = []
    @Published var progress: ScanProgress?
    @Published var isBusy = false
    @Published var statusMessage = "Ready. Start with “Check this Mac”, then look at your Wi-Fi."
    @Published var lastError: String?
    @Published var authorizedToScan = false
    @Published var selectedFinding: Finding?
    @Published var scanMode: HomeScanMode = .quick
    @Published var lastExportURL: URL?
    @Published var selectedHostIP: String?
    @Published var macCheckRan = false

    private let networkScanner = NetworkScanner()
    private let bonjour = BonjourDiscovery()

    init() {
        refreshNetworkInfo()
        Task { await startMacCheck(silent: true) }
    }

    var scanProfile: ScanProfile { scanMode.profile }

    var highCount: Int {
        findings.filter { $0.severity >= .high }.count
    }

    var issues: [Finding] {
        findings.filter(\.severity.needsAttention)
    }

    var macFindings: [Finding] {
        findings.filter { $0.host == "this-mac" || $0.category == .hardening || $0.category == .listening }
    }

    var networkFindings: [Finding] {
        findings.filter { $0.category == .network || $0.category == .remoteAccess || $0.category == .service }
            .filter { $0.host != "this-mac" }
    }

    func refreshNetworkInfo() {
        do {
            snapshot = try NetworkInfo.currentSnapshot()
        } catch {
            lastError = error.localizedDescription
        }
    }

    func startFullCheck() async {
        await startMacCheck()
        if !Task.isCancelled {
            await startNetworkScan()
        }
    }

    func startMacCheck(silent: Bool = false) async {
        guard silent || !isBusy else { return }
        if !silent {
            isBusy = true
            lastError = nil
            statusMessage = "Checking the safety settings on this Mac…"
            progress = ScanProgress(phase: "This Mac", completed: 0, total: 1, statusLine: "Looking at sharing, firewall, encryption, and updates")
        }
        defer {
            if !silent {
                isBusy = false
                progress = nil
            }
        }

        findings.removeAll { $0.host == "this-mac" || $0.category == .hardening || $0.category == .listening }
        let macFindings = await Task.detached(priority: .userInitiated) {
            HardeningScanner.run()
        }.value
        findings.append(contentsOf: macFindings)
        findings.sort { $0.severity > $1.severity }
        macCheckRan = true
        let problems = macFindings.filter(\.severity.needsAttention).count
        statusMessage = problems == 0
            ? "This Mac looks in good shape. Read the safety tips for what to do next."
            : "This Mac: \(problems) setting\(problems == 1 ? "" : "s") to change. Open “This Mac” for step-by-step help."
        if !silent {
            section = .mac
        }
    }

    func startNetworkScan() async {
        guard !isBusy else { return }
        guard authorizedToScan else {
            lastError = SentinelError.unauthorizedNetwork.localizedDescription
            statusMessage = "Tick the box on Home to confirm this is your network, then try again."
            section = .dashboard
            return
        }

        isBusy = true
        lastError = nil
        defer {
            isBusy = false
            progress = nil
        }

        refreshNetworkInfo()
        guard let snapshot else {
            lastError = SentinelError.noActiveInterface.localizedDescription
            return
        }

        findings.removeAll {
            ($0.category == .network || $0.category == .remoteAccess || $0.category == .service)
                && $0.host != "this-mac"
        }
        hosts = []
        let profile = scanProfile
        let place = snapshot.ssid.map { "Wi-Fi “\($0)”" } ?? snapshot.interfaceName
        statusMessage = "Looking for devices on \(place)…"

        let hints = await networkScanner.discoverHosts(snapshot: snapshot, profile: profile) { [weak self] update in
            Task { @MainActor in
                self?.progress = update
                self?.statusMessage = "Looking for devices… \(update.statusLine)"
            }
        }

        statusMessage = "Listening for printers, TVs, and other gadgets that announce themselves…"
        progress = ScanProgress(phase: "Devices", completed: 0, total: 1, statusLine: "Checking who is visible on the network")
        let advertised = await bonjour.discover()

        let portList = profile.ports(customSpec: "22,80,443,445,548,5900,3389,8080")
        statusMessage = "Checking whether those devices are sharing files or allowing remote access…"
        var scanned = await networkScanner.scanPorts(
            hints: hints,
            ports: portList,
            localIP: snapshot.ipAddress,
            profile: profile
        ) { [weak self] update in
            Task { @MainActor in
                self?.progress = update
                self?.statusMessage = update.statusLine
            }
        }

        for index in scanned.indices {
            let ip = scanned[index].ip
            let extras = advertised.flatMap { key, names -> [String] in
                if key == ip || (scanned[index].hostname?.localizedCaseInsensitiveContains(key) ?? false) {
                    return names
                }
                return []
            }
            if extras.isEmpty == false {
                scanned[index].bonjourNames = extras
            }
        }

        hosts = scanned
        var next = NetworkScanner.findings(from: scanned, snapshot: snapshot, profile: profile)
        next.append(contentsOf: await bonjour.findings(map: advertised))
        findings.append(contentsOf: next)
        findings.sort { $0.severity > $1.severity }
        let issues = next.filter(\.severity.needsAttention).count
        statusMessage = issues == 0
            ? "Wi-Fi check finished. \(hosts.count) device\(hosts.count == 1 ? "" : "s") found, nothing worrying."
            : "Wi-Fi check finished. \(hosts.count) device\(hosts.count == 1 ? "" : "s"), \(issues) thing\(issues == 1 ? "" : "s") to look at."
        section = .network
    }

    func exportReport() -> URL? {
        let text = ReportExporter.markdown(findings: findings, hosts: hosts, snapshot: snapshot)
        return saveExport(text, name: "Sentinel-Safety-Report.md")
    }

    private func saveExport(_ text: String, name: String) -> URL? {
        let url = ExportStore.supportDirectory.appendingPathComponent(name)
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            lastExportURL = url
            return url
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    func clearFindings() {
        findings = []
        hosts = []
        selectedFinding = nil
        macCheckRan = false
        statusMessage = "Cleared. Run the Mac check or the Wi-Fi look again when you are ready."
    }

    func openSystemSettings() {
        let url = URL(fileURLWithPath: "/System/Applications/System Settings.app")
        NSWorkspace.shared.open(url)
    }

    func showAbout() {
        let alert = NSAlert()
        alert.messageText = "Sentinel — free version"
        alert.informativeText = """
        Copyright © James Murphy.

        Sentinel is copyright of the owner and developer, James Murphy. All rights reserved.

        This is the free version of the software. Use it for personal, lawful checks on a network you own or have permission to look at. It is provided as-is, without any warranty.

        Developed by James Murphy.
        """
        alert.alertStyle = .informational
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
