import SwiftUI
import AppKit

struct NetworkScanView: View {
    @EnvironmentObject private var app: AppState

    var body: some View {
        HSplitView {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    howItWorks
                    if app.hosts.isEmpty && !app.isBusy {
                        Panel {
                            Text("No devices listed yet. Tick the box on Home, then press “Look at my Wi-Fi”.")
                                .foregroundStyle(SentinelTheme.muted)
                        }
                    }
                    ForEach(app.hosts) { host in
                        hostCard(host)
                    }
                }
                .padding(20)
            }
            FindingsPane(
                title: "What this means",
                categories: [.network, .remoteAccess, .service],
                excludeThisMac: true
            )
        }
        .background(SentinelTheme.background)
    }

    private var howItWorks: some View {
        Panel(title: "Look at your Wi-Fi") {
            Text("This lists phones, computers, printers, and gadgets on the same network as this Mac. For each one we check whether it is sharing files or offering remote access. We do not try passwords or break in.")
                .font(.system(size: 12))
                .foregroundStyle(SentinelTheme.muted)
                .fixedSize(horizontal: false, vertical: true)

            if !app.authorizedToScan {
                Text("On Home, tick the box that this is your network, then come back.")
                    .foregroundStyle(SentinelTheme.amber)
                    .font(.system(size: 12, weight: .medium))
            }

            Picker("How thorough", selection: $app.scanMode) {
                ForEach(HomeScanMode.allCases) { mode in
                    Text(mode.title).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 360)

            Text(app.scanMode.summary)
                .font(.system(size: 12))
                .foregroundStyle(SentinelTheme.muted)
        }
    }

    private func hostCard(_ host: DiscoveredHost) -> some View {
        let kind = DeviceGuide.kind(host, gateway: app.snapshot?.gateway)
        let title = host.isLocalMachine ? "This Mac — \(host.ip)" : "\(kind) — \(host.ip)"
        return Panel(title: title) {
            VStack(alignment: .leading, spacing: 6) {
                Text(DeviceGuide.blurb(host, gateway: app.snapshot?.gateway))
                    .font(.system(size: 12))
                    .foregroundStyle(SentinelTheme.muted)

                if let name = host.hostname {
                    labeled("Name", name)
                }
                if let vendor = host.vendor {
                    labeled("Maker", vendor)
                }
                if let os = host.osGuess {
                    labeled("Looks like", os.summary)
                }
            }

            if host.ports.isEmpty {
                Text("Nothing notable is being shared from here.")
                    .font(.system(size: 12))
                    .foregroundStyle(SentinelTheme.mint)
            } else {
                Text("Open on this device")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(SentinelTheme.muted)
                    .padding(.top, 4)
                ForEach(host.ports) { port in
                    let guide = PortCatalog.homeGuide(for: port.port, onThisMac: host.isLocalMachine)
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            SeverityBadge(severity: port.risk)
                            Text(guide.headline)
                                .font(.system(size: 12, weight: .semibold))
                            Spacer()
                        }
                        Text(guide.meaning)
                            .font(.system(size: 12))
                            .foregroundStyle(SentinelTheme.muted)
                        Text(guide.fix)
                            .font(.system(size: 12))
                            .foregroundStyle(SentinelTheme.mint)
                    }
                    .padding(.vertical, 4)
                }
            }

            if !host.bonjourNames.isEmpty {
                labeled("Announcing itself as", host.bonjourNames.joined(separator: ", "))
            }
        }
    }

    private func labeled(_ title: String, _ value: String) -> some View {
        HStack(alignment: .top) {
            Text(title)
                .font(.system(size: 12))
                .foregroundStyle(SentinelTheme.muted)
                .frame(width: 140, alignment: .leading)
            Text(value)
                .font(.system(size: 12))
                .textSelection(.enabled)
        }
    }
}

struct FindingsListView: View {
    @EnvironmentObject private var app: AppState
    @State private var showOK = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Toggle("Show things that look fine", isOn: $showOK)
                    .toggleStyle(.checkbox)
                    .font(.system(size: 12))
                Spacer()
                Button("Save a report") {
                    if let url = app.exportReport() {
                        ScanFileReveal.reveal(url)
                    }
                }
                Button("Clear") { app.clearFindings() }
            }
            .padding(16)
            FindingsPane(
                title: nil,
                categories: FindingCategory.allCases,
                minimum: showOK ? nil : .medium,
                showDetail: true
            )
        }
        .background(SentinelTheme.background)
    }
}

struct FindingsPane: View {
    @EnvironmentObject private var app: AppState
    var title: String? = "Notes"
    var categories: [FindingCategory]
    var minimum: Severity? = nil
    var showDetail: Bool = false
    var excludeThisMac: Bool = false

    private var items: [Finding] {
        app.findings.filter { finding in
            categories.contains(finding.category)
                && (minimum == nil || finding.severity >= minimum!)
                && (!excludeThisMac || finding.host != "this-mac")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if let title {
                Text(title.uppercased())
                    .font(.system(size: 11, weight: .semibold, design: .rounded))
                    .foregroundStyle(SentinelTheme.muted)
                    .tracking(1.1)
                    .padding(.horizontal, 16)
                    .padding(.top, 14)
                    .padding(.bottom, 8)
            }
            List(items, selection: $app.selectedFinding) { finding in
                VStack(alignment: .leading, spacing: 8) {
                    FindingRow(finding: finding)
                    if showDetail || app.selectedFinding?.id == finding.id {
                        Text(finding.detail)
                            .font(.system(size: 12))
                            .foregroundStyle(SentinelTheme.muted)
                            .textSelection(.enabled)
                        Text(finding.remediation)
                            .font(.system(size: 12))
                            .foregroundStyle(SentinelTheme.mint)
                            .textSelection(.enabled)
                    }
                }
                .tag(finding)
                .listRowBackground(SentinelTheme.background)
            }
            .scrollContentBackground(.hidden)
        }
        .background(SentinelTheme.panel)
    }
}
