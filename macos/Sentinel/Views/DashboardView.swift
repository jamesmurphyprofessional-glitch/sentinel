import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var app: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                welcome
                legalDisclaimer
                authorizationBanner
                actionRow
                statsRow
                HStack(alignment: .top, spacing: 16) {
                    networkCard
                    macPreview
                }
                recentFindings
            }
            .padding(20)
        }
        .background(SentinelTheme.background)
    }

    private var welcome: some View {
        Panel {
            VStack(alignment: .leading, spacing: 8) {
                Text("A calmer look at home security")
                    .font(.system(size: 18, weight: .semibold))
                Text("Sentinel explains, in everyday language, who is on your Wi-Fi and which Mac settings to change. There is no malware scanner here — Apple already handles that. Use this app to turn on the boring protections that actually help: the firewall, disk encryption, sharing off, and a better router password.")
                    .font(.system(size: 13))
                    .foregroundStyle(SentinelTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var legalDisclaimer: some View {
        Panel(title: "Free version") {
            VStack(alignment: .leading, spacing: 8) {
                Text("This is the free version of Sentinel.")
                    .font(.system(size: 13, weight: .semibold))
                Text("Copyright © James Murphy. Sentinel is copyright of the owner and developer, James Murphy. All rights reserved.")
                    .font(.system(size: 12))
                    .foregroundStyle(SentinelTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Use it for personal, lawful checks on a network you own or have permission to look at. It is provided as-is, without any warranty.")
                    .font(.system(size: 12))
                    .foregroundStyle(SentinelTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var authorizationBanner: some View {
        Panel {
            VStack(alignment: .leading, spacing: 10) {
                Text("Before we look at other devices")
                    .font(.system(size: 15, weight: .semibold))
                Text("Checking this Mac only looks at settings on this computer. Looking at Wi-Fi lists other devices on the same network. Only do that at home, at work, or on a network you are allowed to check — not at a café.")
                    .font(.system(size: 12))
                    .foregroundStyle(SentinelTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)
                Toggle("This is my network, and I am allowed to check the devices on it", isOn: $app.authorizedToScan)
                    .toggleStyle(.checkbox)
                    .font(.system(size: 13, weight: .medium))
            }
        }
    }

    private var actionRow: some View {
        HStack(spacing: 12) {
            actionCard(
                title: "1. Check this Mac",
                detail: "Firewall, FileVault, sharing, updates, and guest login — with steps to change each one.",
                image: "laptopcomputer"
            ) {
                Task { await app.startMacCheck() }
            }
            actionCard(
                title: "2. Look at my Wi-Fi",
                detail: "See phones, TVs, printers, and anything that is sharing files or allowing remote access.",
                image: "wifi"
            ) {
                Task { await app.startNetworkScan() }
            }
            actionCard(
                title: "3. Read the tips",
                detail: "Router passwords, guest Wi-Fi, public hotspots, Apple ID, and scams to ignore.",
                image: "lightbulb.fill"
            ) {
                app.section = .tips
            }
        }
    }

    private func actionCard(title: String, detail: String, image: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 8) {
                Image(systemName: image)
                    .font(.system(size: 20))
                    .foregroundStyle(SentinelTheme.mint)
                Text(title)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(SentinelTheme.text)
                Text(detail)
                    .font(.system(size: 12))
                    .foregroundStyle(SentinelTheme.muted)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(SentinelTheme.panel)
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(SentinelTheme.stroke, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
        .disabled(app.isBusy && image != "lightbulb.fill")
    }

    private var statsRow: some View {
        HStack(spacing: 12) {
            stat("Devices seen", value: "\(app.hosts.count)", color: SentinelTheme.blue)
            stat("Things to fix", value: "\(app.issues.count)", color: app.issues.isEmpty ? SentinelTheme.mint : SentinelTheme.amber)
            stat("Urgent", value: "\(app.highCount)", color: app.highCount == 0 ? SentinelTheme.mint : SentinelTheme.red)
        }
    }

    private func stat(_ title: String, value: String, color: Color) -> some View {
        Panel {
            VStack(alignment: .leading, spacing: 6) {
                Text(title.uppercased())
                    .font(.system(size: 10, weight: .semibold, design: .rounded))
                    .foregroundStyle(SentinelTheme.muted)
                Text(value)
                    .font(.system(size: 28, weight: .bold, design: .rounded))
                    .foregroundStyle(color)
            }
        }
    }

    private var networkCard: some View {
        Panel(title: "This connection") {
            if let snapshot = app.snapshot {
                infoRow("Wi-Fi", snapshot.ssid ?? "Ethernet / cable")
                infoRow("This Mac’s address", snapshot.ipAddress)
                infoRow("Router", snapshot.gateway ?? "Not found")
            } else {
                Text("Connect to Wi-Fi or Ethernet to look at other devices.")
                    .foregroundStyle(SentinelTheme.muted)
            }
            HStack {
                Button("Refresh connection") { app.refreshNetworkInfo() }
                Button("Check both") {
                    Task { await app.startFullCheck() }
                }
                .disabled(app.isBusy)
            }
            .padding(.top, 6)
        }
    }

    private var macPreview: some View {
        Panel(title: "This Mac") {
            let macIssues = app.macFindings.filter(\.severity.needsAttention)
            if !app.macCheckRan && macIssues.isEmpty {
                Text("Checking built-in settings in the background…")
                    .foregroundStyle(SentinelTheme.muted)
            } else if macIssues.isEmpty {
                Text("The important built-in switches look good. Open “This Mac” to see the full list, or “Safety tips” for router and habit advice.")
                    .font(.system(size: 12))
                    .foregroundStyle(SentinelTheme.muted)
            } else {
                Text("\(macIssues.count) setting\(macIssues.count == 1 ? "" : "s") to change on this computer.")
                    .font(.system(size: 13, weight: .medium))
                ForEach(macIssues.prefix(4)) { finding in
                    FindingRow(finding: finding)
                        .onTapGesture { app.selectedFinding = finding; app.section = .mac }
                }
            }
            Button("Open This Mac") { app.section = .mac }
                .padding(.top, 6)
        }
    }

    private var recentFindings: some View {
        Panel(title: "Fix these first") {
            if app.issues.isEmpty {
                Text("Nothing urgent yet. Check this Mac, then look at your Wi-Fi.")
                    .foregroundStyle(SentinelTheme.muted)
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(app.issues.prefix(8)) { finding in
                        FindingRow(finding: finding)
                            .onTapGesture { app.selectedFinding = finding; app.section = .findings }
                    }
                }
            }
        }
    }

    private func infoRow(_ key: String, _ value: String) -> some View {
        HStack {
            Text(key)
                .foregroundStyle(SentinelTheme.muted)
            Spacer()
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
        }
        .font(.system(size: 12))
    }
}

struct FindingRow: View {
    let finding: Finding

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            SeverityBadge(severity: finding.severity)
            VStack(alignment: .leading, spacing: 2) {
                Text(finding.title)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(SentinelTheme.text)
                Text(finding.category.label)
                    .font(.system(size: 11))
                    .foregroundStyle(SentinelTheme.muted)
            }
            Spacer()
            if let host = finding.host, host != "this-mac" {
                Text(host)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(SentinelTheme.muted)
            }
        }
        .padding(8)
        .background(SentinelTheme.panelRaised)
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}
