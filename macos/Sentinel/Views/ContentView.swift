import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var app: AppState

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 210, ideal: 230, max: 270)
        } detail: {
            VStack(spacing: 0) {
                header
                Divider().overlay(SentinelTheme.stroke)
                Group {
                    switch app.section {
                    case .dashboard: DashboardView()
                    case .network: NetworkScanView()
                    case .mac: MacCheckView()
                    case .tips: TipsView()
                    case .findings: FindingsListView()
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                statusBar
            }
            .background(SentinelTheme.background)
        }
        .navigationSplitViewStyle(.balanced)
        .background(SentinelTheme.background)
    }

    private var sidebar: some View {
        List(AppState.Section.allCases, selection: $app.section) { section in
            NavigationLink(value: section) {
                Label {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(section.rawValue)
                        Text(section.subtitle)
                            .font(.system(size: 10))
                            .foregroundStyle(SentinelTheme.muted)
                    }
                } icon: {
                    Image(systemName: section.systemImage)
                }
            }
        }
        .listStyle(.sidebar)
        .scrollContentBackground(.hidden)
        .background(SentinelTheme.background)
        .safeAreaInset(edge: .top) {
            HStack(spacing: 10) {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundStyle(SentinelTheme.mint)
                    .font(.title2)
                VStack(alignment: .leading, spacing: 1) {
                    Text("SENTINEL")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                    Text("Home safety helper")
                        .font(.system(size: 11))
                        .foregroundStyle(SentinelTheme.muted)
                }
                Spacer()
            }
            .padding(14)
        }
        .safeAreaInset(edge: .bottom) {
            Text("Developed by James Murphy")
                .font(.system(size: 10))
                .foregroundStyle(SentinelTheme.muted)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 14)
                .padding(.bottom, 12)
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(app.section.rawValue)
                    .font(.system(size: 22, weight: .semibold))
                Text(headerCaption)
                    .font(.system(size: 12))
                    .foregroundStyle(SentinelTheme.muted)
            }
            Spacer()
            if app.isBusy {
                ProgressView()
                    .controlSize(.small)
            }
            PrimaryButton(
                title: "Check this Mac",
                systemImage: "laptopcomputer",
                enabled: !app.isBusy
            ) {
                Task { await app.startMacCheck() }
            }
            PrimaryButton(
                title: "Look at my Wi-Fi",
                systemImage: "wifi",
                enabled: !app.isBusy
            ) {
                Task { await app.startNetworkScan() }
            }
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
        .background(SentinelTheme.panel)
    }

    private var headerCaption: String {
        if let snapshot = app.snapshot {
            if let ssid = snapshot.ssid {
                return "Connected to Wi-Fi “\(ssid)”"
            }
            return "Connected via \(snapshot.interfaceName) · \(snapshot.ipAddress)"
        }
        return "Not connected to a network yet"
    }

    private var statusBar: some View {
        HStack(spacing: 10) {
            Circle()
                .fill(app.isBusy ? SentinelTheme.amber : SentinelTheme.mint)
                .frame(width: 7, height: 7)
            Text(app.statusMessage)
                .font(.system(size: 12))
                .foregroundStyle(SentinelTheme.muted)
                .lineLimit(1)
            Spacer()
            if let progress = app.progress {
                ProgressView(value: progress.fraction)
                    .frame(width: 140)
            }
            let count = app.issues.count
            Text(count == 0 ? "Nothing urgent" : "\(count) to fix")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(count == 0 ? SentinelTheme.mint : SentinelTheme.amber)
            Text("·")
                .foregroundStyle(SentinelTheme.muted)
            Text("Developed by James Murphy")
                .font(.system(size: 11))
                .foregroundStyle(SentinelTheme.muted)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(SentinelTheme.panel)
    }
}
