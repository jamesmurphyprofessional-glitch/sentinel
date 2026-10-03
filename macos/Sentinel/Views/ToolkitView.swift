import SwiftUI
import AppKit

struct ToolkitView: View {
    @EnvironmentObject private var app: AppState
    @State private var query = ""
    @State private var categoryFilter: ToolCategory?

    private var filtered: [ToolDefinition] {
        ToolDefinition.catalog.filter { tool in
            if let categoryFilter, tool.category != categoryFilter { return false }
            if query.isEmpty { return true }
            let hay = "\(tool.name) \(tool.inspiredBy) \(tool.summary) \(tool.category.label)".lowercased()
            return hay.contains(query.lowercased())
        }
    }

    var body: some View {
        HSplitView {
            catalog
                .frame(minWidth: 250, idealWidth: 280, maxWidth: 320)
            workspace
        }
        .background(SentinelTheme.background)
    }

    private var catalog: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 8) {
                Text("TOOLS")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(SentinelTheme.muted)
                    .tracking(1.1)
                TextField("Search tools", text: $query)
                    .textFieldStyle(.roundedBorder)
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        categoryChip(nil, "All")
                        ForEach(ToolCategory.allCases) { category in
                            categoryChip(category, category.label)
                        }
                    }
                }
            }
            .padding(12)

            Divider().overlay(SentinelTheme.stroke)

            List(selection: $app.selectedToolID) {
                ForEach(ToolCategory.allCases) { category in
                    let items = filtered.filter { $0.category == category }
                    if !items.isEmpty {
                        Section(category.label) {
                            ForEach(items) { tool in
                                toolRow(tool)
                                    .tag(tool.id)
                            }
                        }
                    }
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
        }
        .background(SentinelTheme.panel)
    }

    private func categoryChip(_ category: ToolCategory?, _ title: String) -> some View {
        let selected = categoryFilter == category
        return Button(title) {
            categoryFilter = category
        }
        .buttonStyle(.plain)
        .font(.system(size: 10, weight: .semibold))
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .foregroundStyle(selected ? SentinelTheme.background : SentinelTheme.text)
        .background(selected ? SentinelTheme.mint : SentinelTheme.panelRaised)
        .clipShape(Capsule())
    }

    private func toolRow(_ tool: ToolDefinition) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(tool.name)
                .font(.system(size: 13, weight: .medium))
            Text(tool.inspiredBy)
                .font(.system(size: 10, design: .monospaced))
                .foregroundStyle(SentinelTheme.muted)
                .lineLimit(1)
        }
        .padding(.vertical, 2)
    }

    private var workspace: some View {
        VStack(spacing: 0) {
            runnerHeader
            Divider().overlay(SentinelTheme.stroke)
            HSplitView {
                outputPane
                sidePane
                    .frame(minWidth: 220, idealWidth: 260, maxWidth: 320)
            }
        }
    }

    private var runnerHeader: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(app.selectedTool.name)
                        .font(.system(size: 20, weight: .semibold))
                    Text(app.selectedTool.summary)
                        .font(.system(size: 12))
                        .foregroundStyle(SentinelTheme.muted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Text(app.selectedTool.inspiredBy)
                    .font(.system(size: 11, design: .monospaced))
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .foregroundStyle(SentinelTheme.mint)
                    .background(SentinelTheme.mint.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
            }

            if !app.authorizedToScan && app.selectedTool.needsNetwork {
                Text("Turn on the authorization checkbox on Overview before running this tool.")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(SentinelTheme.amber)
            }

            HStack(spacing: 8) {
                TextField(app.selectedTool.needsNetwork ? "Host, IP, or domain" : "Optional input", text: $app.toolTarget)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 13, design: .monospaced))
                if app.selectedTool.needsPort {
                    TextField("Port", text: $app.toolPortText)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 72)
                        .font(.system(size: 13, design: .monospaced))
                        .onAppear {
                            if app.toolPortText.isEmpty, let port = app.selectedTool.defaultPort {
                                app.toolPortText = String(port)
                            }
                        }
                        .onChange(of: app.selectedToolID) { _, _ in
                            if let port = app.selectedTool.defaultPort {
                                app.toolPortText = String(port)
                            }
                        }
                }
                PrimaryButton(
                    title: "Run",
                    systemImage: "play.fill",
                    enabled: !app.isBusy && (app.authorizedToScan || !app.selectedTool.needsNetwork)
                ) {
                    Task { await app.runSelectedTool() }
                }
            }

            if !quickTargets.isEmpty {
                HStack(spacing: 6) {
                    Text("Targets")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundStyle(SentinelTheme.muted)
                    ForEach(quickTargets, id: \.self) { item in
                        Button(item) { app.toolTarget = item }
                            .buttonStyle(.plain)
                            .font(.system(size: 11, design: .monospaced))
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(SentinelTheme.panelRaised)
                            .clipShape(Capsule())
                    }
                }
            }
        }
        .padding(16)
        .background(SentinelTheme.panel)
    }

    private var quickTargets: [String] {
        var items: [String] = []
        if let ip = app.snapshot?.ipAddress { items.append(ip) }
        if let gw = app.snapshot?.gateway { items.append(gw) }
        items.append(contentsOf: app.hosts.prefix(6).map(\.ip))
        var seen = Set<String>()
        return items.filter { seen.insert($0).inserted }
    }

    private var outputPane: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("OUTPUT")
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(SentinelTheme.muted)
                    .tracking(1.1)
                Spacer()
                if let run = app.currentToolRun {
                    Text(run.target)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(SentinelTheme.muted)
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(run.output, forType: .string)
                    }
                    .font(.system(size: 11))
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)

            ScrollView {
                Text(app.currentToolRun?.output ?? "Pick a tool and run it against a host you are authorized to assess.\n\nEvery tool here is identification only: banners, headers, DNS, and single well-known checks. Nothing guesses passwords or sends exploit payloads.")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(app.currentToolRun == nil ? SentinelTheme.muted : SentinelTheme.text)
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
            }
        }
        .background(SentinelTheme.background)
    }

    private var sidePane: some View {
        VStack(alignment: .leading, spacing: 0) {
            findingsBlock
            Divider().overlay(SentinelTheme.stroke)
            historyBlock
        }
        .background(SentinelTheme.panel)
    }

    private var findingsBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("THIS RUN")
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(SentinelTheme.muted)
                .tracking(1.1)
            if let run = app.currentToolRun, !run.findings.isEmpty {
                ForEach(run.findings) { finding in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            SeverityBadge(severity: finding.severity)
                            Text(finding.title)
                                .font(.system(size: 11, weight: .medium))
                                .lineLimit(2)
                        }
                        Text(finding.remediation)
                            .font(.system(size: 10))
                            .foregroundStyle(SentinelTheme.muted)
                    }
                    .padding(8)
                    .background(SentinelTheme.panelRaised)
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }
            } else {
                Text("No extra findings from the last run.")
                    .font(.system(size: 11))
                    .foregroundStyle(SentinelTheme.muted)
            }
        }
        .padding(14)
    }

    private var historyBlock: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("HISTORY")
                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                .foregroundStyle(SentinelTheme.muted)
                .tracking(1.1)
            if app.toolRuns.isEmpty {
                Text("Runs from this session show up here.")
                    .font(.system(size: 11))
                    .foregroundStyle(SentinelTheme.muted)
            } else {
                ForEach(app.toolRuns.prefix(8)) { run in
                    Button {
                        app.currentToolRun = run
                        app.selectedToolID = run.toolID
                        app.toolTarget = run.target
                    } label: {
                        HStack {
                            Circle()
                                .fill(run.succeeded ? SentinelTheme.mint : SentinelTheme.red)
                                .frame(width: 6, height: 6)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(run.toolName)
                                    .font(.system(size: 12, weight: .medium))
                                Text(run.target)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(SentinelTheme.muted)
                            }
                            Spacer()
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(14)
    }
}
