import SwiftUI

struct MacCheckView: View {
    @EnvironmentObject private var app: AppState

    private var problems: [Finding] {
        app.macFindings.filter(\.severity.needsAttention)
    }

    private var lookingGood: [Finding] {
        app.macFindings.filter { !$0.severity.needsAttention }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                intro
                if !problems.isEmpty {
                    section(title: "Change these", items: problems, empty: "")
                }
                section(
                    title: "Looking good",
                    items: lookingGood,
                    empty: app.macCheckRan
                        ? "Run the check again after you change a setting."
                        : "Press “Check this Mac” to read the built-in switches."
                )
                stillDoThese
            }
            .padding(20)
        }
        .background(SentinelTheme.background)
    }

    private var intro: some View {
        Panel {
            VStack(alignment: .leading, spacing: 10) {
                Text("The settings that matter on this computer")
                    .font(.system(size: 16, weight: .semibold))
                Text("These are the Mac switches most people should turn on, and the sharing features most people should leave off. Each card tells you why it matters and the exact clicks in System Settings.")
                    .font(.system(size: 13))
                    .foregroundStyle(SentinelTheme.muted)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 16) {
                    Label("\(problems.count) to change", systemImage: problems.isEmpty ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                        .foregroundStyle(problems.isEmpty ? SentinelTheme.mint : SentinelTheme.amber)
                    Label("\(lookingGood.count) already good", systemImage: "checkmark")
                        .foregroundStyle(SentinelTheme.muted)
                    Spacer()
                    Button("Open System Settings") { app.openSystemSettings() }
                    Button("Recheck") {
                        Task { await app.startMacCheck() }
                    }
                    .disabled(app.isBusy)
                }
                .font(.system(size: 13, weight: .medium))
            }
        }
    }

    private func section(title: String, items: [Finding], empty: String) -> some View {
        Panel(title: title) {
            if items.isEmpty {
                Text(empty)
                    .foregroundStyle(SentinelTheme.muted)
            } else {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(items) { finding in
                        checkCard(finding)
                    }
                }
            }
        }
    }

    private func checkCard(_ finding: Finding) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                SeverityBadge(severity: finding.severity)
                Text(finding.title)
                    .font(.system(size: 14, weight: .semibold))
                Spacer()
            }
            Text(finding.detail)
                .font(.system(size: 13))
                .foregroundStyle(SentinelTheme.muted)
                .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "hand.point.right.fill")
                    .foregroundStyle(SentinelTheme.mint)
                    .font(.system(size: 12))
                    .padding(.top, 2)
                Text(finding.remediation)
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(SentinelTheme.mint)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .background(SentinelTheme.panelRaised)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }

    private var stillDoThese: some View {
        Panel(title: "Also do these (we cannot check them for you)") {
            VStack(alignment: .leading, spacing: 10) {
                extra(
                    "Lock screen password",
                    "System Settings → Lock Screen → require a password immediately after sleep or the screen saver."
                )
                extra(
                    "Find My Mac",
                    "System Settings → your name → Find My → turn on Find My Mac."
                )
                extra(
                    "Apple ID two-factor",
                    "System Settings → your name → Sign-In & Security → Two-Factor Authentication."
                )
                extra(
                    "Login items",
                    "System Settings → General → Login Items & Extensions. Remove names you do not recognize."
                )
                Button("See every safety tip") { app.section = .tips }
                    .padding(.top, 4)
            }
        }
    }

    private func extra(_ title: String, _ steps: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.system(size: 13, weight: .semibold))
            Text(steps)
                .font(.system(size: 12))
                .foregroundStyle(SentinelTheme.muted)
        }
    }
}
