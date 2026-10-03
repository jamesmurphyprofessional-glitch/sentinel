import SwiftUI

enum SentinelTheme {
    static let background = Color(red: 0.043, green: 0.059, blue: 0.078)
    static let panel = Color(red: 0.078, green: 0.102, blue: 0.133)
    static let panelRaised = Color(red: 0.102, green: 0.129, blue: 0.165)
    static let stroke = Color(red: 0.165, green: 0.204, blue: 0.255)
    static let text = Color(red: 0.910, green: 0.933, blue: 0.957)
    static let muted = Color(red: 0.557, green: 0.620, blue: 0.682)
    static let mint = Color(red: 0.239, green: 0.863, blue: 0.592)
    static let amber = Color(red: 0.961, green: 0.647, blue: 0.141)
    static let red = Color(red: 1.0, green: 0.365, blue: 0.365)
    static let blue = Color(red: 0.392, green: 0.710, blue: 0.965)
}

extension Severity {
    var color: Color {
        switch self {
        case .info: return SentinelTheme.blue
        case .low: return SentinelTheme.mint
        case .medium: return SentinelTheme.amber
        case .high: return Color.orange
        case .critical: return SentinelTheme.red
        }
    }
}

struct SeverityBadge: View {
    let severity: Severity

    var body: some View {
        Text(severity.label)
            .font(.system(size: 10, weight: .bold, design: .rounded))
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .foregroundStyle(severity.color)
            .background(severity.color.opacity(0.14))
            .overlay(
                RoundedRectangle(cornerRadius: 4)
                    .stroke(severity.color.opacity(0.45), lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 4))
    }
}

struct Panel<Content: View>: View {
    var title: String?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let title {
                Text(title.uppercased())
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(SentinelTheme.muted)
                    .tracking(1.1)
            }
            content
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
}

struct PrimaryButton: View {
    let title: String
    let systemImage: String
    var enabled: Bool = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label(title, systemImage: systemImage)
                .font(.system(size: 13, weight: .semibold))
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
        }
        .buttonStyle(.borderedProminent)
        .tint(SentinelTheme.mint)
        .disabled(!enabled)
    }
}
