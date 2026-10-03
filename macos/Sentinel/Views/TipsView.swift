import SwiftUI

struct TipsView: View {
    @State private var topic: TipTopic?
    @State private var query = ""
    @State private var expanded: Set<String> = []

    private var items: [SafetyTip] {
        SafetyTips.all.filter { tip in
            if let topic, tip.topic != topic { return false }
            if query.isEmpty { return true }
            let hay = "\(tip.title) \(tip.summary) \(tip.why) \(tip.steps.joined(separator: " "))".lowercased()
            return hay.contains(query.lowercased())
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Panel {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("The handful of changes that actually help")
                            .font(.system(size: 16, weight: .semibold))
                        Text("You do not need special software for most of this. A better Wi-Fi password, the Mac firewall, FileVault, and a bit of skepticism about unexpected links cover more ground than a “virus scan” ever did.")
                            .font(.system(size: 13))
                            .foregroundStyle(SentinelTheme.muted)
                            .fixedSize(horizontal: false, vertical: true)
                        TextField("Search tips", text: $query)
                            .textFieldStyle(.roundedBorder)
                        HStack(spacing: 8) {
                            chip(nil, "All")
                            ForEach(TipTopic.allCases) { item in
                                chip(item, item.label)
                            }
                        }
                    }
                }

                ForEach(grouped, id: \.0) { heading, tips in
                    Panel(title: heading) {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(tips) { tip in
                                tipCard(tip)
                            }
                        }
                    }
                }
            }
            .padding(20)
        }
        .background(SentinelTheme.background)
    }

    private var grouped: [(String, [SafetyTip])] {
        TipTopic.allCases.compactMap { topic in
            let tips = items.filter { $0.topic == topic }
            return tips.isEmpty ? nil : (topic.label, tips)
        }
    }

    private func chip(_ value: TipTopic?, _ title: String) -> some View {
        let selected = topic == value
        return Button(title) { topic = value }
            .buttonStyle(.plain)
            .font(.system(size: 12, weight: .semibold))
            .padding(.horizontal, 10)
            .padding(.vertical, 5)
            .foregroundStyle(selected ? SentinelTheme.background : SentinelTheme.text)
            .background(selected ? SentinelTheme.mint : SentinelTheme.panelRaised)
            .clipShape(Capsule())
    }

    private func tipCard(_ tip: SafetyTip) -> some View {
        let open = expanded.contains(tip.id)
        return VStack(alignment: .leading, spacing: 8) {
            Button {
                if open { expanded.remove(tip.id) } else { expanded.insert(tip.id) }
            } label: {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: tip.systemImage)
                        .foregroundStyle(SentinelTheme.mint)
                        .frame(width: 20)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(tip.title)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(SentinelTheme.text)
                        Text(tip.summary)
                            .font(.system(size: 12))
                            .foregroundStyle(SentinelTheme.muted)
                            .multilineTextAlignment(.leading)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Image(systemName: open ? "chevron.up" : "chevron.down")
                        .foregroundStyle(SentinelTheme.muted)
                        .font(.system(size: 11, weight: .semibold))
                }
            }
            .buttonStyle(.plain)

            if open {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Why it matters")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(SentinelTheme.muted)
                    Text(tip.why)
                        .font(.system(size: 13))
                    Text("What to do")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(SentinelTheme.muted)
                        .padding(.top, 4)
                    ForEach(Array(tip.steps.enumerated()), id: \.offset) { index, step in
                        HStack(alignment: .top, spacing: 8) {
                            Text("\(index + 1).")
                                .font(.system(size: 13, weight: .bold, design: .rounded))
                                .foregroundStyle(SentinelTheme.mint)
                                .frame(width: 20, alignment: .leading)
                            Text(step)
                                .font(.system(size: 13))
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                .padding(.leading, 30)
            }
        }
        .padding(12)
        .background(SentinelTheme.panelRaised)
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
