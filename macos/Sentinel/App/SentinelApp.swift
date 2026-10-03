import SwiftUI

@main
struct SentinelApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .frame(minWidth: 1040, minHeight: 700)
                .preferredColorScheme(.dark)
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 1220, height: 800)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Sentinel") {
                    appState.showAbout()
                }
            }
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Check") {
                Button("Check This Mac") {
                    Task { await appState.startMacCheck() }
                }
                .keyboardShortcut("m", modifiers: [.command])
                .disabled(appState.isBusy)

                Button("Look at My Wi-Fi") {
                    Task { await appState.startNetworkScan() }
                }
                .keyboardShortcut("n", modifiers: [.command])
                .disabled(appState.isBusy)

                Button("Check Both") {
                    Task { await appState.startFullCheck() }
                }
                .keyboardShortcut("f", modifiers: [.command, .shift])
                .disabled(appState.isBusy)

                Divider()

                Button("Safety Tips") {
                    appState.section = .tips
                }
                .keyboardShortcut("t", modifiers: [.command])
            }
        }
    }
}
