import Foundation

enum HardeningScanner {
    static func run() -> [Finding] {
        var findings: [Finding] = []
        findings.append(contentsOf: listeningSockets())
        findings.append(contentsOf: sharingServices())
        findings.append(contentsOf: firewallAndStealth())
        findings.append(contentsOf: systemGuards())
        findings.append(contentsOf: automaticUpdates())
        findings.append(contentsOf: guestAccount())
        findings.append(contentsOf: remoteManagementHints())
        return findings
    }

    // MARK: - Listening sockets

    static func listeningSockets() -> [Finding] {
        let sockets = parseLsof()
        guard !sockets.isEmpty else {
            return [
                Finding(
                    category: .listening,
                    severity: .info,
                    title: "Could not see which apps are accepting connections",
                    detail: "macOS did not let Sentinel list open network doors. That is OK — the other checks below still work.",
                    remediation: "You can still turn on the firewall and turn sharing off. No extra permission is required for those."
                )
            ]
        }

        var findings: [Finding] = []
        let exposed = sockets.filter(\.exposed)
        let localOnly = sockets.filter { !$0.exposed }

        if exposed.isEmpty {
            findings.append(
                Finding(
                    category: .listening,
                    severity: .info,
                    title: "This Mac is not offering extra services to the Wi-Fi",
                    detail: localOnly.isEmpty
                        ? "Nothing on this computer is waiting for other devices to connect."
                        : "A few apps are listening only on this computer (not the Wi-Fi), which is normal.",
                    remediation: "Keep sharing turned off unless you need it. Recheck after you install new apps.",
                    host: "this-mac"
                )
            )
        } else {
            findings.append(
                Finding(
                    category: .listening,
                    severity: .medium,
                    title: "\(exposed.count) app\(exposed.count == 1 ? "" : "s") on this Mac can be reached from other devices",
                    detail: summary(exposed),
                    remediation: "If you do not need the app to talk to other devices, quit it or turn off the matching Sharing switch.",
                    host: "this-mac",
                    evidence: summary(exposed)
                )
            )
        }

        for socket in exposed {
            let guide = PortCatalog.homeGuide(for: socket.port, onThisMac: true)
            let remote = Self.remoteProcessHints.contains(where: { socket.process.lowercased().contains($0) })
            findings.append(
                Finding(
                    category: remote ? .remoteAccess : .listening,
                    severity: max(PortCatalog.profile(for: socket.port).risk, .medium),
                    title: "\(guide.headline) (\(socket.process))",
                    detail: "The app “\(socket.process)” is waiting for connections from the network on port \(socket.port). \(guide.meaning)",
                    remediation: guide.fix,
                    host: "this-mac",
                    evidence: "\(socket.process) pid=\(socket.pid) \(socket.address):\(socket.port)"
                )
            )
        }

        return findings
    }

    private static let remoteProcessHints = [
        "sshd", "screensharing", "ardagent", "vnc", "teamviewer", "anydesk",
        "splashtop", "chrome_remote", "remotix", "ssh", "smbd", "afp",
        "applefileserver", "remotemanagement"
    ]

    private static func summary(_ sockets: [ListeningSocket]) -> String {
        sockets
            .map { "\($0.process)  (port \($0.port))" }
            .joined(separator: "\n")
    }

    static func parseLsof() -> [ListeningSocket] {
        let output = Shell.run("/usr/sbin/lsof", ["-nP", "-iTCP", "-sTCP:LISTEN"])
            ?? Shell.run("/usr/sbin/lsof", ["-nP", "-iTCP"])
            ?? ""
        var sockets: [ListeningSocket] = []
        for line in output.split(separator: "\n").dropFirst() {
            let cols = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard cols.count >= 9 else { continue }
            let process = cols[0]
            let pid = cols[1]
            guard let name = cols.last else { continue }
            guard name.contains("LISTEN") || cols.contains(where: { $0.contains("LISTEN") }) else { continue }
            let endpoint = cols.first(where: { $0.contains(":") && !$0.contains("->") }) ?? name
            let parsed = parseEndpoint(endpoint)
            guard let port = parsed.port else { continue }
            sockets.append(
                ListeningSocket(
                    address: parsed.address,
                    port: port,
                    process: process,
                    pid: pid,
                    exposed: isExposed(parsed.address)
                )
            )
        }
        var seen = Set<String>()
        return sockets.filter { seen.insert($0.id).inserted }
    }

    private static func parseEndpoint(_ raw: String) -> (address: String, port: UInt16?) {
        var value = raw
        if let range = value.range(of: " (LISTEN)") {
            value = String(value[..<range.lowerBound])
        }
        if value.hasPrefix("[") {
            if let close = value.firstIndex(of: "]") {
                let addr = String(value[value.index(after: value.startIndex)..<close])
                let rest = value[value.index(after: close)...]
                let port = UInt16(rest.trimmingCharacters(in: CharacterSet(charactersIn: ":")))
                return (addr, port)
            }
        }
        if let colon = value.lastIndex(of: ":") {
            let addr = String(value[..<colon])
            let port = UInt16(value[value.index(after: colon)...])
            return (addr, port)
        }
        return (value, nil)
    }

    private static func isExposed(_ address: String) -> Bool {
        let local = ["127.0.0.1", "::1", "localhost"]
        return !local.contains(address)
    }

    // MARK: - Sharing

    static func sharingServices() -> [Finding] {
        var findings: [Finding] = []

        let checks: [(label: String, job: String, severity: Severity, why: String, steps: String)] = [
            (
                "Remote Login",
                "com.openssh.sshd",
                .high,
                "Other computers can try to sign in to this Mac over the network.",
                "System Settings → General → Sharing → turn off Remote Login."
            ),
            (
                "Screen Sharing",
                "com.apple.screensharing",
                .high,
                "Someone on your Wi-Fi could try to see and control this screen.",
                "System Settings → General → Sharing → turn off Screen Sharing."
            ),
            (
                "Remote Management",
                "com.apple.RemoteDesktop.PrivilegeProxy",
                .critical,
                "This gives full remote control of the Mac. Almost nobody needs it at home.",
                "System Settings → General → Sharing → turn off Remote Management."
            ),
            (
                "File Sharing",
                "com.apple.smbd",
                .medium,
                "Folders on this Mac can be opened from other devices on the Wi-Fi.",
                "System Settings → General → Sharing → turn off File Sharing. If you need it, turn off guest access and share only specific folders."
            ),
            (
                "Remote Apple Events",
                "com.apple.AEServer",
                .high,
                "Other Macs can send this computer commands. It is rarely needed at home.",
                "System Settings → General → Sharing → turn off Remote Apple Events."
            )
        ]

        for check in checks {
            let uid = getuid()
            let printout = Shell.run("/bin/launchctl", ["print", "system/\(check.job)"])
                ?? Shell.run("/bin/launchctl", ["print", "gui/\(uid)/\(check.job)"])
                ?? ""
            let enabled = printout.contains("state = running")
                || printout.contains("runs =")
                || (printout.contains("path =") && !printout.contains("Could not find service"))
            let missing = printout.isEmpty || printout.contains("Could not find service") || printout.contains("does not exist")

            if enabled && !missing {
                findings.append(
                    Finding(
                        category: .remoteAccess,
                        severity: check.severity,
                        title: "\(check.label) is turned on",
                        detail: check.why,
                        remediation: check.steps,
                        host: "this-mac",
                        evidence: String(printout.prefix(400))
                    )
                )
            } else {
                findings.append(
                    Finding(
                        category: .hardening,
                        severity: .info,
                        title: "\(check.label) is off",
                        detail: "This door into the Mac is closed. That is what you want unless you use this feature on purpose.",
                        remediation: "Leave it off.",
                        host: "this-mac"
                    )
                )
            }
        }

        return findings
    }

    // MARK: - Firewall

    static func firewallAndStealth() -> [Finding] {
        var findings: [Finding] = []
        let fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        let global = Shell.run(fw, ["--getglobalstate"]) ?? ""
        let stealth = Shell.run(fw, ["--getstealthmode"]) ?? ""

        let enabled = global.lowercased().contains("enabled")
        findings.append(
            Finding(
                category: .hardening,
                severity: enabled ? .info : .high,
                title: enabled ? "Firewall is on" : "Firewall is off",
                detail: enabled
                    ? "macOS is deciding which apps may accept connections from other devices."
                    : "Without the firewall, any app that starts listening is easier to reach from your Wi-Fi.",
                remediation: enabled
                    ? "Leave it on. You can review apps under System Settings → Network → Firewall → Options."
                    : "System Settings → Network → Firewall → turn it on.",
                host: "this-mac",
                evidence: global
            )
        )

        let stealthOn = stealth.lowercased().contains("enabled")
        findings.append(
            Finding(
                category: .hardening,
                severity: stealthOn ? .info : .low,
                title: stealthOn ? "Stealth Mode is on" : "Stealth Mode is off",
                detail: stealthOn
                    ? "This Mac stays quieter when unknown devices poke the network."
                    : "Stealth Mode makes this Mac ignore unexpected knocks. It is a small extra privacy win on Wi-Fi.",
                remediation: "System Settings → Network → Firewall → Options → turn on Stealth Mode.",
                host: "this-mac"
            )
        )

        return findings
    }

    // MARK: - SIP / FileVault / Gatekeeper

    static func systemGuards() -> [Finding] {
        var findings: [Finding] = []

        let sip = Shell.run("/usr/bin/csrutil", ["status"]) ?? ""
        if sip.lowercased().contains("disabled") {
            findings.append(
                Finding(
                    category: .hardening,
                    severity: .critical,
                    title: "A built-in macOS protection is turned off",
                    detail: "System Integrity Protection (SIP) stops ordinary apps from changing the most sensitive parts of macOS. It should stay on.",
                    remediation: "Restart into Recovery (hold the power button on Apple silicon until “Loading startup options” appears), open Safari or Terminal from the menu, and run: csrutil enable. Then restart.",
                    host: "this-mac",
                    evidence: sip
                )
            )
        } else {
            findings.append(
                Finding(
                    category: .hardening,
                    severity: .info,
                    title: "Built-in macOS protection is on",
                    detail: "System Integrity Protection is doing its job in the background.",
                    remediation: "Leave it on. You never need to disable this for normal use.",
                    host: "this-mac"
                )
            )
        }

        let fv = Shell.run("/usr/bin/fdesetup", ["status"]) ?? ""
        if fv.lowercased().contains("off") || fv.lowercased().contains("off.") {
            findings.append(
                Finding(
                    category: .hardening,
                    severity: .high,
                    title: "Disk encryption is off",
                    detail: "If this Mac is lost or stolen, files on the disk can be read by plugging the drive into another computer.",
                    remediation: "System Settings → Privacy & Security → FileVault → turn it on. Save the recovery key somewhere that is not this Mac.",
                    host: "this-mac",
                    evidence: fv
                )
            )
        } else {
            findings.append(
                Finding(
                    category: .hardening,
                    severity: .info,
                    title: "Disk encryption is on",
                    detail: "FileVault is protecting the files on this disk if the Mac is lost.",
                    remediation: "Keep FileVault on and store the recovery key somewhere safe.",
                    host: "this-mac"
                )
            )
        }

        let gk = Shell.run("/usr/sbin/spctl", ["--status"]) ?? ""
        if gk.lowercased().contains("disabled") {
            findings.append(
                Finding(
                    category: .hardening,
                    severity: .high,
                    title: "App safety checks are turned off",
                    detail: "Gatekeeper is the macOS feature that warns you about apps from unknown developers. It should stay on.",
                    remediation: "Open Terminal and run: sudo spctl --global-enable. Prefer apps from the App Store or the developer’s own site.",
                    host: "this-mac",
                    evidence: gk
                )
            )
        } else {
            findings.append(
                Finding(
                    category: .hardening,
                    severity: .info,
                    title: "App safety checks are on",
                    detail: "macOS will warn you before opening software from unknown developers.",
                    remediation: "Do not click “Open Anyway” for a download you do not trust.",
                    host: "this-mac"
                )
            )
        }

        return findings
    }

    static func automaticUpdates() -> [Finding] {
        let plist = "/Library/Preferences/com.apple.SoftwareUpdate"
        let check = Shell.run("/usr/bin/defaults", ["read", plist, "AutomaticCheckEnabled"]) ?? ""
        let install = Shell.run("/usr/bin/defaults", ["read", plist, "AutomaticallyInstallMacOSUpdates"]) ?? ""
        let security = Shell.run("/usr/bin/defaults", ["read", plist, "CriticalUpdateInstall"]) ?? ""

        let checkOff = check.trimmingCharacters(in: .whitespacesAndNewlines) == "0"
        let installOff = install.trimmingCharacters(in: .whitespacesAndNewlines) == "0"
        let securityOff = security.trimmingCharacters(in: .whitespacesAndNewlines) == "0"

        if checkOff || installOff || securityOff {
            return [
                Finding(
                    category: .hardening,
                    severity: .medium,
                    title: "Automatic updates are not fully on",
                    detail: "macOS can download and install security fixes by itself. Leaving that off means holes stay open until you remember to check.",
                    remediation: "System Settings → General → Software Update → Automatic Updates. Turn on checking, downloading, macOS updates, and security responses.",
                    host: "this-mac",
                    evidence: "AutomaticCheckEnabled=\(check.trimmingCharacters(in: .whitespacesAndNewlines)) AutomaticallyInstallMacOSUpdates=\(install.trimmingCharacters(in: .whitespacesAndNewlines)) CriticalUpdateInstall=\(security.trimmingCharacters(in: .whitespacesAndNewlines))"
                )
            ]
        }

        return [
            Finding(
                category: .hardening,
                severity: .info,
                title: "Automatic updates look on",
                detail: "This Mac is set to look for (and usually install) Apple’s security updates.",
                remediation: "Leave Automatic Updates on, and restart when macOS asks.",
                host: "this-mac"
            )
        ]
    }

    static func guestAccount() -> [Finding] {
        let raw = Shell.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"]) ?? ""
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed == "1" {
            return [
                Finding(
                    category: .hardening,
                    severity: .medium,
                    title: "The Guest User account is on",
                    detail: "A guest account lets anyone sit down and use this Mac without your password. Fine for a family iMac in the kitchen; usually a bad idea on a laptop.",
                    remediation: "System Settings → Users & Groups → Guest User → turn off “Allow guests to log in”.",
                    host: "this-mac",
                    evidence: trimmed
                )
            ]
        }
        return [
            Finding(
                category: .hardening,
                severity: .info,
                title: "Guest User is off",
                detail: "Only people with an account can log in to this Mac.",
                remediation: "Leave Guest User off on laptops.",
                host: "this-mac"
            )
        ]
    }

    static func remoteManagementHints() -> [Finding] {
        let path = "/Library/Preferences/com.apple.RemoteManagement.plist"
        guard FileManager.default.fileExists(atPath: path) else { return [] }
        let contents = Shell.run("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.RemoteManagement"]) ?? ""
        return [
            Finding(
                category: .remoteAccess,
                severity: .high,
                title: "Remote Management looks configured",
                detail: "This Mac has been set up for Apple Remote Desktop, which allows full remote control.",
                remediation: "System Settings → General → Sharing → turn off Remote Management if you do not use it.",
                host: "this-mac",
                evidence: contents
            )
        ]
    }
}

enum Shell {
    @discardableResult
    static func run(_ launchPath: String, _ arguments: [String], timeout: TimeInterval = 8) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        do {
            try process.run()
        } catch {
            return nil
        }

        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if process.isRunning {
            process.terminate()
        }

        let data = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        let combined = data + errData
        return String(data: combined, encoding: .utf8)
    }
}
