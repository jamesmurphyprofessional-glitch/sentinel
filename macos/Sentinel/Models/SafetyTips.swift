import Foundation

enum TipTopic: String, CaseIterable, Identifiable, Sendable {
    case wifi
    case mac
    case habits

    var id: String { rawValue }

    var label: String {
        switch self {
        case .wifi: return "Wi-Fi & router"
        case .mac: return "This Mac"
        case .habits: return "Everyday habits"
        }
    }

    var systemImage: String {
        switch self {
        case .wifi: return "wifi"
        case .mac: return "laptopcomputer"
        case .habits: return "person.fill.checkmark"
        }
    }
}

struct SafetyTip: Identifiable, Hashable, Sendable {
    let id: String
    let topic: TipTopic
    let title: String
    let summary: String
    let why: String
    let steps: [String]
    let systemImage: String
}

enum SafetyTips {
    static let all: [SafetyTip] = wifi + mac + habits

    static let wifi: [SafetyTip] = [
        SafetyTip(
            id: "wifi-password",
            topic: .wifi,
            title: "Use a strong Wi-Fi password",
            summary: "The password for your home network should be long and unique — not the one printed on the sticker if you can change it.",
            why: "Anyone who knows your Wi-Fi password can use your internet, see devices on your network, and sometimes reach shared folders or cameras.",
            steps: [
                "On a computer already on the Wi-Fi, open a browser and go to your router page. This is often 192.168.1.1 or 192.168.0.1, or the address shown on the router sticker.",
                "Sign in with the router admin name and password (this is different from the Wi-Fi password).",
                "Find Wireless / Wi-Fi settings and set a new password. Use at least 12 characters, with words and numbers you will remember.",
                "Security mode should be WPA3 if every device supports it, otherwise WPA2. Do not use Open, None, or WEP.",
                "Save, then reconnect phones, TVs, and computers with the new password."
            ],
            systemImage: "key.fill"
        ),
        SafetyTip(
            id: "router-admin",
            topic: .wifi,
            title: "Change the router’s own login",
            summary: "The page that controls your Wi-Fi often still uses admin / admin or a password printed on the box.",
            why: "If someone on your Wi-Fi can open that page, they can change your Wi-Fi password, turn on remote access, or send your traffic somewhere else.",
            steps: [
                "Open the router admin page in a browser (same address as above).",
                "Look for Administration, System, or Password.",
                "Set a new admin password that is not the Wi-Fi password and not a default like admin, password, or 1234.",
                "Turn off “remote management” or “WAN access” so the admin page cannot be reached from outside your home."
            ],
            systemImage: "lock.rectangle.stack.fill"
        ),
        SafetyTip(
            id: "guest-wifi",
            topic: .wifi,
            title: "Put visitors and gadgets on a guest network",
            summary: "Most home routers can make a second Wi-Fi just for guests, TVs, bulbs, and cameras.",
            why: "A guest network lets people get online without seeing your computers or shared files. Smart gadgets get hacked more often than phones, so they are safer in their own lane.",
            steps: [
                "In the router admin page, look for Guest Network or Guest Wi-Fi.",
                "Turn it on, give it its own name and password, and leave “isolate guests” or “AP isolation” enabled if you see it.",
                "Connect visitors, smart TVs, bulbs, plugs, and cameras to the guest network.",
                "Keep phones, computers, and printers you trust on the main network."
            ],
            systemImage: "person.2.fill"
        ),
        SafetyTip(
            id: "router-updates",
            topic: .wifi,
            title: "Keep the router’s software current",
            summary: "Routers need updates too. Old router software is a common way into home networks.",
            why: "Attackers look for known bugs in popular home routers. An update is often a one-time click and then a short restart.",
            steps: [
                "Open the router admin page.",
                "Find Firmware, System Update, or Advanced → Administration.",
                "Check for an update and install it. The internet may drop for a minute while it restarts.",
                "If the router is more than about six years old and no longer gets updates, consider replacing it."
            ],
            systemImage: "arrow.triangle.2.circlepath"
        ),
        SafetyTip(
            id: "upnp-wps",
            topic: .wifi,
            title: "Turn off WPS and UPnP if you can",
            summary: "These shortcuts make setup easier, and they also make it easier for someone else to open doors into your network.",
            why: "WPS PIN codes can be guessed. UPnP lets devices punch holes through the router so they can be reached from the internet — including cameras and file shares you never meant to publish.",
            steps: [
                "In the router admin page, find WPS and turn it off.",
                "Find UPnP (sometimes under Advanced or NAT) and turn it off.",
                "If a game console or app later needs a port opened, add that one rule by hand instead of leaving UPnP on for everything."
            ],
            systemImage: "xmark.shield.fill"
        ),
        SafetyTip(
            id: "public-wifi",
            topic: .wifi,
            title: "Be careful on coffee-shop and airport Wi-Fi",
            summary: "Public Wi-Fi is convenient. Treat it as if a stranger is sitting on the same network.",
            why: "On open Wi-Fi, someone nearby can sometimes watch unencrypted traffic or set up a fake hotspot with a similar name.",
            steps: [
                "Avoid banking, shopping, and email passwords on public Wi-Fi unless the site shows a lock (https) and you trust it.",
                "Prefer your phone’s hotspot for anything sensitive.",
                "A personal VPN app from a known company adds a useful extra layer on public networks.",
                "Forget the network when you leave so your Mac does not auto-join next time."
            ],
            systemImage: "cup.and.saucer.fill"
        ),
        SafetyTip(
            id: "wifi-name",
            topic: .wifi,
            title: "Do not advertise your router model in the Wi-Fi name",
            summary: "Names like NETGEAR-5G or TP-Link-XXXX tell an attacker exactly which bugs to try.",
            why: "A generic name (the family name, a nickname) is one less clue. You do not need to hide; you just do not need to help.",
            steps: [
                "In Wireless settings, change the network name (SSID) to something that is not the brand or model.",
                "You can leave the network visible. Hiding the name does little and makes your own devices harder to connect."
            ],
            systemImage: "tag.fill"
        )
    ]

    static let mac: [SafetyTip] = [
        SafetyTip(
            id: "mac-password",
            topic: .mac,
            title: "Give this Mac a real login password",
            summary: "If someone picks up your laptop, the login password is the first lock they have to get through.",
            why: "Without a password, anyone with a minute at your desk can read email, files, and saved passwords.",
            steps: [
                "Open System Settings → Users & Groups.",
                "Select your account → Change Password.",
                "Use something long you can remember, or a passphrase of several words. Do not reuse your Apple ID password if you can avoid it.",
                "Turn on a password (or Touch ID / Apple Watch) to unlock the screen under System Settings → Lock Screen."
            ],
            systemImage: "person.badge.key.fill"
        ),
        SafetyTip(
            id: "mac-lock",
            topic: .mac,
            title: "Lock the screen when you walk away",
            summary: "A locked screen is as important at home as it is in a café.",
            why: "Messages, password managers, and banking tabs stay open until the Mac sleeps and asks for a password.",
            steps: [
                "Press Control-Command-Q to lock immediately.",
                "Open System Settings → Lock Screen.",
                "Set “Turn display off” to 5 or 10 minutes, and require a password immediately after sleep or screen saver."
            ],
            systemImage: "lock.fill"
        ),
        SafetyTip(
            id: "mac-updates",
            topic: .mac,
            title: "Turn on automatic updates",
            summary: "Apple’s updates fix security holes. Let the Mac install them without you hunting for them.",
            why: "Most break-ins on home computers use bugs that already have a fix. Automatic updates close those holes for you.",
            steps: [
                "Open System Settings → General → Software Update.",
                "Turn on Automatic Updates.",
                "Click the info button next to it and enable checking, downloading, macOS updates, app updates from the App Store, and security responses.",
                "Install any update that is waiting, then restart when asked."
            ],
            systemImage: "gear.badge"
        ),
        SafetyTip(
            id: "mac-firewall",
            topic: .mac,
            title: "Turn on the Mac firewall",
            summary: "The firewall decides which apps are allowed to accept connections from other devices.",
            why: "If an app starts listening by accident, the firewall is the extra “no” on your Wi-Fi.",
            steps: [
                "Open System Settings → Network → Firewall.",
                "Turn Firewall on.",
                "Open Options and turn on Stealth Mode. That makes this Mac quieter when strangers probe the network.",
                "Leave “Block all incoming connections” off unless you know you need it — it can break printers and file sharing you actually use."
            ],
            systemImage: "flame.fill"
        ),
        SafetyTip(
            id: "mac-filevault",
            topic: .mac,
            title: "Turn on FileVault disk encryption",
            summary: "FileVault scrambles the disk so a stolen Mac is just a brick without your password.",
            why: "If the laptop is lost, FileVault keeps photos, tax files, and saved logins unreadable.",
            steps: [
                "Open System Settings → Privacy & Security.",
                "Find FileVault and turn it on.",
                "Allow it to use your iCloud account for recovery, or save the recovery key somewhere safe — not on this Mac.",
                "Keep the Mac plugged in the first time; the first encryption pass can take a while."
            ],
            systemImage: "internaldrive.fill"
        ),
        SafetyTip(
            id: "mac-sharing",
            topic: .mac,
            title: "Turn sharing off unless you use it",
            summary: "Remote Login, Screen Sharing, File Sharing, and Remote Management are doors into this Mac.",
            why: "On home Wi-Fi those doors are visible to every phone and gadget on the same network. Most people never need them.",
            steps: [
                "Open System Settings → General → Sharing.",
                "Turn off Screen Sharing, File Sharing, Remote Login, Remote Management, and Remote Apple Events unless you know you use that feature.",
                "If you do need File Sharing, turn off guest access and share only the folders you mean to share."
            ],
            systemImage: "shared.with.you.slash"
        ),
        SafetyTip(
            id: "mac-gatekeeper",
            topic: .mac,
            title: "Only install apps you trust",
            summary: "macOS already blocks unsigned apps. Do not override that for a random download.",
            why: "Fake “codec”, “cleaner”, and “update” downloads are a common way junk software gets onto a Mac.",
            steps: [
                "Prefer the App Store, or the company’s own website (Apple, Microsoft, Google, Adobe, and so on).",
                "If macOS says an app cannot be opened, do not click Open Anyway unless you are sure who made it.",
                "Avoid “Mac cleaner”, “driver updater”, and browser pop-ups that insist you must install something now."
            ],
            systemImage: "checkmark.seal.fill"
        ),
        SafetyTip(
            id: "mac-findmy",
            topic: .mac,
            title: "Turn on Find My for this Mac",
            summary: "If the laptop is lost, Find My helps you locate it, lock it, or erase it.",
            why: "FileVault protects the files. Find My helps you get the computer back — or make sure nobody else can use it.",
            steps: [
                "Open System Settings → your name (Apple ID) → Find My.",
                "Turn on Find My Mac.",
                "On an iPhone, open the Find My app and confirm this Mac appears."
            ],
            systemImage: "location.fill"
        )
    ]

    static let habits: [SafetyTip] = [
        SafetyTip(
            id: "apple-id-2fa",
            topic: .habits,
            title: "Turn on two-factor for your Apple ID",
            summary: "A second step (a code on your iPhone) stops someone who only has your password.",
            why: "Your Apple ID unlocks photos, iCloud files, Find My, and often saved passwords. One extra step is worth it.",
            steps: [
                "Open System Settings → your name → Sign-In & Security.",
                "Turn on Two-Factor Authentication if it is not already on.",
                "Keep a trusted phone number current so you can recover the account."
            ],
            systemImage: "lock.badge.clock.fill"
        ),
        SafetyTip(
            id: "passwords",
            topic: .habits,
            title: "Use unique passwords, and let the Mac remember them",
            summary: "Reusing one password means one leak unlocks everything.",
            why: "Sites get breached. If the same password is in your email and your bank, that leak becomes a much bigger problem.",
            steps: [
                "Open System Settings → Passwords (or the Passwords app) and save logins in iCloud Keychain.",
                "When Safari offers a strong password, take it.",
                "Turn on two-factor on email, banking, and shopping accounts too."
            ],
            systemImage: "rectangle.and.pencil.and.ellipsis"
        ),
        SafetyTip(
            id: "phishing",
            topic: .habits,
            title: "Do not trust unexpected links or attachments",
            summary: "A message that looks like Apple, your bank, or a shipper can still be fake.",
            why: "Most “hacks” of home users start with a click, not a movie-style break-in.",
            steps: [
                "If a text or email asks you to sign in, open the real app or type the address yourself. Do not tap the link.",
                "Apple will not call or text you out of the blue asking for your password or a verification code.",
                "Be extra careful with “you have a voicemail / unpaid toll / package waiting” messages.",
                "When in doubt, wait and ask the person another way."
            ],
            systemImage: "envelope.badge.shield.half.filled"
        ),
        SafetyTip(
            id: "screenshare-scam",
            topic: .habits,
            title: "Never let a stranger share your screen",
            summary: "“Apple Support”, “Windows Support”, and pop-up virus warnings that want remote access are almost always a scam.",
            why: "Screen sharing hands them the keyboard. They can steal passwords or talk you into buying fake software.",
            steps: [
                "Hang up. Real Apple Support will not cold-call you.",
                "Do not install AnyDesk, TeamViewer, or “cleanup” tools because a pop-up told you to.",
                "If you already shared the screen, disconnect, change important passwords from a different device, and run Software Update."
            ],
            systemImage: "rectangle.badge.xmark"
        ),
        SafetyTip(
            id: "backups",
            topic: .habits,
            title: "Keep a backup",
            summary: "Ransomware and a spilled drink have the same fix: a backup you can restore.",
            why: "Security is not only about keeping people out. It is also about being able to recover if something goes wrong.",
            steps: [
                "Use Time Machine with an external drive, or turn on iCloud for Desktop and Documents if that fits how you work.",
                "Unplug a Time Machine drive when you are not backing up if you want a copy that malware cannot also encrypt.",
                "Check once in a while that you can see files on the backup."
            ],
            systemImage: "externaldrive.badge.timemachine"
        ),
        SafetyTip(
            id: "loginitems",
            topic: .habits,
            title: "Review what opens when you log in",
            summary: "Apps that start by themselves are a common hiding place for junk software.",
            why: "You should recognize every name in that list. If you do not, it does not need to start with the Mac.",
            steps: [
                "Open System Settings → General → Login Items & Extensions.",
                "Remove anything you do not remember installing.",
                "If an item looks unfamiliar, search the name plus “Mac” before you leave it running."
            ],
            systemImage: "list.bullet.rectangle"
        )
    ]
}
