import Foundation

struct PortProfile: Sendable {
    let service: String
    let risk: Severity
    let reason: String
    let identificationProbe: IdentificationProbe
}

enum IdentificationProbe: Sendable {
    case bannerOnly
    case httpHead
}

enum PortCatalog {
    /// Ports commonly abused for remote access, lateral movement, or exposed admin surfaces.
    /// Identification only — no authentication attempts and no exploit payloads.
    static let profiles: [UInt16: PortProfile] = {
        var map: [UInt16: PortProfile] = [:]

        func add(
            _ ports: [UInt16],
            _ service: String,
            _ risk: Severity,
            _ reason: String,
            probe: IdentificationProbe = .bannerOnly
        ) {
            for port in ports {
                map[port] = PortProfile(
                    service: service,
                    risk: risk,
                    reason: reason,
                    identificationProbe: probe
                )
            }
        }

        add([21], "FTP", .high, "FTP is unencrypted and frequently targeted for credential theft and anonymous file access.")
        add([69], "TFTP", .high, "TFTP has no authentication and can leak or overwrite files.")
        add([22], "SSH", .medium, "Remote shell. Safe if key-only and patched; risky if exposed with password authentication.")
        add([23, 2323], "Telnet", .critical, "Telnet is unencrypted remote access and should never be reachable on a modern network.")
        add([512, 513, 514], "r-services", .critical, "Legacy rsh/rlogin/rexec allow remote command execution with weak or no authentication.")
        add([3389], "RDP", .critical, "Remote Desktop is a primary ransomware and brute-force target.")
        add([5900, 5901, 5902], "VNC / Screen Sharing", .high, "Graphical remote desktop. Often weakly authenticated on home and lab networks.")
        add([3283, 5900], "Apple Remote Desktop", .high, "Apple Remote Desktop / screen control can grant full interactive access.")
        add([5985, 5986], "WinRM", .critical, "Windows remote management — full administrative remote execution if reachable.")
        add([5984], "CouchDB", .high, "Database admin interfaces are frequently left open with default credentials.")
        add([8291, 8292, 8293], "MikroTik / Winbox", .high, "Router admin surfaces are high-value targets when exposed on LAN or WAN.")
        add([7547], "TR-069 / CWMP", .high, "ISP CPE management protocol; historically abused for remote device takeover.")
        add([5555], "ADB", .high, "Android Debug Bridge can yield a remote shell on misconfigured devices.")
        add([2375], "Docker API (plaintext)", .critical, "Unauthenticated Docker API can give root on the host.")
        add([2376], "Docker API (TLS)", .medium, "Docker API should not be reachable from untrusted hosts even with TLS.")
        add([6443, 10250, 10255], "Kubernetes", .high, "Kubernetes API / kubelet exposure can lead to cluster takeover.")
        add([2379, 2380], "etcd", .critical, "etcd often holds cluster secrets; unauthenticated access is severe.")
        add([445, 139], "SMB", .high, "File sharing / SMB is a classic worm and ransomware path (including guest shares).")
        add([135], "MSRPC / epmap", .high, "Windows RPC endpoint mapper; used to locate other RPC services.")
        add([593], "RPC over HTTP", .high, "RPC over HTTP is a Windows remote-management path.")
        add([1025, 1026, 1027, 1028, 1029], "Windows RPC dynamic", .medium, "Common Windows RPC / service ports after the mapper.")
        add([5357], "WSDAPI / Network Discovery", .low, "Windows Network Discovery web service.")
        add([3702], "WS-Discovery", .low, "Web Services Dynamic Discovery.")
        add([3268, 3269], "Global Catalog", .medium, "Active Directory global catalog.")
        add([88], "Kerberos", .medium, "Authentication service; useful to attackers mapping a domain.")
        add([464], "kpasswd", .low, "Kerberos password-change service.")
        add([3260], "iSCSI", .high, "Block storage target; should not be on a general LAN.")
        add([1521], "Oracle TNS", .high, "Oracle listener; often weakly authenticated.")
        add([1080], "SOCKS", .medium, "Proxy port; unexpected SOCKS on a LAN can be a pivot.")
        add([3128], "HTTP proxy", .medium, "Forward proxy. Confirm it is not an open relay.", probe: .httpHead)
        add([5984], "CouchDB", .high, "Database admin interfaces are frequently left open with default credentials.", probe: .httpHead)
        add([548], "AFP", .medium, "Apple Filing Protocol exposes shared files if guest or weak auth is enabled.")
        add([2049, 111], "NFS / rpcbind", .high, "NFS exports and rpcbind can disclose or share files without strong auth.")
        add([873], "rsync", .high, "rsync modules are often unauthenticated and can sync entire filesystems.")
        add([88], "Kerberos", .medium, "Authentication service; useful to attackers mapping a domain.")
        add([389], "LDAP", .medium, "Directory service may leak users, computers, and configuration.")
        add([636], "LDAPS", .low, "Encrypted directory service; still an admin surface.")
        add([161, 162], "SNMP", .high, "SNMP can leak network configuration; community strings are often public/private.")
        add([1900], "UPnP / SSDP", .medium, "UPnP can punch WAN holes and expose internal services.")
        add([5353], "mDNS", .info, "Multicast DNS advertises devices and services on the LAN.")
        add([80, 8080, 8000, 8008, 8888, 5000, 3000, 4173], "HTTP", .medium, "Unencrypted web / admin UI. Check for exposed routers, NAS, cameras, and app consoles.", probe: .httpHead)
        add([443, 8443, 4443], "HTTPS", .low, "Encrypted web. Still review for exposed admin panels.", probe: .httpHead)
        add([631], "IPP / CUPS", .medium, "Printer service; CUPS has a history of remote code execution bugs.")
        add([9100], "JetDirect", .low, "Raw printer port; usually local-only risk.")
        add([3306], "MySQL / MariaDB", .high, "Database should not be reachable beyond the app host.")
        add([5432], "PostgreSQL", .high, "Database should not be reachable beyond the app host.")
        add([1433, 1434], "MSSQL", .high, "SQL Server is a frequent ransomware staging target.")
        add([27017, 27018], "MongoDB", .critical, "Historically left unauthenticated on 0.0.0.0; ransomware and data theft target.")
        add([6379], "Redis", .critical, "Redis is often unauthenticated and can lead to remote code execution via config writes.")
        add([11211], "Memcached", .high, "Unauthenticated memory cache; can leak session data or be abused in amplification.")
        add([9200, 9300], "Elasticsearch", .high, "Search cluster APIs frequently exposed without auth.")
        add([5601], "Kibana", .medium, "Ops dashboard; often shares access with Elasticsearch.")
        add([5672], "AMQP / RabbitMQ", .high, "Message broker; default guest/guest is well known.")
        add([1883], "MQTT", .medium, "IoT message bus; often has no authentication on LAN.")
        add([8883], "MQTT/TLS", .low, "Encrypted MQTT. Confirm authentication is required.")
        add([25, 587, 465], "SMTP", .medium, "Mail transfer; open relays and unauthenticated submission are abused for spam.")
        add([110, 995], "POP3", .low, "Mail retrieval.")
        add([143, 993], "IMAP", .low, "Mail retrieval.")
        add([53], "DNS", .medium, "Open resolvers can be abused; also maps internal names.")
        add([67, 68], "DHCP", .medium, "Rogue DHCP on a LAN can intercept traffic.")
        add([123], "NTP", .low, "Time service; mainly an amplification/info leak concern.")
        add([161], "SNMP", .high, "Management protocol with weak community-string auth.")
        add([1723], "PPTP", .high, "Broken VPN protocol.")
        add([1194, 51820], "OpenVPN / WireGuard", .info, "VPN endpoint. Expected if you run a VPN; unexpected otherwise.")
        add([500, 4500], "IPsec / IKE", .info, "VPN endpoint.")
        add([9418], "Git", .medium, "Unauthenticated git:// protocol can leak source.")
        add([62078], "lockdownd (iOS)", .info, "Apple mobile device pairing service.")
        add([7000], "AirPlay", .low, "Media receiver advertised on the LAN.")
        add([3689], "DAAP", .low, "iTunes / Music sharing.")
        add([5480], "VMware?", .medium, "Common hypervisor or appliance admin port.")
        add([9440], "Nutanix / appliance", .medium, "Common virtualization admin TLS port.")
        add([8834], "Nessus", .medium, "Vulnerability scanner console.")
        add([10000], "Webmin / NDMP", .high, "Webmin and backup services are frequently targeted.")
        add([8081, 8090, 9090], "Alt HTTP admin", .medium, "Secondary web consoles (proxies, NAS, CI).", probe: .httpHead)
        add([9000, 9001], "App / Tor", .medium, "Common app or proxy admin port.")
        add([6667, 6697], "IRC", .low, "Chat service; also used as malware C2 historically.")
        add([5060, 5061], "SIP", .medium, "VoIP signaling; often abused for toll fraud.")
        add([554], "RTSP", .medium, "Camera streams are frequently unauthenticated.")
        add([8554], "RTSP alt", .medium, "Alternate camera stream port.")
        add([81, 82, 8082], "Camera / IoT HTTP", .high, "Consumer cameras and IoT admin pages are a common LAN foothold.", probe: .httpHead)
        add([23], "Telnet", .critical, "Cleartext remote shell.")
        add([2222], "SSH alt", .medium, "Non-standard SSH port still provides remote shell access.")
        add([2200], "SSH alt", .medium, "Non-standard SSH port.")
        add([4899], "Radmin", .high, "Third-party remote-control software.")
        add([5938], "TeamViewer", .medium, "Remote-control software. Confirm you expect it.")
        add([7070], "RealServer / alt", .low, "Less common media/admin port.")
        add([16992, 16993], "Intel AMT", .critical, "Intel AMT/vPro out-of-band management can outlive the OS.")
        add([623], "IPMI", .critical, "BMC / IPMI out-of-band management; default passwords are common.")
        add([5120, 5121], "iLO / BMC alt", .high, "Server light-out management.")
        add([17988, 17990], "iLO", .high, "HPE iLO remote console.")
        add([5000], "UPnP / Flask / AirTunes", .medium, "Often an app dev server or UPnP control point.", probe: .httpHead)
        add([7001], "WebLogic", .high, "Enterprise app server admin; frequently unpatched.")
        add([4848], "GlassFish admin", .high, "App-server admin console.")
        add([8161], "ActiveMQ", .high, "Message-broker web console.")
        add([15672], "RabbitMQ management", .high, "Broker admin UI; default guest account is well known.")
        add([8500], "Consul", .high, "Service discovery; can expose cluster membership and KV secrets.")
        add([8300, 8301], "Consul RPC", .high, "Consul cluster ports.")
        add([4646], "Nomad", .high, "Scheduler API; job submit equals remote execution.")
        add([8200], "Vault", .medium, "Secrets manager. Should not be open to the whole LAN.")
        add([9418], "git", .medium, "Git protocol.")

        return map
    }()

    static let discoveryPorts: [UInt16] = [22, 80, 443, 445, 548, 631, 3389, 5900, 5353, 62078, 8080]

    static let defaultScanPorts: [UInt16] = {
        let keys = Set(profiles.keys)
        let extras: [UInt16] = [21, 22, 23, 80, 139, 443, 445, 3389, 5900, 22]
        return Array(keys.union(extras)).sorted()
    }()

    static func profile(for port: UInt16) -> PortProfile {
        profiles[port] ?? PortProfile(
            service: "unknown",
            risk: .low,
            reason: "This device has an extra door open. If you do not recognize the device, look it up or unplug it.",
            identificationProbe: .bannerOnly
        )
    }

    struct HomeGuide: Sendable {
        let headline: String
        let meaning: String
        let fix: String
    }

    static func homeGuide(for port: UInt16, onThisMac: Bool = false) -> HomeGuide {
        let whereTo = onThisMac ? "this Mac" : "this device"
        switch port {
        case 22, 2222, 2200:
            return HomeGuide(
                headline: "Remote login is on",
                meaning: "Someone on your Wi-Fi could try to sign in to \(whereTo) as if they were sitting at the keyboard.",
                fix: onThisMac
                    ? "System Settings → General → Sharing → turn off Remote Login."
                    : "Turn off SSH / remote login in this device’s settings if you do not use it."
            )
        case 23, 2323:
            return HomeGuide(
                headline: "An old, unsafe remote login is on",
                meaning: "Telnet sends passwords in the clear. Nothing on a home network should still offer this.",
                fix: "Turn Telnet off. If this is a router or camera, replace it if you cannot disable Telnet."
            )
        case 3389, 5985, 5986:
            return HomeGuide(
                headline: "Windows remote desktop is on",
                meaning: "This is a common way thieves lock people out of a computer and demand money.",
                fix: "On that PC: Settings → System → Remote Desktop → Off, unless you truly use it through a VPN."
            )
        case 5900, 5901, 5902, 3283:
            return HomeGuide(
                headline: "Screen sharing is on",
                meaning: "Someone on your Wi-Fi could try to see and control the screen.",
                fix: onThisMac
                    ? "System Settings → General → Sharing → turn off Screen Sharing and Remote Management."
                    : "Turn off VNC / screen sharing on this device if you do not need it."
            )
        case 445, 139:
            return HomeGuide(
                headline: "File sharing is on",
                meaning: "Folders on \(whereTo) may be visible to other devices on the Wi-Fi.",
                fix: onThisMac
                    ? "System Settings → General → Sharing → turn off File Sharing, or at least turn off guest access."
                    : "Turn off guest file sharing and use a password if you actually need to share files."
            )
        case 548:
            return HomeGuide(
                headline: "Mac file sharing is on",
                meaning: "Another Mac can see shared folders on this computer.",
                fix: "System Settings → General → Sharing → File Sharing. Turn it off if you do not use it."
            )
        case 80, 8080, 8000, 8008, 8888, 81, 82, 8082:
            return HomeGuide(
                headline: "A web admin page is open",
                meaning: "Routers, cameras, printers, and gadgets often put their settings on a web page. Anyone on your Wi-Fi can try to open it.",
                fix: "Change the device’s password from the default, and do not allow access from the internet (WAN / remote management)."
            )
        case 443, 8443, 4443:
            return HomeGuide(
                headline: "A locked web page is open",
                meaning: "This is usually a settings page using https. Still change the default password.",
                fix: "Sign in, set a unique password, and turn off remote access from outside the home."
            )
        case 554, 8554:
            return HomeGuide(
                headline: "A camera stream looks available",
                meaning: "Live video can sometimes be watched by anyone on the same Wi-Fi — and from the internet if the router was talked into opening a hole.",
                fix: "Set a camera password, put cameras on a guest network, and turn off “access from anywhere” unless you really want that."
            )
        case 21:
            return HomeGuide(
                headline: "Old-style file transfer is on",
                meaning: "FTP is outdated and often has no real password.",
                fix: "Turn FTP off. Use the device’s app or a modern share if you need the files."
            )
        case 161, 162:
            return HomeGuide(
                headline: "Network management (SNMP) is on",
                meaning: "This can leak Wi-Fi names, device lists, and settings. Home gadgets often leave the password as “public”.",
                fix: "Disable SNMP on the router or gadget, or change the community string from public/private."
            )
        case 1900:
            return HomeGuide(
                headline: "UPnP is talking on the network",
                meaning: "Gadgets use this to open ports on the router by themselves. That is how cameras and file shares sometimes end up on the internet.",
                fix: "Turn UPnP off in the router admin page if you can."
            )
        case 631, 9100:
            return HomeGuide(
                headline: "Printer sharing is on",
                meaning: "Normal at home. Just make sure the printer’s own admin password is not still the default.",
                fix: "Open the printer’s settings page and change the admin password if it is still admin/admin or blank."
            )
        case 3306, 5432, 1433, 27017, 6379, 9200, 11211:
            return HomeGuide(
                headline: "A database is reachable on the Wi-Fi",
                meaning: "This is unusual on a family network. If you did not set it up, find out which app did.",
                fix: "Quit the app that started it, or bind it to localhost so only this computer can use it."
            )
        case 5938, 4899:
            return HomeGuide(
                headline: "Remote-control software is running",
                meaning: "TeamViewer and similar tools are fine if you installed them. They are a red flag if you did not.",
                fix: "If you do not use this, uninstall it. Never allow a stranger on the phone to install it."
            )
        default:
            let profile = profile(for: port)
            return HomeGuide(
                headline: "\(profile.service) is available",
                meaning: "\(whereTo.prefix(1).uppercased() + whereTo.dropFirst()) is offering “\(profile.service)” to the rest of your Wi-Fi.",
                fix: "If you do not use this, turn it off in the device’s settings."
            )
        }
    }
}
