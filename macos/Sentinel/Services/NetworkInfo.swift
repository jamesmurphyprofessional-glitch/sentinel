import Foundation
import SystemConfiguration
import Darwin

enum NetworkInfo {
    static func currentSnapshot() throws -> NetworkSnapshot {
        guard let interface = primaryIPv4Interface() else {
            throw SentinelError.noActiveInterface
        }

        let cidr = cidr(from: interface.netmask)
        let hosts = hostsInSubnet(ip: interface.ip, netmask: interface.netmask)
        let broadcast = broadcastAddress(ip: interface.ip, netmask: interface.netmask)

        return NetworkSnapshot(
            interfaceName: interface.name,
            ipAddress: interface.ip,
            netmask: interface.netmask,
            cidr: cidr,
            broadcast: broadcast,
            gateway: defaultGateway(),
            ssid: currentSSID(),
            hosts: hosts
        )
    }

    private struct IPv4Interface {
        let name: String
        let ip: String
        let netmask: String
    }

    private static func primaryIPv4Interface() -> IPv4Interface? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }

        var candidates: [IPv4Interface] = []
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let iface = cursor {
            defer { cursor = iface.pointee.ifa_next }
            let flags = Int32(iface.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            guard let addr = iface.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }
            guard let netmask = iface.pointee.ifa_netmask else { continue }

            let name = String(cString: iface.pointee.ifa_name)
            let ip = dottedIPv4(addr)
            let mask = dottedIPv4(netmask)
            guard !ip.hasPrefix("169.254.") else { continue }
            candidates.append(IPv4Interface(name: name, ip: ip, netmask: mask))
        }

        let preferred = candidates.first { $0.name.hasPrefix("en") }
            ?? candidates.first { $0.name.hasPrefix("bridge") }
            ?? candidates.first { $0.name.hasPrefix("wlan") }
            ?? candidates.first
        return preferred
    }

    private static func dottedIPv4(_ sa: UnsafePointer<sockaddr>) -> String {
        sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { pointer in
            var addr = pointer.pointee.sin_addr
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            inet_ntop(AF_INET, &addr, &buffer, socklen_t(INET_ADDRSTRLEN))
            return String(cString: buffer)
        }
    }

    static func cidr(from netmask: String) -> Int {
        let parts = netmask.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return 24 }
        return parts.reduce(0) { $0 + $1.nonzeroBitCount }
    }

    static func broadcastAddress(ip: String, netmask: String) -> String {
        let ipParts = ip.split(separator: ".").compactMap { UInt32($0) }
        let maskParts = netmask.split(separator: ".").compactMap { UInt32($0) }
        guard ipParts.count == 4, maskParts.count == 4 else { return ip }
        let octets = zip(ipParts, maskParts).map { $0 | (~$1 & 0xFF) }
        return octets.map(String.init).joined(separator: ".")
    }

    static func hostsInSubnet(ip: String, netmask: String) -> [String] {
        let ipValue = ipv4Value(ip)
        let maskValue = ipv4Value(netmask)
        guard ipValue != 0, maskValue != 0 else { return [] }

        let network = ipValue & maskValue
        let broadcast = network | ~maskValue
        let hostCount = Int(broadcast &- network &- 1)

        // Cap at a /22 equivalent so a misdetected huge subnet cannot freeze the UI.
        let maxHosts = 1022
        if hostCount <= 0 { return [] }
        if hostCount > maxHosts {
            let start = max(network + 1, ipValue > 128 ? ipValue - 128 : network + 1)
            let end = min(broadcast, start + UInt32(maxHosts))
            return stride(from: start, to: end, by: 1).map(dotted(from:))
        }

        return stride(from: network + 1, to: broadcast, by: 1).map(dotted(from:))
    }

    static func ipv4Value(_ dotted: String) -> UInt32 {
        let parts = dotted.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4 else { return 0 }
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    }

    static func dotted(from value: UInt32) -> String {
        [
            (value >> 24) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 8) & 0xFF,
            value & 0xFF
        ].map(String.init).joined(separator: ".")
    }

    static func defaultGateway() -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        process.arguments = ["-rn", "-f", "inet"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard let text = String(data: data, encoding: .utf8) else { return nil }
            for line in text.split(separator: "\n") {
                let cols = line.split(whereSeparator: { $0.isWhitespace })
                guard cols.count >= 2, cols[0] == "default" else { continue }
                let hop = String(cols[1])
                if hop.contains(".") { return hop }
            }
        } catch {
            return nil
        }
        return nil
    }

    static func currentSSID() -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/system_profiler")
        process.arguments = ["SPAirPortDataType", "-json"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            guard
                let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                let airport = json["SPAirPortDataType"] as? [[String: Any]]
            else { return nil }

            for item in airport {
                if let interfaces = item["spairport_airport_interfaces"] as? [[String: Any]] {
                    for iface in interfaces {
                        if let ssid = iface["spairport_current_network_information"] as? [String: Any],
                           let name = ssid["_name"] as? String {
                            return name
                        }
                    }
                }
            }
        } catch {
            return nil
        }
        return nil
    }

    static func reverseName(for ip: String) -> String? {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return nil }

        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let result = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                getnameinfo(sa, socklen_t(MemoryLayout<sockaddr_in>.size), &host, socklen_t(host.count), nil, 0, NI_NAMEREQD)
            }
        }
        guard result == 0 else { return nil }
        let name = String(cString: host)
        return name == ip ? nil : name
    }
}
