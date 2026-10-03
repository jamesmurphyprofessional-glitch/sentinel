using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Sentinel.Models;

namespace Sentinel.Services;

public static class NetworkInfoService
{
    public static NetworkSnapshot Current()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;

            var props = nic.GetIPProperties();
            var uni = props.UnicastAddresses.FirstOrDefault(a =>
                a.Address.AddressFamily == AddressFamily.InterNetwork &&
                !IPAddress.IsLoopback(a.Address) &&
                !a.Address.ToString().StartsWith("169.254.", StringComparison.Ordinal));
            if (uni == null) continue;

            var ip = uni.Address.ToString();
            var mask = uni.IPv4Mask?.ToString() ?? "255.255.255.0";
            var cidr = Cidr(mask);
            if (cidr < 16) cidr = 22; // safety cap for huge subnets
            if (cidr < 22) cidr = 22;

            var gateway = props.GatewayAddresses
                .Select(g => g.Address)
                .FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                ?.ToString();

            return new NetworkSnapshot
            {
                InterfaceName = nic.Name,
                IpAddress = ip,
                Netmask = CidrToMask(cidr),
                Cidr = cidr,
                Broadcast = Broadcast(ip, CidrToMask(cidr)),
                Gateway = gateway,
                Hosts = HostsInSubnet(ip, cidr)
            };
        }

        throw new InvalidOperationException("No active IPv4 interface was found. Connect to a network and try again.");
    }

    public static int Cidr(string netmask)
    {
        var parts = netmask.Split('.').Select(p => byte.TryParse(p, out var b) ? b : (byte)0).ToArray();
        if (parts.Length != 4) return 24;
        return parts.Sum(b => System.Numerics.BitOperations.PopCount((uint)b));
    }

    public static string CidrToMask(int cidr)
    {
        var bits = cidr < 0 ? 0 : cidr > 32 ? 32 : cidr;
        var mask = bits == 0 ? 0u : uint.MaxValue << (32 - bits);
        return string.Join(".", new[] { (mask >> 24) & 255, (mask >> 16) & 255, (mask >> 8) & 255, mask & 255 });
    }

    public static string Broadcast(string ip, string mask)
    {
        var a = ToUInt(ip);
        var m = ToUInt(mask);
        return ToDotted(a | ~m);
    }

    public static uint ToUInt(string ip)
    {
        var p = ip.Split('.');
        if (p.Length != 4) return 0;
        return (uint.Parse(p[0]) << 24) | (uint.Parse(p[1]) << 16) | (uint.Parse(p[2]) << 8) | uint.Parse(p[3]);
    }

    public static string ToDotted(uint v) =>
        $"{(v >> 24) & 255}.{(v >> 16) & 255}.{(v >> 8) & 255}.{v & 255}";

    public static List<string> HostsInSubnet(string ip, int cidr)
    {
        var hostBits = 32 - cidr;
        var count = hostBits >= 16 ? 1022 : (1 << hostBits) - 2;
        if (count < 1) count = 1;
        var baseAddr = ToUInt(ip) & (uint.MaxValue << hostBits);
        var list = new List<string>(count);
        for (uint i = 1; i <= (uint)count; i++)
            list.Add(ToDotted(baseAddr + i));
        return list;
    }
}
