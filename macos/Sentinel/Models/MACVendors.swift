import Foundation

/// Short IEEE OUI table (public assignments) used like nmap-mac-prefixes.
enum MACVendors {
    static func vendor(for mac: String) -> String? {
        let hex = mac
            .uppercased()
            .replacingOccurrences(of: "-", with: "")
            .replacingOccurrences(of: ":", with: "")
            .replacingOccurrences(of: ".", with: "")
        guard hex.count >= 6 else { return nil }
        return table[String(hex.prefix(6))]
    }

    static func normalize(_ mac: String) -> String {
        let hex = mac.uppercased().filter(\.isHexDigit)
        guard hex.count >= 12 else { return mac.uppercased() }
        let chars = Array(hex.prefix(12))
        return stride(from: 0, to: 12, by: 2).map { String(chars[$0...$0 + 1]) }.joined(separator: ":")
    }

    private static let table: [String: String] = {
        var map: [String: String] = [:]
        func add(_ prefix: String, _ name: String) {
            map[prefix] = name
        }

        let apple = [
            "F0D4E2", "F0B479", "F02929", "ACDE48", "A4C361", "A4B197", "A4D18C", "A4B805",
            "A860B6", "A85C2C", "A88808", "A8BE27", "B065BD", "B0702D", "B09FBA", "B8C111",
            "B8E856", "B8FF61", "BC3BAF", "BC52B7", "BC6778", "BC92A0", "C02C5C", "C0A53E",
            "C4B301", "C82A14", "C869CD", "C8B5B7", "CC08E0", "CC25EF", "D023DB", "D02598",
            "D0E140", "D4619D", "D8A25E", "D8BB2C", "DC2B61", "DC37D2", "E0ACCB", "E0B52D",
            "E0C767", "E0F5C6", "E4CE8F", "E80F67", "E88D28", "EC3586", "F0C1F1", "F0DBE2",
            "F40F24", "F41BA1", "F45C89", "F4F15A", "F8E94E", "FC253F", "001451", "0017F2",
            "0019E3", "001B63", "001CB3", "001EC2", "001FF3", "002241", "002312", "002332",
            "002436", "002500", "0025BC", "002608", "00264A", "003065", "0050E4", "00A040",
            "040CCE", "0452F3", "049F81", "04D3CF", "04E536", "04F13E", "04F7E4", "0C3021",
            "0C3E9F", "0C4DE9", "0C74C2", "109ADD", "10DDB1", "14109F", "148FC6", "18AF61",
            "18E7F4", "1C1AC0", "1C36BB", "1C5CF2", "1CAB01", "20768F", "207D74", "24A074",
            "24AB81", "24E314", "280B5C", "28E02C", "2C1F23", "2CB43A", "34159E", "348446",
            "34A395", "34C059", "380F4A", "3C0754", "3CD0F8", "40A6D9", "40B395", "40D32D",
            "443583", "48A195", "48BF6B", "4C3275", "4C8D79", "503237", "50ED3C", "542696",
            "58686C", "5C5948", "5CF938", "609AC1", "60F81D", "64A3CB", "64B0A6", "64B9E8",
            "68A86D", "68D93C", "6C19C0", "6C3E6D", "6C4008", "6C709F", "6C72E7", "6C8DC1",
            "6CA100", "7014A6", "7073CB", "70DEE2", "70E72C", "70F087", "78A3E4", "78CA39",
            "7C0191", "7C5049", "7CC3A1", "7CD1C3", "7CF05F", "80E650", "84A134", "84B153",
            "84FCAC", "88C663", "88E87F", "8C006D", "8C2937", "8C7B9D", "8C8590", "8CFABA",
            "907240", "90840D", "90B21F", "90C1C6", "9801A7", "985AEB", "989E63", "9C207B",
            "9C293F", "9C4FDA", "9C84BF", "9CF387", "9CF48E", "A01828"
        ]
        apple.forEach { add($0, "Apple") }

        [
            "001B2F", "001C58", "001E13", "001E14", "001E79", "002155", "0021A0", "0021D8",
            "0022BD", "0023EA", "0024C4", "0024F9", "0026CA", "0026CB", "00D006", "00D058",
            "00D0BA", "00D0D3", "00E014", "00E01E", "04C5A4", "08CC68", "0CF5A4", "188B45",
            "1C17D3", "1C6A7A", "203A07", "2C3ECF", "2C36F8", "3C08F6", "3CCE73", "5006AB",
            "5475D0", "54781A", "58AC78", "641225", "68BDAB", "6C416A", "70105C", "704CA5",
            "705A0F", "70CA9B", "84B261", "8843E1", "A09347", "A0E0AF", "B41489", "B4A4E3",
            "B8BEBF", "C0626B", "C47295", "C8D719", "D0C282", "D46D50", "D48CB5", "D8B190",
            "E00EDA", "E8BA70", "F07F06", "F40F1B", "F4CFE2", "F80BCB", "F87B20"
        ].forEach { add($0, "Cisco") }

        [
            "00156D", "002722", "0418D6", "24A43C", "44D9E7", "68D79A", "74ACB9", "788A20",
            "802AA8", "B4FBE4", "DC9FDB", "E063DA", "F09FC2", "FCECDA"
        ].forEach { add($0, "Ubiquiti") }

        [
            "000FB5", "00146C", "001E2A", "001F33", "00223F", "0024B2", "0026F2", "008EF2",
            "100D7F", "20E52A", "28C68E", "2C3033", "30469A", "4494FC", "4C60DE", "6CB0CE",
            "803773", "841B5E", "9C3DCF", "A00460", "A021B7", "A040A0", "B07FB9", "C03F0E",
            "C40415", "C43DC7", "CC40D0", "E0469A", "E091F5", "E4F4C6", "78D294"
        ].forEach { add($0, "Netgear") }

        [
            "14CC20", "1C3BF3", "30B5C2", "50C7BF", "54C80F", "60E327", "647002", "6C5AB0",
            "98DAC4", "A0F3C1", "B0487A", "C006C3", "C4E984", "D80D17", "E4D332", "EC086B",
            "F4EC38", "54AF97", "F8D111"
        ].forEach { add($0, "TP-Link") }

        [
            "001A11", "3C5AB4", "546009", "54EAA8", "94EB2C", "A47733", "F4F5D8", "F4F5E8",
            "F88FCA", "18B430", "7C2EBD"
        ].forEach { add($0, "Google") }

        [
            "002243", "0C47C9", "34D270", "40B4CD", "44D884", "50DCB7", "68F44B", "74C246",
            "84D6D0", "8871E5", "A002DC", "AC63BE", "B47C9C", "F0272D", "FC65DE"
        ].forEach { add($0, "Amazon") }

        [
            "001320", "0013CE", "0013E8", "001517", "0016EA", "0016EB", "0018DE", "0019D1",
            "0019D2", "001B21", "001B77", "001CBF", "001CC0", "001DE0", "001E64", "001E67",
            "001F3B", "001F3C", "00215C", "00215D", "00216A", "00216B", "0022FA", "0022FB",
            "002314", "002315", "0024D6", "0024D7", "0026C6", "0026C7", "00270E", "002710",
            "3CA9F4", "448500", "4CAC0A", "5C514F", "68ECC5", "7C7A91", "8C8D28", "A08869",
            "B80305", "DC5360"
        ].forEach { add($0, "Intel") }

        [
            "000D88", "0015E9", "00179A", "00195B", "001B11", "001CF0", "001E58", "002191",
            "0022B0", "002401", "00265A", "14D64D", "1C7EE5", "1CAFF7", "28D127", "34C3D2",
            "78A6E1", "84C9B2", "908D78", "B8A386", "C0A0BB", "C4A81D", "C8BE19", "CCB255",
            "F07D68", "F48CEB", "FC7516", "6C198F"
        ].forEach { add($0, "D-Link") }

        [
            "001A92", "001E8C", "002215", "002354", "00248C", "04D4C4", "107B44", "10BF48",
            "14DDA9", "1C872C", "20CF30", "2C4D54", "2C56DC", "305A3A", "382C4A", "40B076",
            "50465D", "54A050", "60A44C", "704D7B", "74D02B", "AC220B", "BCAEC5", "D017C2",
            "E03F49", "E0CB4E", "F07959", "F46D04", "0013D4"
        ].forEach { add($0, "ASUSTek") }

        [
            "000C41", "000E08", "000F66", "001217", "001310", "0014BF", "0016B6", "001839",
            "0018F8", "001A70", "001C10", "001D7E", "001EE5", "002129", "00226B", "002369",
            "00259C"
        ].forEach { add($0, "Linksys") }

        [
            "2037A5", "20A680", "247F3C", "285FDB", "2C55D3", "346AC2", "3CDFBD", "3C37D3",
            "48AD08", "4C1FCC", "548998", "5CF96A", "64A651", "70A8E3", "7C6097", "80717A",
            "88CF98", "88A2D7", "8CE117", "A0F479", "AC853D", "B41513", "C40528", "D4612E",
            "E0247F", "F4C714"
        ].forEach { add($0, "Huawei") }

        [
            "001632", "00166B", "00166C", "0018AF", "001D25", "001EE1", "002339", "002454",
            "002490", "002566", "04180F", "08373D", "08D42B", "0C715D", "10D38A", "14F42A",
            "18E2C2", "1C5A3E", "1C62B8", "24C696", "2C4401", "34BE00", "38AA3C", "3C5A37",
            "40B837", "44D6E1", "50B7C3", "5C0A5B", "5C3C27", "78F882", "8C7712", "A00798",
            "B047BF", "C417FE", "CC07AB", "E09971", "EC1F72", "F025B7", "F47B5E", "FC1910"
        ].forEach { add($0, "Samsung") }

        [
            "0024E8", "002564", "0026B9", "141877", "149ECF", "180373", "18A99B", "1C4024",
            "246E96", "3417EB", "44A842", "4C7625", "549F35", "5C260A", "7427EA", "7845C4",
            "8C0474", "A41F72", "B083FE", "B8AC6F", "D067E5", "D481D7", "F8B156"
        ].forEach { add($0, "Dell") }

        [
            "001871", "0019BB", "001A4B", "001CC4", "001E0B", "002264", "00237D", "002481",
            "0025B3", "002655", "10604B", "1458D0", "18A905", "2C27D7", "3C4A92", "3CD92B",
            "645106", "6C3BE5", "784859", "80C16E", "84A93E", "9C8E99", "A0B3CC", "B4B52F",
            "C4346B", "D48564", "E83935", "EC8EB5", "F0921C", "F4CE46"
        ].forEach { add($0, "Hewlett Packard") }

        [
            "B827EB", "DCA632", "E45F01", "2CCF67", "D83ADD"
        ].forEach { add($0, "Raspberry Pi") }

        [
            "10FEED", "24A160", "240AC4", "246F28", "30AEA4", "3C6105", "483FDA", "4C11AE",
            "545AA6", "5CCF7F", "600194", "68C63A", "807D3A", "84F3EB", "8CAAB5", "A020A6",
            "A4CF12", "A0CEB8", "ACD074", "B0A737", "BCFF4D", "CC50E3", "D8A01D", "DC4F22",
            "ECFAA0"
        ].forEach { add($0, "Espressif") }

        [
            "000C29", "005056", "000569", "001C14"
        ].forEach { add($0, "VMware") }

        add("080027", "PCS / VirtualBox")
        add("0A0027", "VirtualBox")
        add("00155D", "Microsoft Hyper-V")
        add("00163E", "Xen")
        add("525400", "QEMU/KVM")
        add("0003FF", "Microsoft")
        add("001DD8", "Microsoft")
        add("0025AE", "Microsoft")
        add("0050F2", "Microsoft")
        add("7C1E52", "Microsoft")
        add("001018", "Broadcom")
        add("00E04C", "Realtek")
        add("64B5C6", "Nintendo")
        add("0025A0", "Nintendo")
        add("0009BF", "Nintendo")
        add("002709", "Nintendo")
        add("0017AB", "Nintendo")
        add("0021BD", "Nintendo")
        add("0013A9", "Sony")
        add("0015C1", "Sony")
        add("0016B8", "Sony")
        add("0019C5", "Sony")
        add("001A80", "Sony")
        add("001D28", "Sony")
        add("001EDC", "Sony")
        add("00219E", "Sony")
        add("0024BE", "Sony")
        add("045D4B", "Sony")
        add("0CFE45", "Sony")
        add("001D43", "Sonos")
        add("48A6B8", "Sonos")
        add("542A1B", "Sonos")
        add("5CAAFD", "Sonos")
        add("7828CA", "Sonos")
        add("949F3E", "Sonos")
        add("B8E937", "Sonos")
        add("C43875", "Sonos")
        add("000C42", "MikroTik")
        add("4C5E0C", "MikroTik")
        add("64D154", "MikroTik")
        add("6C3B6B", "MikroTik")
        add("CC2DE0", "MikroTik")
        add("D4CA6D", "MikroTik")
        add("E48D8C", "MikroTik")
        add("002590", "Super Micro")
        add("003048", "Super Micro")
        add("0CC47A", "Super Micro")
        add("3CECEF", "Super Micro")
        add("AC1F6B", "Super Micro")
        add("000E50", "Philips")
        add("001788", "Philips")
        add("1C1448", "ARRIS")
        add("20E564", "ARRIS")
        add("181E78", "Sagemcom")
        add("F0B429", "Xiaomi")
        add("94B819", "Nokia")
        add("A47B2C", "Nokia")
        add("00C0CA", "SonicWall")
        add("0004C6", "Yamaha")
        add("70B3D5", "IEEE registration")
        add("9CEFD5", "Panda Wireless")
        add("0022F4", "AMPAK")
        return map
    }()
}
