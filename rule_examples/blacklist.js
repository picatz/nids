if (containsLayer("IPv4")) {
    var ipv4 = packet[layerIndex("IPv4")].Info

    checkBlacklist(ipv4.DstIP)
}