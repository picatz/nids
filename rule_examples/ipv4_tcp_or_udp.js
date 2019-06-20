if (containsLayer("TCP")) {
    var ip4Index  = layerIndex("IPv4")
    var tcpIndex = layerIndex("TCP")

    var ip4 = packet[ip4Index].Info
    var tcp =  packet[tcpIndex].Info

    console.log("tcp: " + ip4.SrcIP + ":" + tcp.SrcPort + "->" + ip4.DstIP + ":" + tcp.DstPort)
} else if (containsLayer("UDP")) {
    var ip4Index  = layerIndex("IPv4")
    var udpIndex = layerIndex("UDP")

    var ip4 = packet[ip4Index].Info
    var udp =  packet[udpIndex].Info

    console.log("tcp: " + ip4.SrcIP + ":" + udp.SrcPort + "->" + ip4.DstIP + ":" + udp.DstPort)
} else {
    // console.log("unkown packet: " + JSON.stringify(packet))
}