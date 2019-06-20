if (containsLayer("TCP")) {
    var tcpIndex = layerIndex("TCP")

    var tcpPayload = packet[tcpIndex].Info.Payload

    var hexdumpedStr = hexdump(tcpPayload)

    if (hexdumpedStr) {
        console.log(hexdumpedStr)
    }
}