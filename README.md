# nids

> [Network Intrusion Detection System](https://en.wikipedia.org/wiki/Intrusion_detection_system)

Engine written in Go supporting rules written in JavaScript.

## Install

```console
$ go get -u github.com/picatz/nids
```

## Rule Example

Check if the destination IP matches a given blacklist.

```javascript
// setup rules file
var blacklist = ["1.1.1.1", "8.8.8.8"]

// add helper function to check the list
function checkBlacklist(ip) {
    for (i in blacklist) {
        if (ip == blacklist[i]) {
            console.log("found " + ip + " from blacklist")
        }
    }
}
```

```javascript
// rules file
if (containsLayer("IPv4")) {
    var ipv4 = packet[layerIndex("IPv4")].Info

    checkBlacklist(ip4.DstIP)
}
```

Now we can start the engine from the command-line:

```console
$ nids -interface en0 -immediate -rules-setup rule_examples/create_blacklist.js -rules rule_examples/blacklist.js
found 8.8.8.8 from blacklist
found 1.1.1.1 from blacklist
...
```
