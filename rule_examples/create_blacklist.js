var blacklist = ["1.1.1.1", "8.8.8.8"]

function checkBlacklist(ip) {
    for (i in blacklist) {
        if (ip == blacklist[i]) {
            console.log("found " + ip + " from blacklist")
        }
    }
}