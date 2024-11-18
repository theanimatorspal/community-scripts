const ScanRuleMetadata = Java.type("org.zaproxy.addon.commonlib.scanrules.ScanRuleMetadata");

function getMetadata() {
    return ScanRuleMetadata.fromYaml(`
id: 67890
name: ksai_WebCacheDeception
description: Detects potential Web Cache Deception vulnerabilities by testing path and file extension variations.
solution: Ensure proper cache controls and avoid caching user-specific content.
references:
  - https://portswigger.net/web-security/web-cache-deception
  - https://owasp.org/www-community/attacks/Web_Cache_Deception
category: SERVER
risk: HIGH
confidence: MEDIUM
cweId: 525
wascId: 13
alertTags:
  cache: web-cache-deception
otherInfo: Detects path mapping issues and cache misconfigurations.
status: beta
`);
}

function generateRandomString(length) {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let randomString = "";
    for (let i = 0; i < length; i++) {
        randomString += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return randomString;
}

function scanNode(as, msg) {
    print("Starting ksai_WebCacheDeception scanNode for URL: " + msg.getRequestHeader().getURI().toString());

    var randomString = generateRandomString(8); // Generate a random string of 8 characters
    print("Generated random string: " + randomString);

    msg = msg.cloneRequest();
    var uri = msg.getRequestHeader().getURI();
    var basePath = uri.getPath();
    print("Extracted base path: " + basePath);

    if (!basePath.endsWith("/")) {
        basePath += "/";
        print("Adjusted base path to end with '/': " + basePath);
    }

    var paths = [
        basePath + randomString,
        basePath + randomString + ".js",
        basePath + randomString + ".css"
    ];
    var responses = {};
    print("Paths to test: " + JSON.stringify(paths));

    msg.getRequestHeader().getURI().setPath(basePath);
    as.sendAndReceive(msg, false, false)
    responses[basePath] = {
        status: msg.getResponseHeader().getStatusCode(),
        size: msg.getResponseBody().length(),
        headers: msg.getResponseHeader().toString()
    }

    for (var i = 0; i < paths.length; i++) {
        var testPath = paths[i];
        msg.getRequestHeader().getURI().setPath(testPath);
        print("Testing path: " + testPath);

        as.sendAndReceive(msg, false, false);
        print("Received response for path: " + testPath);

        responses[testPath] = {
            status: msg.getResponseHeader().getStatusCode(),
            size: msg.getResponseBody().length(),
            headers: msg.getResponseHeader().toString()
        };

        print("Comparing:" + responses[basePath].status + " and " + responses[testPath].status)
        if (i == 0 && responses[basePath] &&
            responses[basePath].status == responses[testPath].status) {
            print("Identified path mapping discrepancy for: " + testPath);
            as.newAlert()
                .setRisk(1)
                .setConfidence(2)
                .setName("ksai_PathMappingDiscrepancy")
                .setDescription("Identical responses for /path/ and /path/" + randomString + ".")
                .setSolution("Review path handling.")
                .setEvidence(JSON.stringify(responses))
                .setMessage(msg)
                .raise();
        }

        if (i > 0 && responses[basePath] &&
            responses[basePath].status == responses[testPath].status) {
            print("Identified path extension discrepancy for: " + testPath);
            as.newAlert()
                .setRisk(1)
                .setConfidence(2)
                .setName("ksai_PathMappingDiscrepancyExtension")
                .setDescription("Identical responses for /path/ and " + testPath)
                .setSolution("Review path extension handling.")
                .setEvidence(JSON.stringify(responses))
                .setMessage(msg)
                .raise();
        }
    }

    if (/X-Cache/i.test(responses[paths[1]].headers) ||
        /Cache-Control/i.test(responses[paths[1]].headers)) {
        print("Cache-related headers detected in the response for: " + paths[1]);

        randomString = generateRandomString(8);
        paths = [
            basePath + randomString,
            basePath + randomString + "." + randomString,
            basePath + randomString + ".css"
        ];


        var cacheResponses = [];
        for (var j = 0; j < 5; j++) {
            msg.getRequestHeader().getURI().setPath(paths[1]);
            as.sendAndReceive(msg, false, false);
            cacheResponses.push(msg.getResponseHeader().toString());
        }

        if (/MISS/i.test(cacheResponses[0])) {
            print("miss detected on the cache response")
            if (cacheResponses.slice(1).some(h => /HIT/i.test(h))) {
                print("Web Cache Deception behavior detected.");
                as.newAlert()
                    .setRisk(3)
                    .setConfidence(3)
                    .setName("ksai_CacheDeception")
                    .setDescription("Cache behavior suggests a Web Cache Deception vulnerability.")
                    .setSolution("Enforce proper cache control headers.")
                    .setEvidence(cacheResponses.join("\n"))
                    .setMessage(msg)
                    .raise();
            }
        }
    }

    print("Finished ksai_WebCacheDeception scanNode.");
}
