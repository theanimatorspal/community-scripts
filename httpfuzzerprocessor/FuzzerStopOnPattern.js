var regexPattern = /incorrect password/i; // modify this as you want
var pattern_should_match = false // false if you want to actually NOT match the pattern
function processMessage(utils, message) {
     // No processing required for the request.
}

function processResult(utils, fuzzResult) {
     var responseBody = fuzzResult.getHttpMessage().getResponseBody().toString();
     var matched = false;
     if (regexPattern.test(responseBody)) {
          matched = true;
     }
     if (pattern_should_match == matched) {
          utils.stopFuzzer();
          fuzzResult.addCustomState("Match", "Pattern Matched");
     }
     return true;
}
