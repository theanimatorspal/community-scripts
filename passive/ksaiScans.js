var Pattern = Java.type("java.util.regex.Pattern");

function scan(helper, msg, src) {
     var response = msg.getResponseBody().toString();

     // Debuggirg helper to log patterns being checked and matches found
     function debugLog(message) {
          print("[DEBUG] " + message);
     }

     var regexChecks = [
          { name: "ksaiJSAPIEndpoint", pattern: /https?:\/\/[\w.-]+\/api\/[\w./?=&-]*/gi, description: "Potential API endpoint detected." },
          { name: "ksaiPotentialKey", pattern: /[\w-]{32,}/g, description: "Potential API key or token detected." },
          { name: "ksaiSensitiveData", pattern: /(password|secret|access[_\-]key|private[_\-]key|authorization|bearer\s[\w-]+)/gi, description: "Sensitive data detected in the JavaScript file." },
          { name: "ksaiJWTWeakness", pattern: /\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.?[a-zA-Z0-9_-]*\b/gi, description: "JWT token detected; check for weak algorithms or improper implementation." },
          { name: "ksaiInsecureHTTP", pattern: /http:\/\/[\w.-]+/gi, description: "Insecure HTTP endpoint detected." },
          { name: "ksaiEmailAddresses", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/gi, description: "Email address found in JavaScript file." },
          { name: "ksaiAWSKey", pattern: /AKIA[0-9A-Z]{16}/g, description: "Potential AWS key detected." },
          { name: "ksaiDangerousFunction", pattern: /\b(eval|document\.write|setTimeout|setInterval|innerHTML)\b/gi, description: "Dangerous JavaScript function detected." },
          { name: "ksaiHardcodedCredentials", pattern: /\b(username|password)[\s=:]+["']?\w+["']?/gi, description: "Hardcoded credentials detected." },
          { name: "ksaiErrorPatterns", pattern: /(exception|stack trace|traceback|error|referenceerror|uncaughtexception)/gi, description: "Error patterns found in the JavaScript file." },
          { name: "ksaiPrivateIP", pattern: /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/g, description: "Private IP address found; check for potential internal exposure." },
          { name: "ksaiHardcodedToken", pattern: /\b[A-Za-z0-9_-]{30,}\b/g, description: "Potential hardcoded token detected; check for sensitive data exposure." },
          { name: "ksaiWeakCrypto", pattern: /\b(md5|sha1|rot13)\b/g, description: "Usage of weak cryptographic algorithms found; consider stronger alternatives like SHA-256 or AES." },
          { name: "ksaiPrivateBucket", pattern: /https?:\/\/s3\.(.*)\.amazonaws\.com\/[^\s]+/g, description: "S3 bucket URL found; ensure it is properly secured." },
          { name: "ksaiQueryInjection", pattern: /\bSELECT .* FROM\b|\bUPDATE .* SET\b|\bDELETE FROM\b/g, description: "SQL keywords detected; verify the backend's, input sanitization and prepared statements." },
          { name: "ksaiOpenRedirect", pattern: /\b(location\.href|window\.location) *= *["']?https?:\/\/[^\s'"]+/g, description: "Potential open redirect vulnerability found; ensure validation of redirect URLs." },
          { name: "ksaiCrossDomainAccess", pattern: /\bwindow\.postMessage\(/g, description: "Cross-origin communication detected; ensure messages are sent to trusted domains only." },
          { name: "ksaiSensitiveEnv", pattern: /\b(process\.env|env\.)/g, description: "Environment variable access detected; verify it does not expose sensitive data." },
          { name: "ksaiCommandInjection", pattern: /\b(require|child_process)\.exec\(.+\)/g, description: "Command execution function detected; check for potential command injection risks." },
          { name: "ksaiExcessiveError", pattern: /\bconsole\.(error|log|warn)\(.+\)/g, description: "Excessive debugging information found; verify no sensitive information is logged." },
          { name: "ksaiSuperGlobalUsage", pattern: /\b(window|global|document)\.\w+/g, description: "Direct manipulation of global objects found; ensure no critical objects are being overridden." },
          { name: "ksaiUnsafeRegex", pattern: /(.*)\((.*)\)\1\2/g, description: "Potential unsafe regular expression found; check for ReDoS (Regular Expression Denial of Service)." }
     ];

     regexChecks.forEach(function (check) {
          debugLog("Checking pattern: " + check.name);
          var matches = response.match(check.pattern);
          if (matches) {
               debugLog("Matches found for " + check.name + ": " + matches.join(", "));
               helper.newAlert()
                    .setRisk(3)
                    .setConfidence(2)
                    .setName(check.name)
                    .setDescription(check.description)
                    .setEvidence(matches.join("\n"))
                    .setMessage(msg)
                    .raise();
          } else {
               debugLog("No matches found for " + check.name);
          }
     });

     var suspiciousPatterns = ["<script src=", "<iframe", "onerror=", "onclick="];
     suspiciousPatterns.forEach(function (pattern) {
          debugLog("Checking suspicious pattern: " + pattern);
          if (response.indexOf(pattern) != -1) {
               debugLog("Suspicious pattern found: " + pattern);
               helper.newAlert()
                    .setRisk(2)
                    .setConfidence(2)
                    .setName("ksaiSuspiciousPattern")
                    .setDescription("Suspicious pattern detected: " + pattern)
                    .setEvidence(pattern)
                    .setMessage(msg)
                    .raise();
          } else {
               debugLog("Suspicious pattern not found: " + pattern);
          }
     });
}

function appliesToHistoryType(historyType) {
     return org.zaproxy.zap.extension.pscan.PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
}
