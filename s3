var PluginPassiveScanner = Java.type("org.zaproxy.zap.extension.pscan.PluginPassiveScanner");

/**
 * Passively scans an HTTP message. The scan function will be called for 
 * request/response made via ZAP, actual messages depend on the function
 * "appliesToHistoryType", defined below.
 * 
 * @param ps - the PassiveScan parent object that will do all the core interface tasks 
 *     (i.e.: providing access to Threshold settings, raising alerts, etc.). 
 *     This is an ScriptsPassiveScanner object.
 * @param msg - the HTTP Message being scanned. This is an HttpMessage object.
 * @param src - the Jericho Source representation of the message being scanned.
 */
function scan(ps, msg, src) {
    // regex for s3
    var s3BucketURLRegex = /\b(?:https?):\/\/(?:s3(?:[-.](?:[-a-z0-9]+))?\.(?:amazonaws\.com|amazon.com|aws.amazon.com|amazonwebservices\.com|aws\.amazonwebservices\.com|s3-website(?:-[a-z0-9-]+)?\.amazonaws\.com|s3\.amazonaws\.com)|s3\.dualstack\.[a-z0-9-]+\.amazonaws\.com)\/(?:[^\/]+\/?)*\b/g;
    // Extract URLs from request headers, request body, response headers, and response body
    var urls = [];
    urls.push(...extractUrls(msg.getRequestHeader().getHeaders(), s3BucketURLRegex));
    urls.push(...extractUrls([msg.getRequestBody().toString()], s3BucketURLRegex));
    urls.push(...extractUrls(msg.getResponseHeader().getHeaders(), s3BucketURLRegex));
    urls.push(...extractUrls([msg.getResponseBody().toString()], s3BucketURLRegex));

    // Check if S3 buckets are readable
    checkS3BucketReadability(ps, urls);
}

/**
 * Extracts URLs matching the given regex from an array of strings.
 * 
 * @param strings - An array of strings to search for URLs.
 * @param regex - The regular expression to match URLs.
 * @returns An array of matched URLs.
 */
function extractUrls(strings, regex) {
    var matchedUrls = [];
    strings.forEach(function(str) {
        var match;
        while ((match = regex.exec(str)) !== null) {
            matchedUrls.push(match[0]);
        }
    });
    return matchedUrls;
}

/**
 * Checks the readability of S3 buckets and raises alerts if any are found and are readable.
 * 
 * @param ps - The PassiveScan object to raise alerts.
 * @param urls - An array of URLs to check.
 */
function checkS3BucketReadability(ps, urls) {
    function isS3BucketReadable(url) {
        // Perform an HTTP HEAD request to the S3 bucket
        var httpRequest = new org.apache.http.client.methods.HttpHead(url);
        var httpClient = org.apache.http.impl.client.HttpClients.createDefault();
        var httpResponse = null;
    
        try {
            httpResponse = httpClient.execute(httpRequest);
            var statusCode = httpResponse.getStatusLine().getStatusCode();
            if (statusCode >= 200 && statusCode < 300) {
                // S3 bucket is readable
                return true;
            } else {
                // S3 bucket is not readable
                return false;
            }
        } catch (e) {
            // An error occurred, consider the bucket as not readable
            return false;
        } finally {
            // Close the HTTP response
            if (httpResponse !== null) {
                try {
                    httpResponse.close();
                } catch (e) {
                }
            }
        }
    }
    

    urls.forEach(function(url) {
        // Check if S3 bucket is readable
        if (isS3BucketReadable(url)) {
            // Raise alert for readable S3 bucket
            ps.newAlert()
                .setRisk(2)
                .setConfidence(2)
                .setName('Readable s3 bucket URL')
                .setDescription('The extension detected a readable s3 bucket URL in the HTTP message.')
                .setOtherInfo('S3 bucket URL: ' + url)
                .setSolution('Review the S3 bucket permissions to ensure it is not publicly accessible.')
                .setCweId(200)
                .raise();
        } else {
            // Raise alert for found S3 bucket
            ps.newAlert()
                .setRisk(1)
                .setConfidence(2)
                .setName('Found s3 bucket URL')
                .setDescription('The extension detected an s3 bucket URL in the HTTP message.')
                .setOtherInfo('S3 bucket URL: ' + url)
                .setSolution('Review the application code and ensure that S3 bucket URLs are not exposed.')
                .setCweId(200)
                .raise();
        }
    });
}

/**
 * Tells whether or not the scanner applies to the given history type.
 *
 * @param {Number} historyType - The ID of the history type of the message to be scanned.
 * @return {boolean} Whether or not the message with the given type should be scanned by this scanner.
 */
function appliesToHistoryType(historyType) {
    // Default behaviour scans default types.
    return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);
}
