Java.perform(function () {
    const showHeaders = true;

    const Request = Java.use("okhttp3.Request"); // okhttp3.Request
    const Response = Java.use("okhttp3.Response"); // okhttp3.Response

    const BridgeInterceptor = Java.use("okhttp3.internal.http.BridgeInterceptor"); // this is where we can intercept the requests!
    const Buffer = Java.use("okio.Buffer");

    
    function formatHeaders(headers) {
        return headers.toString();
    }

    function interceptRequest(request) {
        let requestMethod = request.method();
        let requestUrl = request.url().toString();
        console.log(`[>] request intercepted: method=${requestMethod} url=${requestUrl}`);
        console.log(request.toString());
    }

    function interceptResponse(response) {
        console.log("[<] response intercepted: " + JSON.stringify(response.toString()));

        if (showHeaders) {
            console.log(" < headers:\n" + formatHeaders(response.headers));
        }

        let responseBody = response.peekBody(1024 * 128); // okhttp3.Response::peekBody(byteCount: Long)
        if (responseBody != null) {
            let responseBodyString = responseBody.string();
            if (responseBodyString != "") {
                console.log(" < body: " + responseBodyString);
            }
        }
        console.log("\n");
    }

    BridgeInterceptor.intercept.implementation = function(chain) {
        let request = chain.request();
        interceptRequest(request);

        let response = this.intercept(chain);

        interceptResponse(response);
        return response;
    }
});
