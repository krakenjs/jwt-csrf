
import { filterUrls, getExcludedUrls } from '../helpers';

export function interceptHeader(name, { get, set }, options) {

    let excludeUrls = getExcludedUrls(options);

    if (set) {
        let open = window.XMLHttpRequest.prototype.open;

        window.XMLHttpRequest.prototype.open = function () {

            let result = open.apply(this, arguments);

            let value = set();

            if (value) {
                // We only want to set the header for certain requests
                let urlToTest = arguments && arguments.length > 1 && arguments[1];

                let excludeTheseUrls = excludeUrls.length > 0
                    ? excludeUrls.filter((url, i, arr) => filterUrls(url, arr, urlToTest))
                    : [];

                // If the filter above did not find anything set the header
                if (!excludeTheseUrls.length) {

                    this.setRequestHeader(name, value);
                }
            } else {
                return result;
            }

            let setRequestHeader = this.setRequestHeader;

            this.setRequestHeader = function (headerName, headerValue) {

                if (headerName === name) {
                    return;
                }

                return setRequestHeader.apply(this, arguments);
            }

            return result;
        };
    }

    if (get) {

        let send = window.XMLHttpRequest.prototype.send;

        window.XMLHttpRequest.prototype.send = function () {

            let self = this;
            let onreadystatechange = self.onreadystatechange;

            function listener() {
                try {
                    //First check if the response url is in the list of excluded urls
                    //if not then get the refreshed header from response
                    //Ideally, CORS requests should always be excluded else there would
                    // be an OPTIONS request followed by the actual POST and the browser
                    // won't allow getting a custom header
                    let urlToTest = this.responseURL;

                    let excludeTheseUrls = excludeUrls.length > 0
                        ? excludeUrls.filter((url, i, arr) => filterUrls(url, arr, urlToTest))
                        : [];

                    if (!excludeTheseUrls.length) {

                        let newValue = this.getResponseHeader(name);

                        if (newValue) {
                            get(newValue);
                        }
                    }
                } catch (err) {
                    // pass
                }

                if (onreadystatechange) {
                    return onreadystatechange.apply(this, arguments);
                }
            }

            delete self.onreadystatechange;
            self.onreadystatechange = listener;

            Object.defineProperty(self, 'onreadystatechange', {
                get() {
                    return listener;
                },
                set(handler) {
                    onreadystatechange = handler;
                }
            });

            return send.apply(this, arguments);
        };
    }
}
