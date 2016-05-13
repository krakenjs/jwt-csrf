
export function interceptHeader(name, { get, set }) {

    if (set) {
        var open = window.XMLHttpRequest.prototype.open;

        window.XMLHttpRequest.prototype.open = function () {

            var result = open.apply(this, arguments);

            var value = set();

            if (value) {
                this.setRequestHeader(name, value);
            } else {
                return result;
            }

            var setRequestHeader = this.setRequestHeader;

            this.setRequestHeader = function(headerName, headerValue) {

                if (headerName === name) {
                    return;
                }

                return setRequestHeader.apply(this, arguments);
            }

            return result;
        };
    }

    if (get) {

        var send = window.XMLHttpRequest.prototype.send;

        window.XMLHttpRequest.prototype.send = function () {

            var self = this;
            var onreadystatechange = self.onreadystatechange;

            function listener() {
                try {
                    var newValue = this.getResponseHeader(name);

                    if (newValue) {
                        get(newValue);
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