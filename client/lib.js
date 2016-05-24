
export function interceptHeader(name, { get, set }) {

    if (set) {
        let open = window.XMLHttpRequest.prototype.open;

        window.XMLHttpRequest.prototype.open = function () {

            let result = open.apply(this, arguments);

            let value = set();

            if (value) {
                this.setRequestHeader(name, value);
            } else {
                return result;
            }

            let setRequestHeader = this.setRequestHeader;

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

        let send = window.XMLHttpRequest.prototype.send;

        window.XMLHttpRequest.prototype.send = function () {

            let self = this;
            let onreadystatechange = self.onreadystatechange;

            function listener() {
                try {
                    let newValue = this.getResponseHeader(name);

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
