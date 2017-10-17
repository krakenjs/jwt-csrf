(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define("jwtCsrf", [], factory);
	else if(typeof exports === 'object')
		exports["jwtCsrf"] = factory();
	else
		root["jwtCsrf"] = factory();
})(this, function() {
return /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports, __webpack_require__) {

	'use strict';

	Object.defineProperty(exports, "__esModule", {
	    value: true
	});
	exports.setToken = setToken;
	exports.getToken = getToken;
	exports.setHeaderName = setHeaderName;
	exports.getHeaderName = getHeaderName;
	exports.setOptions = setOptions;
	exports.patchXhr = patchXhr;

	var _lib = __webpack_require__(1);

	var token = void 0;
	var HEADER_NAME = 'x-csrf-jwt';
	var options = {};

	function setToken(newToken) {
	    token = newToken;
	}

	function getToken(newToken) {
	    return token;
	}

	function setHeaderName(name) {
	    HEADER_NAME = name;
	}

	function getHeaderName() {
	    return HEADER_NAME;
	}

	function setOptions(clientOptions) {
	    options = clientOptions;
	}

	function patchXhr() {

	    (0, _lib.interceptHeader)(HEADER_NAME, {
	        get: function get(value) {
	            token = value;
	        },
	        set: function set() {
	            return token;
	        }
	    }, options);
	}

/***/ }),
/* 1 */
/***/ (function(module, exports, __webpack_require__) {

	'use strict';

	Object.defineProperty(exports, "__esModule", {
	    value: true
	});
	exports.interceptHeader = interceptHeader;

	var _helpers = __webpack_require__(2);

	function interceptHeader(name, _ref, options) {
	    var get = _ref.get,
	        set = _ref.set;


	    var excludeUrls = (0, _helpers.getExcludedUrls)(options);

	    if (set) {
	        var open = window.XMLHttpRequest.prototype.open;

	        window.XMLHttpRequest.prototype.open = function () {

	            var result = open.apply(this, arguments);

	            var value = set();

	            if (value) {
	                // We only want to set the header for certain requests
	                var urlToTest = arguments && arguments.length > 1 && arguments[1];

	                var excludeTheseUrls = excludeUrls.length > 0 ? excludeUrls.filter(function (url, i, arr) {
	                    return (0, _helpers.filterUrls)(url, arr, urlToTest);
	                }) : [];

	                // If the filter above did not find anything set the header
	                if (!excludeTheseUrls.length) {

	                    this.setRequestHeader(name, value);
	                }
	            } else {
	                return result;
	            }

	            var setRequestHeader = this.setRequestHeader;

	            this.setRequestHeader = function (headerName, headerValue) {

	                if (headerName === name) {
	                    return;
	                }

	                return setRequestHeader.apply(this, arguments);
	            };

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
	                    //First check if the response url is in the list of excluded urls
	                    //if not then get the refreshed header from response
	                    //Ideally, CORS requests should always be excluded else there would
	                    // be an OPTIONS request followed by the actual POST and the browser
	                    // won't allow getting a custom header
	                    var urlToTest = this.responseURL;

	                    var excludeTheseUrls = excludeUrls.length > 0 ? excludeUrls.filter(function (url, i, arr) {
	                        return (0, _helpers.filterUrls)(url, arr, urlToTest);
	                    }) : [];

	                    if (!excludeTheseUrls.length) {

	                        var newValue = this.getResponseHeader(name);

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
	                get: function get() {
	                    return listener;
	                },
	                set: function set(handler) {
	                    onreadystatechange = handler;
	                }
	            });

	            return send.apply(this, arguments);
	        };
	    }
	}

/***/ }),
/* 2 */
/***/ (function(module, exports) {

	'use strict';

	// Some quick type testing methods
	var toString = Object.prototype.toString;
	var isRegExp = function isRegExp(obj) {
	    return !!/object RegExp/.exec(toString.apply(obj));
	};
	var isString = function isString(obj) {
	    return !!/object String/.exec(toString.apply(obj));
	};
	var isArray = function isArray(obj) {
	    return !!/object Array/.exec(toString.apply(obj));
	};

	var filterUrls = function filterUrls(url, excludeUrls, urlToTest) {

	    if (isArray(url)) {

	        var expression = url[0];
	        var options = url[1] || '';

	        return new RegExp(expression, options).test(urlToTest);
	    } else if (isRegExp(url)) {

	        return url.test(urlToTest);
	    } else if (isString(url)) {

	        // Setup some variables: regExp for regExp testing and
	        // some bits to use in the indexOf comparison
	        var regExp = new RegExp(url);
	        var bits = (urlToTest || '').split(/[?#]/, 1)[0];

	        // Test regular expression strings first                        
	        if (regExp.exec(urlToTest)) {
	            return true;
	        }

	        // If we are still here, test the legacy indexOf case
	        return excludeUrls.indexOf(bits) !== -1;
	    }
	};

	var getExcludedUrls = function getExcludedUrls(options) {
	    var excludeUrls = options.excludeUrls || [];
	    if (options.baseUrl) {
	        excludeUrls = excludeUrls.map(function (route) {
	            return options.baseUrl + route;
	        });
	    }

	    return excludeUrls;
	};

	module.exports = {
	    toString: toString,
	    isRegExp: isRegExp,
	    isString: isString,
	    isArray: isArray,
	    filterUrls: filterUrls,
	    getExcludedUrls: getExcludedUrls
	};

/***/ })
/******/ ])
});
;