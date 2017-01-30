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
/***/ function(module, exports, __webpack_require__) {

	'use strict';

	Object.defineProperty(exports, "__esModule", {
	    value: true
	});
	exports.setToken = setToken;
	exports.getToken = getToken;
	exports.setHeaderName = setHeaderName;
	exports.getHeaderName = getHeaderName;
	exports.patchXhr = patchXhr;

	var _lib = __webpack_require__(1);

	var token = void 0;
	var HEADER_NAME = 'x-csrf-jwt';

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

	function patchXhr() {

	    (0, _lib.interceptHeader)(HEADER_NAME, {
	        get: function get(value) {
	            token = value;
	        },
	        set: function set() {
	            return token;
	        }
	    });
	}

/***/ },
/* 1 */
/***/ function(module, exports) {

	'use strict';

	Object.defineProperty(exports, "__esModule", {
	    value: true
	});
	exports.interceptHeader = interceptHeader;
	function interceptHeader(name, _ref) {
	    var get = _ref.get,
	        set = _ref.set;


	    if (set) {
	        (function () {
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

	                this.setRequestHeader = function (headerName, headerValue) {

	                    if (headerName === name) {
	                        return;
	                    }

	                    return setRequestHeader.apply(this, arguments);
	                };

	                return result;
	            };
	        })();
	    }

	    if (get) {
	        (function () {

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
	                    get: function get() {
	                        return listener;
	                    },
	                    set: function set(handler) {
	                        onreadystatechange = handler;
	                    }
	                });

	                return send.apply(this, arguments);
	            };
	        })();
	    }
	}

/***/ }
/******/ ])
});
;