// Some quick type testing methods
var toString = Object.prototype.toString;
var isRegExp = function (obj) { return !!/object RegExp/.exec(toString.apply(obj)); }
var isString = function (obj) { return !!/object String/.exec(toString.apply(obj)); }
var isArray = function (obj) { return !!/object Array/.exec(toString.apply(obj)); }

var filterUrls = function (url, excludeUrls, urlToTest) {

    if (isArray(url)) {

        var expression = url[0];
        var options = url[1] || '';

        return new RegExp(expression, options).test(urlToTest);
    }
    else if (isRegExp(url)) {

        return url.test(urlToTest);
    }
    else if (isString(url)) {

        // Setup some variables: regExp for regExp testing and
        // some bits to use in the indexOf comparison
        var regExp = new RegExp(url);
        var bits = ((urlToTest || '').split(/[?#]/, 1))[0];

        // Test regular expression strings first                        
        if (regExp.exec(urlToTest)) {
            return true;
        }

        // If we are still here, test the legacy indexOf case
        return excludeUrls.indexOf(bits) !== -1;
    }
}

var getExcludedUrls = function(options){
    var excludeUrls = options.excludeUrls || [];
    if (options.baseUrl) {
        excludeUrls = excludeUrls.map(function (route) {
            return options.baseUrl + route;
        });
    }

    return excludeUrls;
}

module.exports = {
    toString: toString,
    isRegExp: isRegExp,
    isString: isString,
    isArray: isArray,
    filterUrls: filterUrls,
    getExcludedUrls: getExcludedUrls
};