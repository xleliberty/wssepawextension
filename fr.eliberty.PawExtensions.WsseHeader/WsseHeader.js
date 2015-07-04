"use strict";

var _prototypeProperties = function (child, staticProps, instanceProps) { if (staticProps) Object.defineProperties(child, staticProps); if (instanceProps) Object.defineProperties(child.prototype, instanceProps); };

var _classCallCheck = function (instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } };

/**
 * Class WsseHeader
 */

var WsseHeader = (function () {

    /**
     * Constructor
     */

    function WsseHeader() {
        _classCallCheck(this, WsseHeader);

        this.hexcase = 0;
        this.b64pad = "=";
        this.chrsz = 8;

        this.uname = "";
        this.pwd = "";
    }

    _prototypeProperties(WsseHeader, null, {
        hexSha1: {
            value: function hexSha1(s) {
                return this.binbToHex(this.coreSha1(this.strTonBinb(s), s.length * this.chrsz));
            },
            writable: true,
            configurable: true
        },
        base64Sha1: {
            value: function base64Sha1(s) {
                return this.binbTo64(this.coreSha1(this.strTonBinb(s), s.length * this.chrsz));
            },
            writable: true,
            configurable: true
        },
        strSha1: {
            value: function strSha1(s) {
                return this.binbToStr(this.coreSha1(this.strTonBinb(s), s.length * this.chrsz));
            },
            writable: true,
            configurable: true
        },
        hexHmacSha1: {
            value: function hexHmacSha1(key, data) {
                return this.binbToHex(this.coreHmacSha1(key, data));
            },
            writable: true,
            configurable: true
        },
        b64HmacSha1: {
            value: function b64HmacSha1(key, data) {
                return this.binbTo64(this.coreHmacSha1(key, data));
            },
            writable: true,
            configurable: true
        },
        strHmacSha1: {
            value: function strHmacSha1(key, data) {
                return this.binbToStr(this.coreHmacSha1(key, data));
            },
            writable: true,
            configurable: true
        },
        sha1_vm_test: {

            /*
             * Perform a simple self-test to see if the VM is working
             */

            value: function sha1_vm_test() {
                return this.hexSha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
            },
            writable: true,
            configurable: true
        },
        coreSha1: {

            /*
             * Calculate the SHA-1 of an array of big-endian words, and a bit length
             */

            value: function coreSha1(x, len) {
                /* append padding */
                x[len >> 5] |= 128 << 24 - len % 32;
                x[(len + 64 >> 9 << 4) + 15] = len;

                var w = Array(80);
                var a = 1732584193;
                var b = -271733879;
                var c = -1732584194;
                var d = 271733878;
                var e = -1009589776;

                for (var i = 0; i < x.length; i += 16) {
                    var olda = a;
                    var oldb = b;
                    var oldc = c;
                    var oldd = d;
                    var olde = e;

                    for (var j = 0; j < 80; j++) {
                        if (j < 16) w[j] = x[i + j];else w[j] = this.rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                        var t = this.safeAdd(this.safeAdd(this.rol(a, 5), this.sha1Ft(j, b, c, d)), this.safeAdd(this.safeAdd(e, w[j]), this.sha1kt(j)));
                        e = d;
                        d = c;
                        c = this.rol(b, 30);
                        b = a;
                        a = t;
                    }

                    a = this.safeAdd(a, olda);
                    b = this.safeAdd(b, oldb);
                    c = this.safeAdd(c, oldc);
                    d = this.safeAdd(d, oldd);
                    e = this.safeAdd(e, olde);
                }
                return Array(a, b, c, d, e);
            },
            writable: true,
            configurable: true
        },
        sha1Ft: {

            /*
             * Perform the appropriate triplet combination for the current
             * iteration
             */

            value: function sha1Ft(t, b, c, d) {
                if (t < 20) {
                    return b & c | ~b & d;
                }if (t < 40) {
                    return b ^ c ^ d;
                }if (t < 60) {
                    return b & c | b & d | c & d;
                }return b ^ c ^ d;
            },
            writable: true,
            configurable: true
        },
        sha1kt: {

            /*
             * Determine the appropriate additive constant for the current iteration
             */

            value: function sha1kt(t) {
                return t < 20 ? 1518500249 : t < 40 ? 1859775393 : t < 60 ? -1894007588 : -899497514;
            },
            writable: true,
            configurable: true
        },
        coreHmacSha1: {

            /*
             * Calculate the HMAC-SHA1 of a key and some data
             */

            value: function coreHmacSha1(key, data) {
                var bkey = this.strTonBinb(key);
                if (bkey.length > 16) bkey = this.coreSha1(bkey, key.length * this.chrsz);

                var ipad = Array(16),
                    opad = Array(16);
                for (var i = 0; i < 16; i++) {
                    ipad[i] = bkey[i] ^ 909522486;
                    opad[i] = bkey[i] ^ 1549556828;
                }

                var hash = this.coreSha1(ipad.concat(this.strTonBinb(data)), 512 + data.length * this.chrsz);
                return this.coreSha1(opad.concat(hash), 512 + 160);
            },
            writable: true,
            configurable: true
        },
        safeAdd: {

            /*
             * Add integers, wrapping at 2^32. This uses 16-bit operations internally
             * to work around bugs in some JS interpreters.
             */

            value: function safeAdd(x, y) {
                var lsw = (x & 65535) + (y & 65535);
                var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
                return msw << 16 | lsw & 65535;
            },
            writable: true,
            configurable: true
        },
        rol: {

            /*
             * Bitwise rotate a 32-bit number to the left.
             */

            value: function rol(num, cnt) {
                return num << cnt | num >>> 32 - cnt;
            },
            writable: true,
            configurable: true
        },
        strTonBinb: {

            /*
             * Convert an 8-bit or 16-bit string to an array of big-endian words
             * In 8-bit  characters >255 have their hi-byte silently ignored.
             */

            value: function strTonBinb(str) {
                var bin = new Array();
                var mask = (1 << this.chrsz) - 1;
                for (var i = 0; i < str.length * this.chrsz; i += this.chrsz) {
                    bin[i >> 5] |= (str.charCodeAt(i / this.chrsz) & mask) << 32 - this.chrsz - i % 32;
                }return bin;
            },
            writable: true,
            configurable: true
        },
        binbToStr: {

            /*
             * Convert an array of big-endian words to a string
             */

            value: function binbToStr(bin) {
                var str = "";
                var mask = (1 << this.chrsz) - 1;
                for (var i = 0; i < bin.length * 32; i += this.chrsz) {
                    str += String.fromCharCode(bin[i >> 5] >>> 32 - this.chrsz - i % 32 & mask);
                }return str;
            },
            writable: true,
            configurable: true
        },
        binbToHex: {

            /*
             * Convert an array of big-endian words to a hex string.
             */

            value: function binbToHex(binarray) {
                var hex_tab = this.hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
                var str = "";
                for (var i = 0; i < binarray.length * 4; i++) {
                    str += hex_tab.charAt(binarray[i >> 2] >> (3 - i % 4) * 8 + 4 & 15) + hex_tab.charAt(binarray[i >> 2] >> (3 - i % 4) * 8 & 15);
                }
                return str;
            },
            writable: true,
            configurable: true
        },
        binbTo64: {

            /*
             * Convert an array of big-endian words to a base-64 string
             */

            value: function binbTo64(binarray) {
                var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                var str = "";
                for (var i = 0; i < binarray.length * 4; i += 3) {
                    var triplet = (binarray[i >> 2] >> 8 * (3 - i % 4) & 255) << 16 | (binarray[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4) & 255) << 8 | binarray[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4) & 255;
                    for (var j = 0; j < 4; j++) {
                        if (i * 8 + j * 6 > binarray.length * 32) str += this.b64pad;else str += tab.charAt(triplet >> 6 * (3 - j) & 63);
                    }
                }
                return str;
            },
            writable: true,
            configurable: true
        },
        encode64: {

            // aardwulf systems
            // This work is licensed under a Creative Commons License.
            // http://www.aardwulf.com/tutor/base64/

            value: function encode64(input) {
                var keyStr = "ABCDEFGHIJKLMNOP" + "QRSTUVWXYZabcdef" + "ghijklmnopqrstuv" + "wxyz0123456789+/" + "=";

                var output = "";
                var chr1 = undefined,
                    chr2 = undefined,
                    chr3 = "";
                var enc1 = undefined,
                    enc2 = undefined,
                    enc3 = undefined,
                    enc4 = "";
                var i = 0;

                do {
                    chr1 = input.charCodeAt(i++);
                    chr2 = input.charCodeAt(i++);
                    chr3 = input.charCodeAt(i++);

                    enc1 = chr1 >> 2;
                    enc2 = (chr1 & 3) << 4 | chr2 >> 4;
                    enc3 = (chr2 & 15) << 2 | chr3 >> 6;
                    enc4 = chr3 & 63;

                    if (isNaN(chr2)) {
                        enc3 = enc4 = 64;
                    } else if (isNaN(chr3)) {
                        enc4 = 64;
                    }

                    output = output + keyStr.charAt(enc1) + keyStr.charAt(enc2) + keyStr.charAt(enc3) + keyStr.charAt(enc4);
                    chr1 = chr2 = chr3 = "";
                    enc1 = enc2 = enc3 = enc4 = "";
                } while (i < input.length);

                return output;
            },
            writable: true,
            configurable: true
        },
        isoDateTime: {

            // TITLE
            // TempersFewGit v 2.1 (ISO 8601 Time/Date script)
            //
            // OBJECTIVE
            // Javascript script to detect the time zone where a browser
            // is and display the date and time in accordance with the
            // ISO 8601 standard.
            //
            // AUTHOR
            // John Walker
            // http://321WebLiftOff.net
            // jfwalker@ureach.com
            //
            // ENCOMIUM
            // Thanks to Stephen Pugh for his help.
            //
            // CREATED
            // 2000-09-15T09:42:53+01:00
            //
            // REFERENCES
            // For more about ISO 8601 see:
            // http://www.w3.org/TR/NOTE-datetime
            // http://www.cl.cam.ac.uk/~mgk25/iso-time.html
            //
            // COPYRIGHT
            // This script is Copyright  2000 JF Walker All Rights
            // Reserved but may be freely used provided this colophon is
            // included in full.
            //

            value: function isoDateTime() {
                var today = new Date();
                var year = today.getYear();
                if (year < 2000) // Y2K Fix, Isaac Powell
                    year = year + 1900; // http://onyx.idbsu.edu/~ipowell
                var month = today.getMonth() + 1;
                var day = today.getDate();
                var hour = today.getHours();
                var hourUTC = today.getUTCHours();
                var diff = hour - hourUTC;
                var hourdifference = Math.abs(diff);
                var minute = today.getMinutes();
                var minuteUTC = today.getUTCMinutes();
                var minutedifference = undefined;
                var second = today.getSeconds();
                var timezone = undefined;
                if (minute != minuteUTC && minuteUTC < 30 && diff < 0) {
                    hourdifference--;
                }
                if (minute != minuteUTC && minuteUTC > 30 && diff > 0) {
                    hourdifference--;
                }
                if (minute != minuteUTC) {
                    minutedifference = ":30";
                } else {
                    minutedifference = ":00";
                }
                if (hourdifference < 10) {
                    timezone = "0" + hourdifference + minutedifference;
                } else {
                    timezone = "" + hourdifference + minutedifference;
                }
                if (diff < 0) {
                    timezone = "-" + timezone;
                } else {
                    timezone = "+" + timezone;
                }
                if (month <= 9) month = "0" + month;
                if (day <= 9) day = "0" + day;
                if (hour <= 9) hour = "0" + hour;
                if (minute <= 9) minute = "0" + minute;
                if (second <= 9) second = "0" + second;

                return year + "-" + month + "-" + day + "T" + hour + ":" + minute + ":" + second + timezone;
            },
            writable: true,
            configurable: true
        },
        wsse: {

            // (C) 2005 Victor R. Ruiz <victor*sixapart.com>
            // Code to generate WSSE authentication header
            //
            // http://www.sixapart.com/pronet/docs/typepad_atom_api
            //
            // X-WSSE: UsernameToken Username="name", PasswordDigest="digest", Created="timestamp", Nonce="nonce"
            //
            //  * Username- The username that the user enters (the TypePad username).
            //  * Nonce. A secure token generated anew for each HTTP request.
            //  * Created. The ISO-8601 timestamp marking when Nonce was created.
            //  * PasswordDigest. A SHA-1 digest of the Nonce, Created timestamp, and the password
            //    that the user supplies, base64-encoded. In other words, this should be calculated
            //    as: base64(sha1(Nonce . Created . Password))
            //

            /**
             *  generate wsse datas
             *
             * @param Passwords
             * @returns {Array}
             */

            value: function wsse(Password) {
                var PasswordDigest = undefined,
                    Nonce = undefined,
                    Created = undefined,
                    nonceEncoded = undefined;
                var r = new Array();

                Nonce = this.base64Sha1(this.isoDateTime() + "There is more than words");
                nonceEncoded = this.encode64(Nonce);
                Created = this.isoDateTime();
                PasswordDigest = this.base64Sha1(Nonce + Created + Password);

                r[0] = nonceEncoded;
                r[1] = Created;
                r[2] = PasswordDigest;

                return r;
            },
            writable: true,
            configurable: true
        },
        wsseHeader: {

            /**
             * generate WsseHeader
             *
             * @param Username
             * @param Password
             * @returns {string}
             */

            value: function wsseHeader(Username, Password) {
                var w = this.wsse(Password);

                return "UsernameToken Username=\"" + Username + "\", PasswordDigest=\"" + w[2] + "\", Created=\"" + w[1] + "\", Nonce=\"" + w[0] + "\"";
            },
            writable: true,
            configurable: true
        },
        evaluate: {
            value: function evaluate() {
                if (this.uname && this.uname.length > 0 && this.pwd && this.pwd.length > 0) {
                    return this.wsseHeader(this.uname, this.pwd);
                }
            },
            writable: true,
            configurable: true
        },
        title: {
            value: function title() {
                return "Wsse Header";
            },
            writable: true,
            configurable: true
        },
        text: {
            value: function text() {
                if (this.input && this.input.length > 0) {
                    return "" + this.input;
                }
                return null;
            },
            writable: true,
            configurable: true
        }
    });

    WsseHeader.identifier = 'fr.eliberty.PawExtensions.WsseHeader';
    WsseHeader.title = 'Wsse Header Generation';
    WsseHeader.inputs = [DynamicValueInput("uname", "UserName", "String"), DynamicValueInput("pwd", "Password", "String")]

    return WsseHeader;
})();


registerDynamicValueClass(WsseHeader);
