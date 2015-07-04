"use 6to5"

/**
 * Class WsseHeader
 *
 * this class is only an es6 rewrite of excellent V. Ruiz wsse lib (https://github.com/vrruiz/wsse-js)
 *
 * @author Victor R. Ruiz <victor*sixapart.com>
 * @author Xavier Lembo <xlembo@eliberty.fr>
 *
 */
class WsseHeader {

    /**
     * Constructor
     */
    constructor() {
        this.hexcase = 0;
        this.b64pad = "=";
        this.chrsz = 8;

        this.uname = '';
        this.pwd = '';
    }

    hexSha1(s) {
        return this.binbToHex(this.coreSha1(this.strTonBinb(s), s.length * this.chrsz));
    }

    base64Sha1(s) {
        return this.binbTo64(this.coreSha1(this.strTonBinb(s), s.length * this.chrsz));
    }

    strSha1(s) {
        return this.binbToStr(this.coreSha1(this.strTonBinb(s), s.length * this.chrsz));
    }

    hexHmacSha1(key, data) {
        return this.binbToHex(this.coreHmacSha1(key, data));
    }

    b64HmacSha1(key, data) {
        return this.binbTo64(this.coreHmacSha1(key, data));
    }

    strHmacSha1(key, data) {
        return this.binbToStr(this.coreHmacSha1(key, data));
    }

    /*
     * Perform a simple self-test to see if the VM is working
     */
    sha1_vm_test() {
        return this.hexSha1("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d";
    }

    /*
     * Calculate the SHA-1 of an array of big-endian words, and a bit length
     */
    coreSha1(x, len) {
        /* append padding */
        x[len >> 5] |= 0x80 << (24 - len % 32);
        x[((len + 64 >> 9) << 4) + 15] = len;

        let w = Array(80);
        let a = 1732584193;
        let b = -271733879;
        let c = -1732584194;
        let d = 271733878;
        let e = -1009589776;

        for (let i = 0; i < x.length; i += 16) {
            let olda = a;
            let oldb = b;
            let oldc = c;
            let oldd = d;
            let olde = e;

            for (let j = 0; j < 80; j++) {
                if (j < 16) w[j] = x[i + j];
                else w[j] = this.rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                let t = this.safeAdd(this.safeAdd(this.rol(a, 5), this.sha1Ft(j, b, c, d)),
                    this.safeAdd(this.safeAdd(e, w[j]), this.sha1kt(j)));
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

    }

    /*
     * Perform the appropriate triplet combination for the current
     * iteration
     */
    sha1Ft(t, b, c, d) {
        if (t < 20) return (b & c) | ((~b) & d);
        if (t < 40) return b ^ c ^ d;
        if (t < 60) return (b & c) | (b & d) | (c & d);
        return b ^ c ^ d;
    }

    /*
     * Determine the appropriate additive constant for the current iteration
     */
    sha1kt(t) {
        return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
            (t < 60) ? -1894007588 : -899497514;
    }

    /*
     * Calculate the HMAC-SHA1 of a key and some data
     */
    coreHmacSha1(key, data) {
        let bkey = this.strTonBinb(key);
        if (bkey.length > 16) bkey = this.coreSha1(bkey, key.length * this.chrsz);

        let ipad = Array(16), opad = Array(16);
        for (let i = 0; i < 16; i++) {
            ipad[i] = bkey[i] ^ 0x36363636;
            opad[i] = bkey[i] ^ 0x5C5C5C5C;
        }

        let hash = this.coreSha1(ipad.concat(this.strTonBinb(data)), 512 + data.length * this.chrsz);
        return this.coreSha1(opad.concat(hash), 512 + 160);
    }

    /*
     * Add integers, wrapping at 2^32. This uses 16-bit operations internally
     * to work around bugs in some JS interpreters.
     */
    safeAdd(x, y) {
        let lsw = (x & 0xFFFF) + (y & 0xFFFF);
        let msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
    }

    /*
     * Bitwise rotate a 32-bit number to the left.
     */
    rol(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
    }

    /*
     * Convert an 8-bit or 16-bit string to an array of big-endian words
     * In 8-bit  characters >255 have their hi-byte silently ignored.
     */
    strTonBinb(str) {
        let bin = new Array();
        let mask = (1 << this.chrsz) - 1;
        for (let i = 0; i < str.length * this.chrsz; i += this.chrsz)
            bin[i >> 5] |= (str.charCodeAt(i / this.chrsz) & mask) << (32 - this.chrsz - i % 32);
        return bin;
    }

    /*
     * Convert an array of big-endian words to a string
     */
    binbToStr(bin) {
        let str = "";
        let mask = (1 << this.chrsz) - 1;
        for (let i = 0; i < bin.length * 32; i += this.chrsz)
            str += String.fromCharCode((bin[i >> 5] >>> (32 - this.chrsz - i % 32)) & mask);
        return str;
    }

    /*
     * Convert an array of big-endian words to a hex string.
     */
    binbToHex(binarray) {
        let hex_tab = this.hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
        let str = "";
        for (let i = 0; i < binarray.length * 4; i++) {
            str += hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF) +
            hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8  )) & 0xF);
        }
        return str;
    }

    /*
     * Convert an array of big-endian words to a base-64 string
     */
    binbTo64(binarray) {
        let tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let str = "";
        for (let i = 0; i < binarray.length * 4; i += 3) {
            let triplet = (((binarray[i >> 2] >> 8 * (3 - i % 4)) & 0xFF) << 16)
                | (((binarray[i + 1 >> 2] >> 8 * (3 - (i + 1) % 4)) & 0xFF) << 8 )
                | ((binarray[i + 2 >> 2] >> 8 * (3 - (i + 2) % 4)) & 0xFF);
            for (let j = 0; j < 4; j++) {
                if (i * 8 + j * 6 > binarray.length * 32) str += this.b64pad;
                else str += tab.charAt((triplet >> 6 * (3 - j)) & 0x3F);
            }
        }
        return str;
    }

    // aardwulf systems
    // This work is licensed under a Creative Commons License.
    // http://www.aardwulf.com/tutor/base64/
    encode64(input) {
        let keyStr = "ABCDEFGHIJKLMNOP" +
            "QRSTUVWXYZabcdef" +
            "ghijklmnopqrstuv" +
            "wxyz0123456789+/" +
            "=";

        let output = "";
        let chr1, chr2, chr3 = "";
        let enc1, enc2, enc3, enc4 = "";
        let i = 0;

        do {
            chr1 = input.charCodeAt(i++);
            chr2 = input.charCodeAt(i++);
            chr3 = input.charCodeAt(i++);

            enc1 = chr1 >> 2;
            enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
            enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
            enc4 = chr3 & 63;

            if (isNaN(chr2)) {
                enc3 = enc4 = 64;
            } else if (isNaN(chr3)) {
                enc4 = 64;
            }

            output = output +
            keyStr.charAt(enc1) +
            keyStr.charAt(enc2) +
            keyStr.charAt(enc3) +
            keyStr.charAt(enc4);
            chr1 = chr2 = chr3 = "";
            enc1 = enc2 = enc3 = enc4 = "";
        } while (i < input.length);

        return output;
    }

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
    isoDateTime() {
        let today = new Date();
        let year = today.getYear();
        if (year < 2000)    // Y2K Fix, Isaac Powell
            year = year + 1900; // http://onyx.idbsu.edu/~ipowell
        let month = today.getMonth() + 1;
        let day = today.getDate();
        let hour = today.getHours();
        let hourUTC = today.getUTCHours();
        let diff = hour - hourUTC;
        let hourdifference = Math.abs(diff);
        let minute = today.getMinutes();
        let minuteUTC = today.getUTCMinutes();
        let minutedifference;
        let second = today.getSeconds();
        let timezone;

        if (diff > 12) {
            diff -= 24;
        }

        if (diff <= -12 ) {
            diff += 24;
        }
        
        if (minute != minuteUTC && minuteUTC < 30 && diff < 0) {
            hourdifference--;
        }
        if (minute != minuteUTC && minuteUTC > 30 && diff > 0) {
            hourdifference--;
        }
        if (minute != minuteUTC) {
            minutedifference = ":30";
        }
        else {
            minutedifference = ":00";
        }
        if (hourdifference < 10) {
            timezone = "0" + hourdifference + minutedifference;
        }
        else {
            timezone = "" + hourdifference + minutedifference;
        }
        if (diff < 0) {
            timezone = "-" + timezone;
        }
        else {
            timezone = "+" + timezone;
        }
        if (month <= 9) month = "0" + month;
        if (day <= 9) day = "0" + day;
        if (hour <= 9) hour = "0" + hour;
        if (minute <= 9) minute = "0" + minute;
        if (second <= 9) second = "0" + second;

        return year + "-" + month + "-" + day + "T"
        + hour + ":" + minute + ":" + second + timezone;
    }

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
    wsse(Password) {
        let PasswordDigest, Nonce, Created, nonceEncoded;
        let r = new Array;

        Nonce = this.base64Sha1(this.isoDateTime() + 'There is more than words');
        nonceEncoded = this.encode64(Nonce);
        Created = this.isoDateTime();
        PasswordDigest = this.base64Sha1(Nonce + Created + Password);

        r[0] = nonceEncoded;
        r[1] = Created;
        r[2] = PasswordDigest;

        return r;
    }

    /**
     * generate WsseHeader
     *
     * @param Username
     * @param Password
     * @returns {string}
     */
    wsseHeader(Username, Password) {
        let w = this.wsse(Password);

        return 'UsernameToken Username="' + Username + '", PasswordDigest="' + w[2] + '", Created="' + w[1] + '", Nonce="' + w[0] + '"';
    }

    evaluate() {
        if (this.uname && this.uname.length > 0 && this.pwd && this.pwd.length > 0) {
            return this.wsseHeader(this.uname, this.pwd);
        }
    }

    text() {
        if (this.input && this.input.length > 0) {
        return "" + this.input;
      }
      return null;
    }
}

/** Paw specific variable declarations **/
WsseHeader.identifier = 'fr.eliberty.PawExtensions.WsseHeader';
WsseHeader.title = 'Wsse Header';
WsseHeader.inputs = [DynamicValueInput("uname", "Username", "String"), DynamicValueInput("pwd", "Password", "String")];

registerDynamicValueClass(WsseHeader);
