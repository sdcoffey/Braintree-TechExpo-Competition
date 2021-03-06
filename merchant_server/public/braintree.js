/*!
 * Braintree End-to-End Encryption Library
 * https://www.braintreepayments.com
 * Copyright (c) 2009-2014 Braintree, a division of PayPal, Inc.
 *
 * JSBN
 * Copyright (c) 2005  Tom Wu
 *
 * Both Licensed under the MIT License.
 * http://opensource.org/licenses/MIT
 *
 * ASN.1 JavaScript decoder
 * Copyright (c) 2008-2009 Lapo Luchini <lapo@lapo.it>
 * Licensed under the ISC License.
 * http://opensource.org/licenses/ISC
 */

(function () {

// ASN.1 JavaScript decoder
// Copyright (c) 2008-2009 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

function Stream(enc, pos) {
    if (enc instanceof Stream) {
        this.enc = enc.enc;
        this.pos = enc.pos;
    } else {
        this.enc = enc;
        this.pos = pos;
    }
}
Stream.prototype.get = function(pos) {
    if (pos == undefined)
        pos = this.pos++;
    if (pos >= this.enc.length)
        throw 'Requesting byte offset ' + pos + ' on a stream of length ' + this.enc.length;
    return this.enc[pos];
}
Stream.prototype.hexDigits = "0123456789ABCDEF";
Stream.prototype.hexByte = function(b) {
    return this.hexDigits.charAt((b >> 4) & 0xF) + this.hexDigits.charAt(b & 0xF);
}
Stream.prototype.hexDump = function(start, end) {
    var s = "";
    for (var i = start; i < end; ++i) {
        s += this.hexByte(this.get(i));
        switch (i & 0xF) {
        case 0x7: s += "  "; break;
        case 0xF: s += "\n"; break;
        default:  s += " ";
        }
    }
    return s;
}
Stream.prototype.parseStringISO = function(start, end) {
    var s = "";
    for (var i = start; i < end; ++i)
        s += String.fromCharCode(this.get(i));
    return s;
}
Stream.prototype.parseStringUTF = function(start, end) {
    var s = "", c = 0;
    for (var i = start; i < end; ) {
        var c = this.get(i++);
        if (c < 128)
            s += String.fromCharCode(c);
        else if ((c > 191) && (c < 224))
            s += String.fromCharCode(((c & 0x1F) << 6) | (this.get(i++) & 0x3F));
        else
            s += String.fromCharCode(((c & 0x0F) << 12) | ((this.get(i++) & 0x3F) << 6) | (this.get(i++) & 0x3F));
        //TODO: this doesn't check properly 'end', some char could begin before and end after
    }
    return s;
}
Stream.prototype.reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
Stream.prototype.parseTime = function(start, end) {
    var s = this.parseStringISO(start, end);
    var m = this.reTime.exec(s);
    if (!m)
        return "Unrecognized time: " + s;
    s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
    if (m[5]) {
        s += ":" + m[5];
        if (m[6]) {
            s += ":" + m[6];
            if (m[7])
                s += "." + m[7];
        }
    }
    if (m[8]) {
        s += " UTC";
        if (m[8] != 'Z') {
            s += m[8];
            if (m[9])
                s += ":" + m[9];
        }
    }
    return s;
}
Stream.prototype.parseInteger = function(start, end) {
    //TODO support negative numbers
    var len = end - start;
    if (len > 4) {
        len <<= 3;
        var s = this.get(start);
        if (s == 0)
            len -= 8;
        else
            while (s < 128) {
                s <<= 1;
                --len;
            }
        return "(" + len + " bit)";
    }
    var n = 0;
    for (var i = start; i < end; ++i)
        n = (n << 8) | this.get(i);
    return n;
}
Stream.prototype.parseBitString = function(start, end) {
    var unusedBit = this.get(start);
    var lenBit = ((end - start - 1) << 3) - unusedBit;
    var s  = "(" + lenBit + " bit)";
    if (lenBit <= 20) {
        var skip = unusedBit;
        s += " ";
        for (var i = end - 1; i > start; --i) {
            var b = this.get(i);
            for (var j = skip; j < 8; ++j)
                s += (b >> j) & 1 ? "1" : "0";
            skip = 0;
        }
    }
    return s;
}
Stream.prototype.parseOctetString = function(start, end) {
    var len = end - start;
    var s = "(" + len + " byte) ";
    if (len > 20)
        end = start + 20;
    for (var i = start; i < end; ++i)
        s += this.hexByte(this.get(i));
    if (len > 20)
        s += String.fromCharCode(8230); // ellipsis
    return s;
}
Stream.prototype.parseOID = function(start, end) {
    var s, n = 0, bits = 0;
    for (var i = start; i < end; ++i) {
        var v = this.get(i);
        n = (n << 7) | (v & 0x7F);
        bits += 7;
        if (!(v & 0x80)) { // finished
            if (s == undefined)
                s = parseInt(n / 40) + "." + (n % 40);
            else
                s += "." + ((bits >= 31) ? "bigint" : n);
            n = bits = 0;
        }
        s += String.fromCharCode();
    }
    return s;
}

function ASN1(stream, header, length, tag, sub) {
    this.stream = stream;
    this.header = header;
    this.length = length;
    this.tag = tag;
    this.sub = sub;
}
ASN1.prototype.typeName = function() {
    if (this.tag == undefined)
        return "unknown";
    var tagClass = this.tag >> 6;
    var tagConstructed = (this.tag >> 5) & 1;
    var tagNumber = this.tag & 0x1F;
    switch (tagClass) {
    case 0: // universal
        switch (tagNumber) {
        case 0x00: return "EOC";
        case 0x01: return "BOOLEAN";
        case 0x02: return "INTEGER";
        case 0x03: return "BIT_STRING";
        case 0x04: return "OCTET_STRING";
        case 0x05: return "NULL";
        case 0x06: return "OBJECT_IDENTIFIER";
        case 0x07: return "ObjectDescriptor";
        case 0x08: return "EXTERNAL";
        case 0x09: return "REAL";
        case 0x0A: return "ENUMERATED";
        case 0x0B: return "EMBEDDED_PDV";
        case 0x0C: return "UTF8String";
        case 0x10: return "SEQUENCE";
        case 0x11: return "SET";
        case 0x12: return "NumericString";
        case 0x13: return "PrintableString"; // ASCII subset
        case 0x14: return "TeletexString"; // aka T61String
        case 0x15: return "VideotexString";
        case 0x16: return "IA5String"; // ASCII
        case 0x17: return "UTCTime";
        case 0x18: return "GeneralizedTime";
        case 0x19: return "GraphicString";
        case 0x1A: return "VisibleString"; // ASCII subset
        case 0x1B: return "GeneralString";
        case 0x1C: return "UniversalString";
        case 0x1E: return "BMPString";
        default: return "Universal_" + tagNumber.toString(16);
        }
    case 1: return "Application_" + tagNumber.toString(16);
    case 2: return "[" + tagNumber + "]"; // Context
    case 3: return "Private_" + tagNumber.toString(16);
    }
}
ASN1.prototype.content = function() {
    if (this.tag == undefined)
        return null;
    var tagClass = this.tag >> 6;
    if (tagClass != 0) // universal
        return (this.sub == null) ? null : "(" + this.sub.length + ")";
    var tagNumber = this.tag & 0x1F;
    var content = this.posContent();
    var len = Math.abs(this.length);
    switch (tagNumber) {
    case 0x01: // BOOLEAN
        return (this.stream.get(content) == 0) ? "false" : "true";
    case 0x02: // INTEGER
        return this.stream.parseInteger(content, content + len);
    case 0x03: // BIT_STRING
        return this.sub ? "(" + this.sub.length + " elem)" :
            this.stream.parseBitString(content, content + len)
    case 0x04: // OCTET_STRING
        return this.sub ? "(" + this.sub.length + " elem)" :
            this.stream.parseOctetString(content, content + len)
    //case 0x05: // NULL
    case 0x06: // OBJECT_IDENTIFIER
        return this.stream.parseOID(content, content + len);
    //case 0x07: // ObjectDescriptor
    //case 0x08: // EXTERNAL
    //case 0x09: // REAL
    //case 0x0A: // ENUMERATED
    //case 0x0B: // EMBEDDED_PDV
    case 0x10: // SEQUENCE
    case 0x11: // SET
        return "(" + this.sub.length + " elem)";
    case 0x0C: // UTF8String
        return this.stream.parseStringUTF(content, content + len);
    case 0x12: // NumericString
    case 0x13: // PrintableString
    case 0x14: // TeletexString
    case 0x15: // VideotexString
    case 0x16: // IA5String
    //case 0x19: // GraphicString
    case 0x1A: // VisibleString
    //case 0x1B: // GeneralString
    //case 0x1C: // UniversalString
    //case 0x1E: // BMPString
        return this.stream.parseStringISO(content, content + len);
    case 0x17: // UTCTime
    case 0x18: // GeneralizedTime
        return this.stream.parseTime(content, content + len);
    }
    return null;
}
ASN1.prototype.toString = function() {
    return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + ((this.sub == null) ? 'null' : this.sub.length) + "]";
}
ASN1.prototype.print = function(indent) {
    if (indent == undefined) indent = '';
    document.writeln(indent + this);
    if (this.sub != null) {
        indent += '  ';
        for (var i = 0, max = this.sub.length; i < max; ++i)
            this.sub[i].print(indent);
    }
}
ASN1.prototype.toPrettyString = function(indent) {
    if (indent == undefined) indent = '';
    var s = indent + this.typeName() + " @" + this.stream.pos;
    if (this.length >= 0)
        s += "+";
    s += this.length;
    if (this.tag & 0x20)
        s += " (constructed)";
    else if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub != null))
        s += " (encapsulates)";
    s += "\n";
    if (this.sub != null) {
        indent += '  ';
        for (var i = 0, max = this.sub.length; i < max; ++i)
            s += this.sub[i].toPrettyString(indent);
    }
    return s;
}
ASN1.prototype.posStart = function() {
    return this.stream.pos;
}
ASN1.prototype.posContent = function() {
    return this.stream.pos + this.header;
}
ASN1.prototype.posEnd = function() {
    return this.stream.pos + this.header + Math.abs(this.length);
}
ASN1.decodeLength = function(stream) {
    var buf = stream.get();
    var len = buf & 0x7F;
    if (len == buf)
        return len;
    if (len > 3)
        throw "Length over 24 bits not supported at position " + (stream.pos - 1);
    if (len == 0)
        return -1; // undefined
    buf = 0;
    for (var i = 0; i < len; ++i)
        buf = (buf << 8) | stream.get();
    return buf;
}
ASN1.hasContent = function(tag, len, stream) {
    if (tag & 0x20) // constructed
        return true;
    if ((tag < 0x03) || (tag > 0x04))
        return false;
    var p = new Stream(stream);
    if (tag == 0x03) p.get(); // BitString unused bits, must be in [0, 7]
    var subTag = p.get();
    if ((subTag >> 6) & 0x01) // not (universal or context)
        return false;
    try {
        var subLength = ASN1.decodeLength(p);
        return ((p.pos - stream.pos) + subLength == len);
    } catch (exception) {
        return false;
    }
}
ASN1.decode = function(stream) {
    if (!(stream instanceof Stream))
        stream = new Stream(stream, 0);
    var streamStart = new Stream(stream);
    var tag = stream.get();
    var len = ASN1.decodeLength(stream);
    var header = stream.pos - streamStart.pos;
    var sub = null;
    if (ASN1.hasContent(tag, len, stream)) {
        // it has content, so we decode it
        var start = stream.pos;
        if (tag == 0x03) stream.get(); // skip BitString unused bits, must be in [0, 7]
        sub = [];
        if (len >= 0) {
            // definite length
            var end = start + len;
            while (stream.pos < end)
                sub[sub.length] = ASN1.decode(stream);
            if (stream.pos != end)
                throw "Content size is not correct for container starting at offset " + start;
        } else {
            // undefined length
            try {
                for (;;) {
                    var s = ASN1.decode(stream);
                    if (s.tag == 0)
                        break;
                    sub[sub.length] = s;
                }
                len = start - stream.pos;
            } catch (e) {
                throw "Exception while decoding undefined length content: " + e;
            }
        }
    } else
        stream.pos += len; // skip content
    return new ASN1(streamStart, header, len, tag, sub);
}

var b64map="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var b64padchar="=";

function hex2b64(h) {
  var i;
  var c;
  var ret = "";
  for(i = 0; i+3 <= h.length; i+=3) {
    c = parseInt(h.substring(i,i+3),16);
    ret += b64map.charAt(c >> 6) + b64map.charAt(c & 63);
  }
  if(i+1 == h.length) {
    c = parseInt(h.substring(i,i+1),16);
    ret += b64map.charAt(c << 2);
  }
  else if(i+2 == h.length) {
    c = parseInt(h.substring(i,i+2),16);
    ret += b64map.charAt(c >> 2) + b64map.charAt((c & 3) << 4);
  }
  while((ret.length & 3) > 0) ret += b64padchar;
  return ret;
}

// convert a base64 string to hex
function b64tohex(s) {
  var ret = "";
  var i;
  var k = 0; // b64 state, 0-3
  var slop;
  var v;
  for(i = 0; i < s.length; ++i) {
    if(s.charAt(i) == b64padchar) break;
    v = b64map.indexOf(s.charAt(i));
    if(v < 0) continue;
    if(k == 0) {
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 1;
    }
    else if(k == 1) {
      ret += int2char((slop << 2) | (v >> 4));
      slop = v & 0xf;
      k = 2;
    }
    else if(k == 2) {
      ret += int2char(slop);
      ret += int2char(v >> 2);
      slop = v & 3;
      k = 3;
    }
    else {
      ret += int2char((slop << 2) | (v >> 4));
      ret += int2char(v & 0xf);
      k = 0;
    }
  }
  if(k == 1)
    ret += int2char(slop << 2);
  return ret;
}

// convert a base64 string to a byte/number array
function b64toBA(s) {
  //piggyback on b64tohex for now, optimize later
  var h = b64tohex(s);
  var i;
  var a = new Array();
  for(i = 0; 2*i < h.length; ++i) {
    a[i] = parseInt(h.substring(2*i,2*i+2),16);
  }
  return a;
}

// Copyright (c) 2005  Tom Wu
// All Rights Reserved.
// See "LICENSE" for details.

// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {
  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+this.DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return (this.s<0)?-r:r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);

// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    throw new Error("Message too long for RSA");
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var randomByte = 0;
  var random = 0;
  var shift = 0;
  while(n > 2) { // random non-zero pad
    if (shift == 0) {
      random = sjcl.random.randomWords(1, 0)[0];
    }

    randomByte = (random >> shift) & 0xff;
    shift = (shift + 8) % 32;
    if (randomByte != 0) {
      ba[--n] = randomByte;
    }
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

// "empty" RSA key constructor
function RSAKey() {
  this.n = null;
  this.e = 0;
  this.d = null;
  this.p = null;
  this.q = null;
  this.dmp1 = null;
  this.dmq1 = null;
  this.coeff = null;
}

// Set the public key fields N and e from hex strings
function RSASetPublic(N,E) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
  }
  else
    throw new Error("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
}

// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}

// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;

/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

"use strict";
/*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape */

/** @namespace The Stanford Javascript Crypto Library, top-level namespace. */
var sjcl = {
  /** @namespace Symmetric ciphers. */
  cipher: {},

  /** @namespace Hash functions.  Right now only SHA256 is implemented. */
  hash: {},

  /** @namespace Key exchange functions.  Right now only SRP is implemented. */
  keyexchange: {},
  
  /** @namespace Block cipher modes of operation. */
  mode: {},

  /** @namespace Miscellaneous.  HMAC and PBKDF2. */
  misc: {},
  
  /**
   * @namespace Bit array encoders and decoders.
   *
   * @description
   * The members of this namespace are functions which translate between
   * SJCL's bitArrays and other objects (usually strings).  Because it
   * isn't always clear which direction is encoding and which is decoding,
   * the method names are "fromBits" and "toBits".
   */
  codec: {},
  
  /** @namespace Exceptions. */
  exception: {
    /** @class Ciphertext is corrupt. */
    corrupt: function(message) {
      this.toString = function() { return "CORRUPT: "+this.message; };
      this.message = message;
    },
    
    /** @class Invalid parameter. */
    invalid: function(message) {
      this.toString = function() { return "INVALID: "+this.message; };
      this.message = message;
    },
    
    /** @class Bug or missing feature in SJCL. */
    bug: function(message) {
      this.toString = function() { return "BUG: "+this.message; };
      this.message = message;
    },

    /** @class Something isn't ready. */
    notReady: function(message) {
      this.toString = function() { return "NOT READY: "+this.message; };
      this.message = message;
    }
  }
};

if(typeof module != 'undefined' && module.exports){
  module.exports = sjcl;
}

/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 *
 * @class Advanced Encryption Standard (low-level interface)
 */
sjcl.cipher.aes = function (key) {
  if (!this._tables[0][0][0]) {
    this._precompute();
  }
  
  var i, j, tmp,
    encKey, decKey,
    sbox = this._tables[0][4], decTable = this._tables[1],
    keyLen = key.length, rcon = 1;
  
  if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
    throw new sjcl.exception.invalid("invalid aes key size");
  }
  
  this._key = [encKey = key.slice(0), decKey = []];
  
  // schedule encryption keys
  for (i = keyLen; i < 4 * keyLen + 28; i++) {
    tmp = encKey[i-1];
    
    // apply sbox
    if (i%keyLen === 0 || (keyLen === 8 && i%keyLen === 4)) {
      tmp = sbox[tmp>>>24]<<24 ^ sbox[tmp>>16&255]<<16 ^ sbox[tmp>>8&255]<<8 ^ sbox[tmp&255];
      
      // shift rows and add rcon
      if (i%keyLen === 0) {
        tmp = tmp<<8 ^ tmp>>>24 ^ rcon<<24;
        rcon = rcon<<1 ^ (rcon>>7)*283;
      }
    }
    
    encKey[i] = encKey[i-keyLen] ^ tmp;
  }
  
  // schedule decryption keys
  for (j = 0; i; j++, i--) {
    tmp = encKey[j&3 ? i : i - 4];
    if (i<=4 || j<4) {
      decKey[j] = tmp;
    } else {
      decKey[j] = decTable[0][sbox[tmp>>>24      ]] ^
                  decTable[1][sbox[tmp>>16  & 255]] ^
                  decTable[2][sbox[tmp>>8   & 255]] ^
                  decTable[3][sbox[tmp      & 255]];
    }
  }
};

sjcl.cipher.aes.prototype = {
  // public
  /* Something like this might appear here eventually
  name: "AES",
  blockSize: 4,
  keySizes: [4,6,8],
  */
  
  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
  encrypt:function (data) { return this._crypt(data,0); },
  
  /**
   * Decrypt an array of 4 big-endian words.
   * @param {Array} data The ciphertext.
   * @return {Array} The plaintext.
   */
  decrypt:function (data) { return this._crypt(data,1); },
  
  /**
   * The expanded S-box and inverse S-box tables.  These will be computed
   * on the client so that we don't have to send them down the wire.
   *
   * There are two tables, _tables[0] is for encryption and
   * _tables[1] is for decryption.
   *
   * The first 4 sub-tables are the expanded S-box with MixColumns.  The
   * last (_tables[01][4]) is the S-box itself.
   *
   * @private
   */
  _tables: [[[],[],[],[],[]],[[],[],[],[],[]]],

  /**
   * Expand the S-box tables.
   *
   * @private
   */
  _precompute: function () {
   var encTable = this._tables[0], decTable = this._tables[1],
       sbox = encTable[4], sboxInv = decTable[4],
       i, x, xInv, d=[], th=[], x2, x4, x8, s, tEnc, tDec;

    // Compute double and third tables
   for (i = 0; i < 256; i++) {
     th[( d[i] = i<<1 ^ (i>>7)*283 )^i]=i;
   }
   
   for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
     // Compute sbox
     s = xInv ^ xInv<<1 ^ xInv<<2 ^ xInv<<3 ^ xInv<<4;
     s = s>>8 ^ s&255 ^ 99;
     sbox[x] = s;
     sboxInv[s] = x;
     
     // Compute MixColumns
     x8 = d[x4 = d[x2 = d[x]]];
     tDec = x8*0x1010101 ^ x4*0x10001 ^ x2*0x101 ^ x*0x1010100;
     tEnc = d[s]*0x101 ^ s*0x1010100;
     
     for (i = 0; i < 4; i++) {
       encTable[i][x] = tEnc = tEnc<<24 ^ tEnc>>>8;
       decTable[i][s] = tDec = tDec<<24 ^ tDec>>>8;
     }
   }
   
   // Compactify.  Considerable speedup on Firefox.
   for (i = 0; i < 5; i++) {
     encTable[i] = encTable[i].slice(0);
     decTable[i] = decTable[i].slice(0);
   }
  },
  
  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param dir The direction, 0 for encrypt and 1 for decrypt.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  _crypt:function (input, dir) {
    if (input.length !== 4) {
      throw new sjcl.exception.invalid("invalid aes block size");
    }
    
    var key = this._key[dir],
        // state variables a,b,c,d are loaded with pre-whitened data
        a = input[0]           ^ key[0],
        b = input[dir ? 3 : 1] ^ key[1],
        c = input[2]           ^ key[2],
        d = input[dir ? 1 : 3] ^ key[3],
        a2, b2, c2,
        
        nInnerRounds = key.length/4 - 2,
        i,
        kIndex = 4,
        out = [0,0,0,0],
        table = this._tables[dir],
        
        // load up the tables
        t0    = table[0],
        t1    = table[1],
        t2    = table[2],
        t3    = table[3],
        sbox  = table[4];
 
    // Inner rounds.  Cribbed from OpenSSL.
    for (i = 0; i < nInnerRounds; i++) {
      a2 = t0[a>>>24] ^ t1[b>>16 & 255] ^ t2[c>>8 & 255] ^ t3[d & 255] ^ key[kIndex];
      b2 = t0[b>>>24] ^ t1[c>>16 & 255] ^ t2[d>>8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
      c2 = t0[c>>>24] ^ t1[d>>16 & 255] ^ t2[a>>8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
      d  = t0[d>>>24] ^ t1[a>>16 & 255] ^ t2[b>>8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
      kIndex += 4;
      a=a2; b=b2; c=c2;
    }
        
    // Last round.
    for (i = 0; i < 4; i++) {
      out[dir ? 3&-i : i] =
        sbox[a>>>24      ]<<24 ^ 
        sbox[b>>16  & 255]<<16 ^
        sbox[c>>8   & 255]<<8  ^
        sbox[d      & 255]     ^
        key[kIndex++];
      a2=a; a=b; b=c; c=d; d=a2;
    }
    
    return out;
  }
};


/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Arrays of bits, encoded as arrays of Numbers.
 *
 * @description
 * <p>
 * These objects are the currency accepted by SJCL's crypto functions.
 * </p>
 *
 * <p>
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 * </p>
 *
 * <p>
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 * </p>
 */
sjcl.bitArray = {
  /**
   * Array slices in units of bits.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
   * slice until the end of the array.
   * @return {bitArray} The requested slice.
   */
  bitSlice: function (a, bstart, bend) {
    a = sjcl.bitArray._shiftRight(a.slice(bstart/32), 32 - (bstart & 31)).slice(1);
    return (bend === undefined) ? a : sjcl.bitArray.clamp(a, bend-bstart);
  },

  /**
   * Extract a number packed into a bit array.
   * @param {bitArray} a The array to slice.
   * @param {Number} bstart The offset to the start of the slice, in bits.
   * @param {Number} length The length of the number to extract.
   * @return {Number} The requested slice.
   */
  extract: function(a, bstart, blength) {
    // FIXME: this Math.floor is not necessary at all, but for some reason
    // seems to suppress a bug in the Chromium JIT.
    var x, sh = Math.floor((-bstart-blength) & 31);
    if ((bstart + blength - 1 ^ bstart) & -32) {
      // it crosses a boundary
      x = (a[bstart/32|0] << (32 - sh)) ^ (a[bstart/32+1|0] >>> sh);
    } else {
      // within a single word
      x = a[bstart/32|0] >>> sh;
    }
    return x & ((1<<blength) - 1);
  },

  /**
   * Concatenate two bit arrays.
   * @param {bitArray} a1 The first array.
   * @param {bitArray} a2 The second array.
   * @return {bitArray} The concatenation of a1 and a2.
   */
  concat: function (a1, a2) {
    if (a1.length === 0 || a2.length === 0) {
      return a1.concat(a2);
    }
    
    var out, i, last = a1[a1.length-1], shift = sjcl.bitArray.getPartial(last);
    if (shift === 32) {
      return a1.concat(a2);
    } else {
      return sjcl.bitArray._shiftRight(a2, shift, last|0, a1.slice(0,a1.length-1));
    }
  },

  /**
   * Find the length of an array of bits.
   * @param {bitArray} a The array.
   * @return {Number} The length of a, in bits.
   */
  bitLength: function (a) {
    var l = a.length, x;
    if (l === 0) { return 0; }
    x = a[l - 1];
    return (l-1) * 32 + sjcl.bitArray.getPartial(x);
  },

  /**
   * Truncate an array.
   * @param {bitArray} a The array.
   * @param {Number} len The length to truncate to, in bits.
   * @return {bitArray} A new array, truncated to len bits.
   */
  clamp: function (a, len) {
    if (a.length * 32 < len) { return a; }
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len) {
      a[l-1] = sjcl.bitArray.partial(len, a[l-1] & 0x80000000 >> (len-1), 1);
    }
    return a;
  },

  /**
   * Make a partial word for a bit array.
   * @param {Number} len The number of bits in the word.
   * @param {Number} x The bits.
   * @param {Number} [0] _end Pass 1 if x has already been shifted to the high side.
   * @return {Number} The partial word.
   */
  partial: function (len, x, _end) {
    if (len === 32) { return x; }
    return (_end ? x|0 : x << (32-len)) + len * 0x10000000000;
  },

  /**
   * Get the number of bits used by a partial word.
   * @param {Number} x The partial word.
   * @return {Number} The number of bits used by the partial word.
   */
  getPartial: function (x) {
    return Math.round(x/0x10000000000) || 32;
  },

  /**
   * Compare two arrays for equality in a predictable amount of time.
   * @param {bitArray} a The first array.
   * @param {bitArray} b The second array.
   * @return {boolean} true if a == b; false otherwise.
   */
  equal: function (a, b) {
    if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
      return false;
    }
    var x = 0, i;
    for (i=0; i<a.length; i++) {
      x |= a[i]^b[i];
    }
    return (x === 0);
  },

  /** Shift an array right.
   * @param {bitArray} a The array to shift.
   * @param {Number} shift The number of bits to shift.
   * @param {Number} [carry=0] A byte to carry in
   * @param {bitArray} [out=[]] An array to prepend to the output.
   * @private
   */
  _shiftRight: function (a, shift, carry, out) {
    var i, last2=0, shift2;
    if (out === undefined) { out = []; }
    
    for (; shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }
    if (shift === 0) {
      return out.concat(a);
    }
    
    for (i=0; i<a.length; i++) {
      out.push(carry | a[i]>>>shift);
      carry = a[i] << (32-shift);
    }
    last2 = a.length ? a[a.length-1] : 0;
    shift2 = sjcl.bitArray.getPartial(last2);
    out.push(sjcl.bitArray.partial(shift+shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(),1));
    return out;
  },
  
  /** xor a block of 4 words together.
   * @private
   */
  _xor4: function(x,y) {
    return [x[0]^y[0],x[1]^y[1],x[2]^y[2],x[3]^y[3]];
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Hexadecimal */
sjcl.codec.hex = {
  /** Convert from a bitArray to a hex string. */
  fromBits: function (arr) {
    var out = "", i, x;
    for (i=0; i<arr.length; i++) {
      out += ((arr[i]|0)+0xF00000000000).toString(16).substr(4);
    }
    return out.substr(0, sjcl.bitArray.bitLength(arr)/4);//.replace(/(.{8})/g, "$1 ");
  },
  /** Convert from a hex string to a bitArray. */
  toBits: function (str) {
    var i, out=[], len;
    str = str.replace(/\s|0x/g, "");
    len = str.length;
    str = str + "00000000";
    for (i=0; i<str.length; i+=8) {
      out.push(parseInt(str.substr(i,8),16)^0);
    }
    return sjcl.bitArray.clamp(out, len*4);
  }
};


/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
 
/** @namespace UTF-8 strings */
sjcl.codec.utf8String = {
  /** Convert from a bitArray to a UTF-8 string. */
  fromBits: function (arr) {
    var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
    for (i=0; i<bl/8; i++) {
      if ((i&3) === 0) {
        tmp = arr[i/4];
      }
      out += String.fromCharCode(tmp >>> 24);
      tmp <<= 8;
    }
    return decodeURIComponent(escape(out));
  },
  
  /** Convert from a UTF-8 string to a bitArray. */
  toBits: function (str) {
    str = unescape(encodeURIComponent(str));
    var out = [], i, tmp=0;
    for (i=0; i<str.length; i++) {
      tmp = tmp << 8 | str.charCodeAt(i);
      if ((i&3) === 3) {
        out.push(tmp);
        tmp = 0;
      }
    }
    if (i&3) {
      out.push(sjcl.bitArray.partial(8*(i&3), tmp));
    }
    return out;
  }
};

/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Base64 encoding/decoding */
sjcl.codec.base64 = {
  /** The base64 alphabet.
   * @private
   */
  _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
  
  /** Convert from a bitArray to a base64 string. */
  fromBits: function (arr, _noEquals, _url) {
    var out = "", i, bits=0, c = sjcl.codec.base64._chars, ta=0, bl = sjcl.bitArray.bitLength(arr);
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; out.length * 6 < bl; ) {
      out += c.charAt((ta ^ arr[i]>>>bits) >>> 26);
      if (bits < 6) {
        ta = arr[i] << (6-bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }
    while ((out.length & 3) && !_noEquals) { out += "="; }
    return out;
  },
  
  /** Convert from a base64 string to a bitArray */
  toBits: function(str, _url) {
    str = str.replace(/\s|=/g,'');
    var out = [], i, bits=0, c = sjcl.codec.base64._chars, ta=0, x;
    if (_url) c = c.substr(0,62) + '-_';
    for (i=0; i<str.length; i++) {
      x = c.indexOf(str.charAt(i));
      if (x < 0) {
        throw new sjcl.exception.invalid("this isn't base64!");
      }
      if (bits > 26) {
        bits -= 26;
        out.push(ta ^ x>>>bits);
        ta  = x << (32-bits);
      } else {
        bits += 6;
        ta ^= x << (32-bits);
      }
    }
    if (bits&56) {
      out.push(sjcl.bitArray.partial(bits&56, ta, 1));
    }
    return out;
  }
};

sjcl.codec.base64url = {
  fromBits: function (arr) { return sjcl.codec.base64.fromBits(arr,1,1); },
  toBits: function (str) { return sjcl.codec.base64.toBits(str,1); }
};

/** @fileOverview CBC mode implementation
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace
 * Dangerous: CBC mode with PKCS#5 padding.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
if (sjcl.beware === undefined) {
  sjcl.beware = {};
}
sjcl.beware["CBC mode is dangerous because it doesn't protect message integrity."
] = function() {
  sjcl.mode.cbc = {
    /** The name of the mode.
     * @constant
     */
    name: "cbc",
    
    /** Encrypt in CBC mode with PKCS#5 padding.
     * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
     * @param {bitArray} plaintext The plaintext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} [adata=[]] The authenticated data.  Must be empty.
     * @return The encrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
     */
    encrypt: function(prp, plaintext, iv, adata) {
      if (adata && adata.length) {
        throw new sjcl.exception.invalid("cbc can't authenticate data");
      }
      if (sjcl.bitArray.bitLength(iv) !== 128) {
        throw new sjcl.exception.invalid("cbc iv must be 128 bits");
      }
      var i,
          w = sjcl.bitArray,
          xor = w._xor4,
          bl = w.bitLength(plaintext),
          bp = 0,
          output = [];

      if (bl&7) {
        throw new sjcl.exception.invalid("pkcs#5 padding only works for multiples of a byte");
      }
    
      for (i=0; bp+128 <= bl; i+=4, bp+=128) {
        /* Encrypt a non-final block */
        iv = prp.encrypt(xor(iv, plaintext.slice(i,i+4)));
        output.splice(i,0,iv[0],iv[1],iv[2],iv[3]);
      }
      
      /* Construct the pad. */
      bl = (16 - ((bl >> 3) & 15)) * 0x1010101;

      /* Pad and encrypt. */
      iv = prp.encrypt(xor(iv,w.concat(plaintext,[bl,bl,bl,bl]).slice(i,i+4)));
      output.splice(i,0,iv[0],iv[1],iv[2],iv[3]);
      return output;
    },
    
    /** Decrypt in CBC mode.
     * @param {Object} prp The block cipher.  It must have a block size of 16 bytes.
     * @param {bitArray} ciphertext The ciphertext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} [adata=[]] The authenticated data.  It must be empty.
     * @return The decrypted data, an array of bytes.
     * @throws {sjcl.exception.invalid} if the IV isn't exactly 128 bits, or if any adata is specified.
     * @throws {sjcl.exception.corrupt} if if the message is corrupt.
     */
    decrypt: function(prp, ciphertext, iv, adata) {
      if (adata && adata.length) {
        throw new sjcl.exception.invalid("cbc can't authenticate data");
      }
      if (sjcl.bitArray.bitLength(iv) !== 128) {
        throw new sjcl.exception.invalid("cbc iv must be 128 bits");
      }
      if ((sjcl.bitArray.bitLength(ciphertext) & 127) || !ciphertext.length) {
        throw new sjcl.exception.corrupt("cbc ciphertext must be a positive multiple of the block size");
      }
      var i,
          w = sjcl.bitArray,
          xor = w._xor4,
          bi, bo,
          output = [];
          
      adata = adata || [];
    
      for (i=0; i<ciphertext.length; i+=4) {
        bi = ciphertext.slice(i,i+4);
        bo = xor(iv,prp.decrypt(bi));
        output.splice(i,0,bo[0],bo[1],bo[2],bo[3]);
        iv = bi;
      }

      /* check and remove the pad */
      bi = output[i-1] & 255;
      if (bi == 0 || bi > 16) {
        throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
      }
      bo = bi * 0x1010101;
      if (!w.equal(w.bitSlice([bo,bo,bo,bo], 0, bi*8),
                   w.bitSlice(output, output.length*32 - bi*8, output.length*32))) {
        throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
      }

      return w.bitSlice(output, 0, output.length*32 - bi*8);
    }
  };
};

/** @fileOverview HMAC implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** HMAC with the specified hash function.
 * @constructor
 * @param {bitArray} key the key for HMAC.
 * @param {Object} [hash=sjcl.hash.sha256] The hash function to use.
 */
sjcl.misc.hmac = function (key, Hash) {
  this._hash = Hash = Hash || sjcl.hash.sha256;
  var exKey = [[],[]], i,
      bs = Hash.prototype.blockSize / 32;
  this._baseHash = [new Hash(), new Hash()];

  if (key.length > bs) {
    key = Hash.hash(key);
  }
  
  for (i=0; i<bs; i++) {
    exKey[0][i] = key[i]^0x36363636;
    exKey[1][i] = key[i]^0x5C5C5C5C;
  }
  
  this._baseHash[0].update(exKey[0]);
  this._baseHash[1].update(exKey[1]);
};

/** HMAC with the specified hash function.  Also called encrypt since it's a prf.
 * @param {bitArray|String} data The data to mac.
 * @param {Codec} [encoding] the encoding function to use.
 */
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (data, encoding) {
  var w = new (this._hash)(this._baseHash[0]).update(data, encoding).finalize();
  return new (this._hash)(this._baseHash[1]).update(w).finalize();
};


/** @fileOverview Javascript SHA-256 implementation.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * Special thanks to Aldo Cortesi for pointing out several bugs in
 * this code.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/**
 * Context for a SHA-256 operation in progress.
 * @constructor
 * @class Secure Hash Algorithm, 256 bits.
 */
sjcl.hash.sha256 = function (hash) {
  if (!this._key[0]) { this._precompute(); }
  if (hash) {
    this._h = hash._h.slice(0);
    this._buffer = hash._buffer.slice(0);
    this._length = hash._length;
  } else {
    this.reset();
  }
};

/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 16 big-endian words.
 */
sjcl.hash.sha256.hash = function (data) {
  return (new sjcl.hash.sha256()).update(data).finalize();
};

sjcl.hash.sha256.prototype = {
  /**
   * The hash's block size, in bits.
   * @constant
   */
  blockSize: 512,
   
  /**
   * Reset the hash state.
   * @return this
   */
  reset:function () {
    this._h = this._init.slice(0);
    this._buffer = [];
    this._length = 0;
    return this;
  },
  
  /**
   * Input several words to the hash.
   * @param {bitArray|String} data the data to hash.
   * @return this
   */
  update: function (data) {
    if (typeof data === "string") {
      data = sjcl.codec.utf8String.toBits(data);
    }
    var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data),
        ol = this._length,
        nl = this._length = ol + sjcl.bitArray.bitLength(data);
    for (i = 512+ol & -512; i <= nl; i+= 512) {
      this._block(b.splice(0,16));
    }
    return this;
  },
  
  /**
   * Complete hashing and output the hash value.
   * @return {bitArray} The hash value, an array of 16 big-endian words.
   */
  finalize:function () {
    var i, b = this._buffer, h = this._h;

    // Round out and push the buffer
    b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1,1)]);
    
    // Round out the buffer to a multiple of 16 words, less the 2 length words.
    for (i = b.length + 2; i & 15; i++) {
      b.push(0);
    }
    
    // append the length
    b.push(Math.floor(this._length / 0x100000000));
    b.push(this._length | 0);

    while (b.length) {
      this._block(b.splice(0,16));
    }

    this.reset();
    return h;
  },

  /**
   * The SHA-256 initialization vector, to be precomputed.
   * @private
   */
  _init:[],
  /*
  _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
  */
  
  /**
   * The SHA-256 hash key, to be precomputed.
   * @private
   */
  _key:[],
  /*
  _key:
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
  */


  /**
   * Function to precompute _init and _key.
   * @private
   */
  _precompute: function () {
    var i = 0, prime = 2, factor;

    function frac(x) { return (x-Math.floor(x)) * 0x100000000 | 0; }

    outer: for (; i<64; prime++) {
      for (factor=2; factor*factor <= prime; factor++) {
        if (prime % factor === 0) {
          // not a prime
          continue outer;
        }
      }
      
      if (i<8) {
        this._init[i] = frac(Math.pow(prime, 1/2));
      }
      this._key[i] = frac(Math.pow(prime, 1/3));
      i++;
    }
  },
  
  /**
   * Perform one cycle of SHA-256.
   * @param {bitArray} words one block of words.
   * @private
   */
  _block:function (words) {  
    var i, tmp, a, b,
      w = words.slice(0),
      h = this._h,
      k = this._key,
      h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3],
      h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];

    /* Rationale for placement of |0 :
     * If a value can overflow is original 32 bits by a factor of more than a few
     * million (2^23 ish), there is a possibility that it might overflow the
     * 53-bit mantissa and lose precision.
     *
     * To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
     * propagates around the loop, and on the hash state h[].  I don't believe
     * that the clamps on h4 and on h0 are strictly necessary, but it's close
     * (for h4 anyway), and better safe than sorry.
     *
     * The clamps on h[] are necessary for the output to be correct even in the
     * common case and for short inputs.
     */
    for (i=0; i<64; i++) {
      // load up the input word for this round
      if (i<16) {
        tmp = w[i];
      } else {
        a   = w[(i+1 ) & 15];
        b   = w[(i+14) & 15];
        tmp = w[i&15] = ((a>>>7  ^ a>>>18 ^ a>>>3  ^ a<<25 ^ a<<14) + 
                         (b>>>17 ^ b>>>19 ^ b>>>10 ^ b<<15 ^ b<<13) +
                         w[i&15] + w[(i+9) & 15]) | 0;
      }
      
      tmp = (tmp + h7 + (h4>>>6 ^ h4>>>11 ^ h4>>>25 ^ h4<<26 ^ h4<<21 ^ h4<<7) +  (h6 ^ h4&(h5^h6)) + k[i]); // | 0;
      
      // shift register
      h7 = h6; h6 = h5; h5 = h4;
      h4 = h3 + tmp | 0;
      h3 = h2; h2 = h1; h1 = h0;

      h0 = (tmp +  ((h1&h2) ^ (h3&(h1^h2))) + (h1>>>2 ^ h1>>>13 ^ h1>>>22 ^ h1<<30 ^ h1<<19 ^ h1<<10)) | 0;
    }

    h[0] = h[0]+h0 | 0;
    h[1] = h[1]+h1 | 0;
    h[2] = h[2]+h2 | 0;
    h[3] = h[3]+h3 | 0;
    h[4] = h[4]+h4 | 0;
    h[5] = h[5]+h5 | 0;
    h[6] = h[6]+h6 | 0;
    h[7] = h[7]+h7 | 0;
  }
};



/** @fileOverview Random number generator.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */

/** @namespace Random number generator
 *
 * @description
 * <p>
 * This random number generator is a derivative of Ferguson and Schneier's
 * generator Fortuna.  It collects entropy from various events into several
 * pools, implemented by streaming SHA-256 instances.  It differs from
 * ordinary Fortuna in a few ways, though.
 * </p>
 *
 * <p>
 * Most importantly, it has an entropy estimator.  This is present because
 * there is a strong conflict here between making the generator available
 * as soon as possible, and making sure that it doesn't "run on empty".
 * In Fortuna, there is a saved state file, and the system is likely to have
 * time to warm up.
 * </p>
 *
 * <p>
 * Second, because users are unlikely to stay on the page for very long,
 * and to speed startup time, the number of pools increases logarithmically:
 * a new pool is created when the previous one is actually used for a reseed.
 * This gives the same asymptotic guarantees as Fortuna, but gives more
 * entropy to early reseeds.
 * </p>
 *
 * <p>
 * The entire mechanism here feels pretty klunky.  Furthermore, there are
 * several improvements that should be made, including support for
 * dedicated cryptographic functions that may be present in some browsers;
 * state files in local storage; cookies containing randomness; etc.  So
 * look for improvements in future versions.
 * </p>
 */
sjcl.random = {
  /** Generate several random words, and return them in an array
   * @param {Number} nwords The number of words to generate.
   */
  randomWords: function (nwords, paranoia) {
    var out = [], i, readiness = this.isReady(paranoia), g;
  
    if (readiness === this._NOT_READY) {
      throw new sjcl.exception.notReady("generator isn't seeded");
    } else if (readiness & this._REQUIRES_RESEED) {
      this._reseedFromPools(!(readiness & this._READY));
    }
  
    for (i=0; i<nwords; i+= 4) {
      if ((i+1) % this._MAX_WORDS_PER_BURST === 0) {
        this._gate();
      }
   
      g = this._gen4words();
      out.push(g[0],g[1],g[2],g[3]);
    }
    this._gate();
  
    return out.slice(0,nwords);
  },
  
  setDefaultParanoia: function (paranoia) {
    this._defaultParanoia = paranoia;
  },
  
  /**
   * Add entropy to the pools.
   * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
   * @param {Number} estimatedEntropy The estimated entropy of data, in bits
   * @param {String} source The source of the entropy, eg "mouse"
   */
  addEntropy: function (data, estimatedEntropy, source) {
    source = source || "user";
  
    var id,
      i, tmp,
      t = (new Date()).valueOf(),
      robin = this._robins[source],
      oldReady = this.isReady(), err = 0;
      
    id = this._collectorIds[source];
    if (id === undefined) { id = this._collectorIds[source] = this._collectorIdNext ++; }
      
    if (robin === undefined) { robin = this._robins[source] = 0; }
    this._robins[source] = ( this._robins[source] + 1 ) % this._pools.length;
  
    switch(typeof(data)) {
      
    case "number":
      if (estimatedEntropy === undefined) {
        estimatedEntropy = 1;
      }
      this._pools[robin].update([id,this._eventId++,1,estimatedEntropy,t,1,data|0]);
      break;
      
    case "object":
      var objName = Object.prototype.toString.call(data);
      if (objName === "[object Uint32Array]") {
        tmp = [];
        for (i = 0; i < data.length; i++) {
          tmp.push(data[i]);
        }
        data = tmp;
      } else {
        if (objName !== "[object Array]") {
          err = 1;
        }
        for (i=0; i<data.length && !err; i++) {
          if (typeof(data[i]) != "number") {
            err = 1;
          }
        }
      }
      if (!err) {
        if (estimatedEntropy === undefined) {
          /* horrible entropy estimator */
          estimatedEntropy = 0;
          for (i=0; i<data.length; i++) {
            tmp= data[i];
            while (tmp>0) {
              estimatedEntropy++;
              tmp = tmp >>> 1;
            }
          }
        }
        this._pools[robin].update([id,this._eventId++,2,estimatedEntropy,t,data.length].concat(data));
      }
      break;
      
    case "string":
      if (estimatedEntropy === undefined) {
       /* English text has just over 1 bit per character of entropy.
        * But this might be HTML or something, and have far less
        * entropy than English...  Oh well, let's just say one bit.
        */
       estimatedEntropy = data.length;
      }
      this._pools[robin].update([id,this._eventId++,3,estimatedEntropy,t,data.length]);
      this._pools[robin].update(data);
      break;
      
    default:
      err=1;
    }
    if (err) {
      throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
    }
  
    /* record the new strength */
    this._poolEntropy[robin] += estimatedEntropy;
    this._poolStrength += estimatedEntropy;
  
    /* fire off events */
    if (oldReady === this._NOT_READY) {
      if (this.isReady() !== this._NOT_READY) {
        this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
      }
      this._fireEvent("progress", this.getProgress());
    }
  },
  
  /** Is the generator ready? */
  isReady: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ (paranoia !== undefined) ? paranoia : this._defaultParanoia ];
  
    if (this._strength && this._strength >= entropyRequired) {
      return (this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date()).valueOf() > this._nextReseed) ?
        this._REQUIRES_RESEED | this._READY :
        this._READY;
    } else {
      return (this._poolStrength >= entropyRequired) ?
        this._REQUIRES_RESEED | this._NOT_READY :
        this._NOT_READY;
    }
  },
  
  /** Get the generator's progress toward readiness, as a fraction */
  getProgress: function (paranoia) {
    var entropyRequired = this._PARANOIA_LEVELS[ paranoia ? paranoia : this._defaultParanoia ];
  
    if (this._strength >= entropyRequired) {
      return 1.0;
    } else {
      return (this._poolStrength > entropyRequired) ?
        1.0 :
        this._poolStrength / entropyRequired;
    }
  },
  
  /** start the built-in entropy collectors */
  startCollectors: function () {
    if (this._collectorsStarted) { return; }
  
    if (window.addEventListener) {
      window.addEventListener("load", this._loadTimeCollector, false);
      window.addEventListener("mousemove", this._mouseCollector, false);
    } else if (document.attachEvent) {
      document.attachEvent("onload", this._loadTimeCollector);
      document.attachEvent("onmousemove", this._mouseCollector);
    }
    else {
      throw new sjcl.exception.bug("can't attach event");
    }
  
    this._collectorsStarted = true;
  },
  
  /** stop the built-in entropy collectors */
  stopCollectors: function () {
    if (!this._collectorsStarted) { return; }
  
    if (window.removeEventListener) {
      window.removeEventListener("load", this._loadTimeCollector, false);
      window.removeEventListener("mousemove", this._mouseCollector, false);
    } else if (window.detachEvent) {
      window.detachEvent("onload", this._loadTimeCollector);
      window.detachEvent("onmousemove", this._mouseCollector);
    }
    this._collectorsStarted = false;
  },
  
  /* use a cookie to store entropy.
  useCookie: function (all_cookies) {
      throw new sjcl.exception.bug("random: useCookie is unimplemented");
  },*/
  
  /** add an event listener for progress or seeded-ness. */
  addEventListener: function (name, callback) {
    this._callbacks[name][this._callbackI++] = callback;
  },
  
  /** remove an event listener for progress or seeded-ness */
  removeEventListener: function (name, cb) {
    var i, j, cbs=this._callbacks[name], jsTemp=[];
  
    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */
  
    for (j in cbs) {
	if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
        jsTemp.push(j);
      }
    }
  
    for (i=0; i<jsTemp.length; i++) {
      j = jsTemp[i];
      delete cbs[j];
    }
  },
  
  /* private */
  _pools                   : [new sjcl.hash.sha256()],
  _poolEntropy             : [0],
  _reseedCount             : 0,
  _robins                  : {},
  _eventId                 : 0,
  
  _collectorIds            : {},
  _collectorIdNext         : 0,
  
  _strength                : 0,
  _poolStrength            : 0,
  _nextReseed              : 0,
  _key                     : [0,0,0,0,0,0,0,0],
  _counter                 : [0,0,0,0],
  _cipher                  : undefined,
  _defaultParanoia         : 6,
  
  /* event listener stuff */
  _collectorsStarted       : false,
  _callbacks               : {progress: {}, seeded: {}},
  _callbackI               : 0,
  
  /* constants */
  _NOT_READY               : 0,
  _READY                   : 1,
  _REQUIRES_RESEED         : 2,

  _MAX_WORDS_PER_BURST     : 65536,
  _PARANOIA_LEVELS         : [0,48,64,96,128,192,256,384,512,768,1024],
  _MILLISECONDS_PER_RESEED : 30000,
  _BITS_PER_RESEED         : 80,
  
  /** Generate 4 random words, no reseed, no gate.
   * @private
   */
  _gen4words: function () {
    for (var i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
    return this._cipher.encrypt(this._counter);
  },
  
  /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
   * @private
   */
  _gate: function () {
    this._key = this._gen4words().concat(this._gen4words());
    this._cipher = new sjcl.cipher.aes(this._key);
  },
  
  /** Reseed the generator with the given words
   * @private
   */
  _reseed: function (seedWords) {
    this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
    this._cipher = new sjcl.cipher.aes(this._key);
    for (var i=0; i<4; i++) {
      this._counter[i] = this._counter[i]+1 | 0;
      if (this._counter[i]) { break; }
    }
  },
  
  /** reseed the data from the entropy pools
   * @param full If set, use all the entropy pools in the reseed.
   */
  _reseedFromPools: function (full) {
    var reseedData = [], strength = 0, i;
  
    this._nextReseed = reseedData[0] =
      (new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;
    
    for (i=0; i<16; i++) {
      /* On some browsers, this is cryptographically random.  So we might
       * as well toss it in the pot and stir...
       */
      reseedData.push(Math.random()*0x100000000|0);
    }
    
    for (i=0; i<this._pools.length; i++) {
     reseedData = reseedData.concat(this._pools[i].finalize());
     strength += this._poolEntropy[i];
     this._poolEntropy[i] = 0;
   
     if (!full && (this._reseedCount & (1<<i))) { break; }
    }
  
    /* if we used the last pool, push a new one onto the stack */
    if (this._reseedCount >= 1 << this._pools.length) {
     this._pools.push(new sjcl.hash.sha256());
     this._poolEntropy.push(0);
    }
  
    /* how strong was this reseed? */
    this._poolStrength -= strength;
    if (strength > this._strength) {
      this._strength = strength;
    }
  
    this._reseedCount ++;
    this._reseed(reseedData);
  },
  
  _mouseCollector: function (ev) {
    var x = ev.x || ev.clientX || ev.offsetX || 0, y = ev.y || ev.clientY || ev.offsetY || 0;
    sjcl.random.addEntropy([x,y], 2, "mouse");
  },
  
  _loadTimeCollector: function (ev) {
    sjcl.random.addEntropy((new Date()).valueOf(), 2, "loadtime");
  },
  
  _fireEvent: function (name, arg) {
    var j, cbs=sjcl.random._callbacks[name], cbsTemp=[];
    /* TODO: there is a race condition between removing collectors and firing them */ 

    /* I'm not sure if this is necessary; in C++, iterating over a
     * collection and modifying it at the same time is a no-no.
     */
  
    for (j in cbs) {
     if (cbs.hasOwnProperty(j)) {
        cbsTemp.push(cbs[j]);
     }
    }
  
    for (j=0; j<cbsTemp.length; j++) {
     cbsTemp[j](arg);
    }
  }
};

(function(){
  try {
    // get cryptographically strong entropy in Webkit
    var ab = new Uint32Array(32);
    crypto.getRandomValues(ab);
    sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");
  } catch (e) {
    // no getRandomValues :-(
  }
})();

(function () {
  for (var key in sjcl.beware) {
    if (sjcl.beware.hasOwnProperty(key)) {
      sjcl.beware[key]();
    }
  }
})();

var Braintree = {
  sjcl: sjcl,
  version: "1.3.10"
};

Braintree.generateAesKey = function () {
  return {
    key: sjcl.random.randomWords(8, 0),
    encrypt: function (plainText) {
      return this.encryptWithIv(plainText, sjcl.random.randomWords(4, 0));
    },
    encryptWithIv: function (plaintext, iv) {
      var aes = new sjcl.cipher.aes(this.key),
          plaintextBits = sjcl.codec.utf8String.toBits(plaintext),
          ciphertextBits = sjcl.mode.cbc.encrypt(aes, plaintextBits, iv),
          ciphertextAndIvBits = sjcl.bitArray.concat(iv, ciphertextBits);

      return sjcl.codec.base64.fromBits(ciphertextAndIvBits);
    }
  };
};

Braintree.create = function (publicKey) {
  return new Braintree.EncryptionClient(publicKey);
};

Braintree.EncryptionClient = function (publicKey) {
  var self = this,
      hiddenFields = [];

  self.publicKey = publicKey;
  self.version = Braintree.version;

  var createElement = function (tagName, attrs) {
    var element, attr, value;

    element = document.createElement(tagName);

    for (attr in attrs) {
      if (attrs.hasOwnProperty(attr)) {
        value = attrs[attr];
        element.setAttribute(attr, value);
      }
    }

    return element;
  };

  var extractForm = function (object) {
    if (window.jQuery && object instanceof jQuery) {
      return object[0];
    } else if (object.nodeType && object.nodeType === 1) {
      return object;
    } else {
      return document.getElementById(object);
    }
  };

  var extractIntegers = function (asn1) {
    var parts = [],
        start, end, data,
        i;

    if (asn1.typeName() === "INTEGER") {
      start = asn1.posContent();
      end   = asn1.posEnd();
      data  = asn1.stream.hexDump(start, end).replace(/[ \n]/g, "");
      parts.push(data);
    }

    if (asn1.sub !== null) {
      for (i = 0; i < asn1.sub.length; i++) {
        parts = parts.concat(extractIntegers(asn1.sub[i]));
      }
    }

    return parts;
  };

  var findInputs = function (element) {
    var found = [],
        children = element.children,
        child, i;

    for (i = 0; i < children.length; i++) {
      child = children[i];

      if (child.nodeType === 1 && child.attributes["data-encrypted-name"]) {
        found.push(child);
      } else if (child.children && child.children.length > 0) {
        found = found.concat(findInputs(child));
      }
    }

    return found;
  };

  var generateRsaKey = function () {
    var asn1, exponent, parts, modulus, rawKey, rsa;

    try {
      rawKey = b64toBA(publicKey);
      asn1 = ASN1.decode(rawKey);
    } catch (e) {
      throw "Invalid encryption key. Please use the key labeled 'Client-Side Encryption Key'";
    }

    parts = extractIntegers(asn1);

    if (parts.length !== 2) {
      throw "Invalid encryption key. Please use the key labeled 'Client-Side Encryption Key'";
    }

    modulus = parts[0];
    exponent = parts[1];

    rsa = new RSAKey();
    rsa.setPublic(modulus, exponent);

    return rsa;
  };

  var generateHmacKey = function () {
    return {
      key: sjcl.random.randomWords(8, 0),
      sign: function (message) {
        var hmac = new sjcl.misc.hmac(this.key, sjcl.hash.sha256),
            signature = hmac.encrypt(message);

        return sjcl.codec.base64.fromBits(signature);
      }
    };
  };

  self.encrypt = function (plaintext) {
    var rsa = generateRsaKey(),
        aes = Braintree.generateAesKey(),
        hmac = generateHmacKey(),
        ciphertext = aes.encrypt(plaintext),
        signature = hmac.sign(sjcl.codec.base64.toBits(ciphertext)),
        combinedKey = sjcl.bitArray.concat(aes.key, hmac.key),
        encodedKey = sjcl.codec.base64.fromBits(combinedKey),
        hexEncryptedKey = rsa.encrypt(encodedKey),
        prefix = "$bt4|javascript_" + self.version.replace(/\./g, "_") + "$",
        encryptedKey = null;

    if(hexEncryptedKey) {
      encryptedKey = hex2b64(hexEncryptedKey);
    }

    return prefix + encryptedKey + "$" + ciphertext + "$" + signature;
  };

  self.encryptForm = function (form) {
    var element, encryptedValue,
        fieldName, hiddenField,
        i, inputs;

    form = extractForm(form);
    inputs = findInputs(form);

    while (hiddenFields.length > 0) {
      try {
        form.removeChild(hiddenFields[0]);
      } catch (err) {}
      hiddenFields.splice(0, 1);
    }

    for (i = 0; i < inputs.length; i++) {
      element = inputs[i];
      fieldName = element.getAttribute("data-encrypted-name");
      encryptedValue = self.encrypt(element.value);
      element.removeAttribute("name");
      hiddenField = createElement("input", {
        value: encryptedValue,
        type: "hidden",
        name: fieldName
      });
      hiddenFields.push(hiddenField);
      form.appendChild(hiddenField);
    }
  };

  self.onSubmitEncryptForm = function (form, callback) {
    var wrappedCallback;

    form = extractForm(form);

    wrappedCallback = function (e) {
      self.encryptForm(form);
      return (!!callback) ? callback(e) : e;
    };

    if (window.jQuery) {
      window.jQuery(form).submit(wrappedCallback);
    } else if (form.addEventListener) {
      form.addEventListener("submit", wrappedCallback, false);
    } else if (form.attachEvent) {
      form.attachEvent("onsubmit", wrappedCallback);
    }
  };

  // backwards compatibility
  self.formEncrypter = {
    encryptForm: self.encryptForm,
    extractForm: extractForm,
    onSubmitEncryptForm: self.onSubmitEncryptForm
  };

  sjcl.random.startCollectors();
};

window.Braintree = Braintree;

})();

!function(e){if("object"==typeof exports&&"undefined"!=typeof module)module.exports=e();else if("function"==typeof define&&define.amd)define([],e);else{var f;"undefined"!=typeof window?f=window:"undefined"!=typeof global?f=global:"undefined"!=typeof self&&(f=self),f.braintree=e()}}(function(){var define,module,exports;return (function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
'use strict';

require('./src/rpc-dispatcher')();

module.exports = require('./src/setup.js');

},{"./src/rpc-dispatcher":209,"./src/setup.js":210}],2:[function(require,module,exports){
'use strict';

function normalizeElement (element, errorMessage) {
  errorMessage = errorMessage || '[' + element + '] is not a valid DOM Element';

  if (element && element.nodeType && element.nodeType === 1) {
    return element;
  }
  if (element && window.jQuery && (element instanceof jQuery || 'jquery' in Object(element)) && element.length !== 0) {
    return element[0];
  }

  if (typeof element === 'string' && document.getElementById(element)) {
    return document.getElementById(element);
  }

  throw new Error(errorMessage);
}

module.exports = {
  normalizeElement: normalizeElement
};

},{}],3:[function(require,module,exports){
'use strict';

function addEventListener(element, type, listener, useCapture) {
  if (element.addEventListener) {
    element.addEventListener(type, listener, useCapture);
  } else if (element.attachEvent) {
    element.attachEvent('on' + type, listener);
  }
}

function removeEventListener(element, type, listener, useCapture) {
  if (element.removeEventListener) {
    element.removeEventListener(type, listener, useCapture);
  } else if (element.detachEvent) {
    element.detachEvent('on' + type, listener);
  }
}

module.exports = {
  addEventListener: addEventListener,
  removeEventListener: removeEventListener
};

},{}],4:[function(require,module,exports){
'use strict';

var toString = Object.prototype.toString;

function isFunction(func) {
  return toString.call(func) === '[object Function]';
}

function bind(func, context) {
  return function () {
    func.apply(context, arguments);
  };
}

module.exports = {
  bind: bind,
  isFunction: isFunction
};

},{}],5:[function(require,module,exports){
'use strict';

function isBrowserHttps() {
  return window.location.protocol === 'https:';
}

function encode(str) {
  switch (str) {
    case null:
    case undefined:
      return '';
    case true:
      return '1';
    case false:
      return '0';
    default:
      return encodeURIComponent(str);
  }
}

function makeQueryString(params, namespace) {
  var query = [], k, p;
  for (p in params) {
    if (params.hasOwnProperty(p)) {
      var v = params[p];
      if (namespace) {
        k = namespace + '[' + p + ']';
      } else {
        k = p;
      }
      if (typeof v === 'object') {
        query.push(makeQueryString(v, k));
      } else if (v !== undefined && v !== null) {
        query.push(encode(k) + '=' + encode(v));
      }
    }
  }
  return query.join('&');
}

function decodeQueryString(queryString) {
  var params = {},
  paramPairs = queryString.split('&');

  for (var i = 0; i < paramPairs.length; i++) {
    var paramPair = paramPairs[i].split('=');
    var key = paramPair[0];
    var value = decodeURIComponent(paramPair[1]);
    params[key] = value;
  }

  return params;
}

function getParams(url) {
  var urlSegments = url.split('?');

  if (urlSegments.length !== 2) {
    return {};
  }

  return decodeQueryString(urlSegments[1]);
}

module.exports = {
  isBrowserHttps: isBrowserHttps,
  makeQueryString: makeQueryString,
  decodeQueryString: decodeQueryString,
  getParams: getParams
};

},{}],6:[function(require,module,exports){
var dom = require('./lib/dom');
var url = require('./lib/url');
var fn = require('./lib/fn');
var events = require('./lib/events');

module.exports = {
  normalizeElement: dom.normalizeElement,
  isBrowserHttps: url.isBrowserHttps,
  makeQueryString: url.makeQueryString,
  decodeQueryString: url.decodeQueryString,
  getParams: url.getParams,
  removeEventListener: events.removeEventListener,
  addEventListener: events.addEventListener,
  bind: fn.bind,
  isFunction: fn.isFunction
};

},{"./lib/dom":2,"./lib/events":3,"./lib/fn":4,"./lib/url":5}],7:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');
var Receiver = require('../shared/receiver');
var version = "1.0.0";

var htmlNode, bodyNode;

function getElementStyle(element, style) {
  var computedStyle = window.getComputedStyle ? getComputedStyle(element) : element.currentStyle;

  return computedStyle[style];
}

function getMerchantPageDefaultStyles() {
  return {
    html: {
      height: htmlNode.style.height || '',
      overflow: getElementStyle(htmlNode, 'overflow'),
      position: getElementStyle(htmlNode, 'position')
    },
    body: {
      height: bodyNode.style.height || '',
      overflow: getElementStyle(bodyNode, 'overflow')
    }
  };
}

function AuthenticationService (assetsUrl, container) {
  this.assetsUrl = assetsUrl;
  this.container = container || document.body;
  this.iframe = null;

  htmlNode = document.documentElement;
  bodyNode = document.body;
  this.merchantPageDefaultStyles = getMerchantPageDefaultStyles();
}

AuthenticationService.prototype.get = function (response, callback) {
  var self = this,
  url = this.constructAuthorizationURL(response);

  if (this.container && utils.isFunction(this.container)) {
    this.container(url + '&no_style=1');
  } else {
    this.insertIframe(url);
  }

  new Receiver(function (response) {
    if (!utils.isFunction(self.container)) {
      self.removeIframe();
    }
    callback(response);
  });
};

AuthenticationService.prototype.removeIframe = function () {
  if (this.container && this.container.nodeType && this.container.nodeType === 1) {
    this.container.removeChild(this.iframe);
  } else if (this.container && window.jQuery && this.container instanceof jQuery) {
    $(this.iframe, this.container).remove();
  } else if (typeof this.container === 'string') {
    document.getElementById(this.container).removeChild(this.iframe);
  }

  this.unlockMerchantWindowSize();
};

AuthenticationService.prototype.insertIframe = function (url) {
  // TODO: Security - This takes a url and makes an iframe. Doesn't seem like this would be a problem.
  var iframe = document.createElement('iframe');
  iframe.src = url;
  this.applyStyles(iframe);
  this.lockMerchantWindowSize();

  if (this.container && this.container.nodeType && this.container.nodeType === 1) {
    this.container.appendChild(iframe);
  } else if (this.container && window.jQuery && this.container instanceof jQuery && this.container.length !== 0) {
    this.container.append(iframe);
  } else if (typeof this.container === 'string' && document.getElementById(this.container)) {
    document.getElementById(this.container).appendChild(iframe);
  } else {
    throw new Error('Unable to find valid container for iframe.');
  }
  this.iframe = iframe;
};

AuthenticationService.prototype.applyStyles = function (iframe) {
  iframe.style.position = 'fixed';
  iframe.style.top = '0';
  iframe.style.left = '0';
  iframe.style.height = '100%';
  iframe.style.width = '100%';
  iframe.setAttribute('frameborder', '0');
  iframe.setAttribute('allowTransparency', 'true');
  iframe.style.border = '0';
  iframe.style.zIndex = '99999';
};

AuthenticationService.prototype.lockMerchantWindowSize = function () {
  htmlNode.style.overflow = 'hidden';
  bodyNode.style.overflow = 'hidden';
  bodyNode.style.height = '100%';
};

AuthenticationService.prototype.unlockMerchantWindowSize = function () {
  var defaultStyles = this.merchantPageDefaultStyles;

  bodyNode.style.height = defaultStyles.body.height;
  bodyNode.style.overflow = defaultStyles.body.overflow;

  htmlNode.style.overflow = defaultStyles.html.overflow;
};

AuthenticationService.prototype.constructAuthorizationURL = function (response) {
  var queryString,
  parentURL = window.location.href;

  if (parentURL.indexOf('#') > -1) {
    parentURL = parentURL.split('#')[0];
  }

  queryString = utils.makeQueryString({
    acsUrl: response.acsUrl,
    pareq: response.pareq,
    termUrl: response.termUrl + '&three_d_secure_version=' + version,
    md: response.md,
    parentUrl: parentURL
  });
  return this.assetsUrl + '/3ds/' + version + '/html/style_frame?' + queryString;
};

module.exports = AuthenticationService;

},{"../shared/receiver":11,"braintree-utilities":6}],8:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');
var AuthenticationService = require('./authorization_service');

function Client(api, options) {
  options = options || {};
  this.clientToken = options.clientToken;
  this.container = options.container;
  this.api = api;
  this.nonce = null;
}

Client.prototype.verify = function (data, callback) {
  if (!utils.isFunction(callback)) {
    throw new Error('No suitable callback argument was given');
  }

  var dataRecord = {nonce: '', amount: data.amount};
  var creditCardMetaData = data.creditCard;

  if (typeof creditCardMetaData === 'string') {
    dataRecord.nonce = creditCardMetaData;
    this.startVerification(dataRecord, callback);
  } else {
    var self = this;
    var boundHandleTokenizeCard = function (err, nonce) {
      if (err) {
        return callback(err);
      }
      dataRecord.nonce = nonce;
      self.startVerification(dataRecord, callback);
    };
    this.api.tokenizeCard(creditCardMetaData, boundHandleTokenizeCard);
  }
};

Client.prototype.startVerification = function (data, merchantCallback) {
  this.api.lookup3DS(data, utils.bind(this.handleLookupResponse(merchantCallback), this));
};

Client.prototype.handleLookupResponse = function (merchantCallback) {
  var self = this;
  return function (errorResponse, lookupResponse) {
    var authenticationService;
    if (errorResponse) {
      merchantCallback(errorResponse.error);
    } else if (lookupResponse.lookup && lookupResponse.lookup.acsUrl && lookupResponse.lookup.acsUrl.length > 0) {
      self.nonce = lookupResponse.paymentMethod.nonce;
      authenticationService = new AuthenticationService(this.clientToken.assetsUrl, this.container);
      authenticationService.get(lookupResponse.lookup, utils.bind(this.handleAuthenticationResponse(merchantCallback), this));
    } else {
      self.nonce = lookupResponse.paymentMethod.nonce;
      merchantCallback(null, {
        nonce: self.nonce,
        verificationDetails: lookupResponse.threeDSecureInfo
      });
    }
  };
};

Client.prototype.handleAuthenticationResponse = function (merchantCallback) {
  return function (authResponseQueryString) {
    var authResponse,
        queryParams = utils.decodeQueryString(authResponseQueryString);

    if (queryParams.user_closed) {
      return;
    }

    authResponse = JSON.parse(queryParams.auth_response);

    if (authResponse.success) {
      merchantCallback(null, {
        nonce: authResponse.paymentMethod.nonce,
        verificationDetails: authResponse.threeDSecureInfo
      });
    } else if (authResponse.threeDSecureInfo && authResponse.threeDSecureInfo.liabilityShiftPossible) {
      merchantCallback(null, {
        nonce: this.nonce,
        verificationDetails: authResponse.threeDSecureInfo
      });
    } else {
      merchantCallback(authResponse.error);
    }
  };
};

module.exports = Client;

},{"./authorization_service":7,"braintree-utilities":6}],9:[function(require,module,exports){
'use strict';

var Client = require('./client');
require('./vendor/json2');

module.exports = {
  create: function (clientToken, options) {
    var client = new Client(clientToken, options);
    return client;
  }
};

},{"./client":8,"./vendor/json2":10}],10:[function(require,module,exports){
/*
    json2.js
    2013-05-26

    Public Domain.

    NO WARRANTY EXPRESSED OR IMPLIED. USE AT YOUR OWN RISK.

    See http://www.JSON.org/js.html


    This code should be minified before deployment.
    See http://javascript.crockford.com/jsmin.html

    USE YOUR OWN COPY. IT IS EXTREMELY UNWISE TO LOAD CODE FROM SERVERS YOU DO
    NOT CONTROL.


    This file creates a global JSON object containing two methods: stringify
    and parse.

        JSON.stringify(value, replacer, space)
            value       any JavaScript value, usually an object or array.

            replacer    an optional parameter that determines how object
                        values are stringified for objects. It can be a
                        function or an array of strings.

            space       an optional parameter that specifies the indentation
                        of nested structures. If it is omitted, the text will
                        be packed without extra whitespace. If it is a number,
                        it will specify the number of spaces to indent at each
                        level. If it is a string (such as '\t' or '&nbsp;'),
                        it contains the characters used to indent at each level.

            This method produces a JSON text from a JavaScript value.

            When an object value is found, if the object contains a toJSON
            method, its toJSON method will be called and the result will be
            stringified. A toJSON method does not serialize: it returns the
            value represented by the name/value pair that should be serialized,
            or undefined if nothing should be serialized. The toJSON method
            will be passed the key associated with the value, and this will be
            bound to the value

            For example, this would serialize Dates as ISO strings.

                Date.prototype.toJSON = function (key) {
                    function f(n) {
                        // Format integers to have at least two digits.
                        return n < 10 ? '0' + n : n;
                    }

                    return this.getUTCFullYear()   + '-' +
                         f(this.getUTCMonth() + 1) + '-' +
                         f(this.getUTCDate())      + 'T' +
                         f(this.getUTCHours())     + ':' +
                         f(this.getUTCMinutes())   + ':' +
                         f(this.getUTCSeconds())   + 'Z';
                };

            You can provide an optional replacer method. It will be passed the
            key and value of each member, with this bound to the containing
            object. The value that is returned from your method will be
            serialized. If your method returns undefined, then the member will
            be excluded from the serialization.

            If the replacer parameter is an array of strings, then it will be
            used to select the members to be serialized. It filters the results
            such that only members with keys listed in the replacer array are
            stringified.

            Values that do not have JSON representations, such as undefined or
            functions, will not be serialized. Such values in objects will be
            dropped; in arrays they will be replaced with null. You can use
            a replacer function to replace those with JSON values.
            JSON.stringify(undefined) returns undefined.

            The optional space parameter produces a stringification of the
            value that is filled with line breaks and indentation to make it
            easier to read.

            If the space parameter is a non-empty string, then that string will
            be used for indentation. If the space parameter is a number, then
            the indentation will be that many spaces.

            Example:

            text = JSON.stringify(['e', {pluribus: 'unum'}]);
            // text is '["e",{"pluribus":"unum"}]'


            text = JSON.stringify(['e', {pluribus: 'unum'}], null, '\t');
            // text is '[\n\t"e",\n\t{\n\t\t"pluribus": "unum"\n\t}\n]'

            text = JSON.stringify([new Date()], function (key, value) {
                return this[key] instanceof Date ?
                    'Date(' + this[key] + ')' : value;
            });
            // text is '["Date(---current time---)"]'


        JSON.parse(text, reviver)
            This method parses a JSON text to produce an object or array.
            It can throw a SyntaxError exception.

            The optional reviver parameter is a function that can filter and
            transform the results. It receives each of the keys and values,
            and its return value is used instead of the original value.
            If it returns what it received, then the structure is not modified.
            If it returns undefined then the member is deleted.

            Example:

            // Parse the text. Values that look like ISO date strings will
            // be converted to Date objects.

            myData = JSON.parse(text, function (key, value) {
                var a;
                if (typeof value === 'string') {
                    a =
/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2}(?:\.\d*)?)Z$/.exec(value);
                    if (a) {
                        return new Date(Date.UTC(+a[1], +a[2] - 1, +a[3], +a[4],
                            +a[5], +a[6]));
                    }
                }
                return value;
            });

            myData = JSON.parse('["Date(09/09/2001)"]', function (key, value) {
                var d;
                if (typeof value === 'string' &&
                        value.slice(0, 5) === 'Date(' &&
                        value.slice(-1) === ')') {
                    d = new Date(value.slice(5, -1));
                    if (d) {
                        return d;
                    }
                }
                return value;
            });


    This is a reference implementation. You are free to copy, modify, or
    redistribute.
*/

/*jslint evil: true, regexp: true */

/*members "", "\b", "\t", "\n", "\f", "\r", "\"", JSON, "\\", apply,
    call, charCodeAt, getUTCDate, getUTCFullYear, getUTCHours,
    getUTCMinutes, getUTCMonth, getUTCSeconds, hasOwnProperty, join,
    lastIndex, length, parse, prototype, push, replace, slice, stringify,
    test, toJSON, toString, valueOf
*/


// Create a JSON object only if one does not already exist. We create the
// methods in a closure to avoid creating global variables.

if (typeof JSON !== 'object') {
    JSON = {};
}

(function () {
    'use strict';

    function f(n) {
        // Format integers to have at least two digits.
        return n < 10 ? '0' + n : n;
    }

    if (typeof Date.prototype.toJSON !== 'function') {

        Date.prototype.toJSON = function () {

            return isFinite(this.valueOf())
                ? this.getUTCFullYear()     + '-' +
                    f(this.getUTCMonth() + 1) + '-' +
                    f(this.getUTCDate())      + 'T' +
                    f(this.getUTCHours())     + ':' +
                    f(this.getUTCMinutes())   + ':' +
                    f(this.getUTCSeconds())   + 'Z'
                : null;
        };

        String.prototype.toJSON      =
            Number.prototype.toJSON  =
            Boolean.prototype.toJSON = function () {
                return this.valueOf();
            };
    }

    var cx = /[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
        escapable = /[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,
        gap,
        indent,
        meta = {    // table of character substitutions
            '\b': '\\b',
            '\t': '\\t',
            '\n': '\\n',
            '\f': '\\f',
            '\r': '\\r',
            '"' : '\\"',
            '\\': '\\\\'
        },
        rep;


    function quote(string) {

// If the string contains no control characters, no quote characters, and no
// backslash characters, then we can safely slap some quotes around it.
// Otherwise we must also replace the offending characters with safe escape
// sequences.

        escapable.lastIndex = 0;
        return escapable.test(string) ? '"' + string.replace(escapable, function (a) {
            var c = meta[a];
            return typeof c === 'string'
                ? c
                : '\\u' + ('0000' + a.charCodeAt(0).toString(16)).slice(-4);
        }) + '"' : '"' + string + '"';
    }


    function str(key, holder) {

// Produce a string from holder[key].

        var i,          // The loop counter.
            k,          // The member key.
            v,          // The member value.
            length,
            mind = gap,
            partial,
            value = holder[key];

// If the value has a toJSON method, call it to obtain a replacement value.

        if (value && typeof value === 'object' &&
                typeof value.toJSON === 'function') {
            value = value.toJSON(key);
        }

// If we were called with a replacer function, then call the replacer to
// obtain a replacement value.

        if (typeof rep === 'function') {
            value = rep.call(holder, key, value);
        }

// What happens next depends on the value's type.

        switch (typeof value) {
        case 'string':
            return quote(value);

        case 'number':

// JSON numbers must be finite. Encode non-finite numbers as null.

            return isFinite(value) ? String(value) : 'null';

        case 'boolean':
        case 'null':

// If the value is a boolean or null, convert it to a string. Note:
// typeof null does not produce 'null'. The case is included here in
// the remote chance that this gets fixed someday.

            return String(value);

// If the type is 'object', we might be dealing with an object or an array or
// null.

        case 'object':

// Due to a specification blunder in ECMAScript, typeof null is 'object',
// so watch out for that case.

            if (!value) {
                return 'null';
            }

// Make an array to hold the partial results of stringifying this object value.

            gap += indent;
            partial = [];

// Is the value an array?

            if (Object.prototype.toString.apply(value) === '[object Array]') {

// The value is an array. Stringify every element. Use null as a placeholder
// for non-JSON values.

                length = value.length;
                for (i = 0; i < length; i += 1) {
                    partial[i] = str(i, value) || 'null';
                }

// Join all of the elements together, separated with commas, and wrap them in
// brackets.

                v = partial.length === 0
                    ? '[]'
                    : gap
                    ? '[\n' + gap + partial.join(',\n' + gap) + '\n' + mind + ']'
                    : '[' + partial.join(',') + ']';
                gap = mind;
                return v;
            }

// If the replacer is an array, use it to select the members to be stringified.

            if (rep && typeof rep === 'object') {
                length = rep.length;
                for (i = 0; i < length; i += 1) {
                    if (typeof rep[i] === 'string') {
                        k = rep[i];
                        v = str(k, value);
                        if (v) {
                            partial.push(quote(k) + (gap ? ': ' : ':') + v);
                        }
                    }
                }
            } else {

// Otherwise, iterate through all of the keys in the object.

                for (k in value) {
                    if (Object.prototype.hasOwnProperty.call(value, k)) {
                        v = str(k, value);
                        if (v) {
                            partial.push(quote(k) + (gap ? ': ' : ':') + v);
                        }
                    }
                }
            }

// Join all of the member texts together, separated with commas,
// and wrap them in braces.

            v = partial.length === 0
                ? '{}'
                : gap
                ? '{\n' + gap + partial.join(',\n' + gap) + '\n' + mind + '}'
                : '{' + partial.join(',') + '}';
            gap = mind;
            return v;
        }
    }

// If the JSON object does not yet have a stringify method, give it one.

    if (typeof JSON.stringify !== 'function') {
        JSON.stringify = function (value, replacer, space) {

// The stringify method takes a value and an optional replacer, and an optional
// space parameter, and returns a JSON text. The replacer can be a function
// that can replace values, or an array of strings that will select the keys.
// A default replacer method can be provided. Use of the space parameter can
// produce text that is more easily readable.

            var i;
            gap = '';
            indent = '';

// If the space parameter is a number, make an indent string containing that
// many spaces.

            if (typeof space === 'number') {
                for (i = 0; i < space; i += 1) {
                    indent += ' ';
                }

// If the space parameter is a string, it will be used as the indent string.

            } else if (typeof space === 'string') {
                indent = space;
            }

// If there is a replacer, it must be a function or an array.
// Otherwise, throw an error.

            rep = replacer;
            if (replacer && typeof replacer !== 'function' &&
                    (typeof replacer !== 'object' ||
                    typeof replacer.length !== 'number')) {
                throw new Error('JSON.stringify');
            }

// Make a fake root object containing our value under the key of ''.
// Return the result of stringifying the value.

            return str('', {'': value});
        };
    }


// If the JSON object does not yet have a parse method, give it one.

    if (typeof JSON.parse !== 'function') {
        JSON.parse = function (text, reviver) {

// The parse method takes a text and an optional reviver function, and returns
// a JavaScript value if the text is a valid JSON text.

            var j;

            function walk(holder, key) {

// The walk method is used to recursively walk the resulting structure so
// that modifications can be made.

                var k, v, value = holder[key];
                if (value && typeof value === 'object') {
                    for (k in value) {
                        if (Object.prototype.hasOwnProperty.call(value, k)) {
                            v = walk(value, k);
                            if (v !== undefined) {
                                value[k] = v;
                            } else {
                                delete value[k];
                            }
                        }
                    }
                }
                return reviver.call(holder, key, value);
            }


// Parsing happens in four stages. In the first stage, we replace certain
// Unicode characters with escape sequences. JavaScript handles many characters
// incorrectly, either silently deleting them, or treating them as line endings.

            text = String(text);
            cx.lastIndex = 0;
            if (cx.test(text)) {
                text = text.replace(cx, function (a) {
                    return '\\u' +
                        ('0000' + a.charCodeAt(0).toString(16)).slice(-4);
                });
            }

// In the second stage, we run the text against regular expressions that look
// for non-JSON patterns. We are especially concerned with '()' and 'new'
// because they can cause invocation, and '=' because it can cause mutation.
// But just to be safe, we want to reject all unexpected forms.

// We split the second stage into 4 regexp operations in order to work around
// crippling inefficiencies in IE's and Safari's regexp engines. First we
// replace the JSON backslash pairs with '@' (a non-JSON character). Second, we
// replace all simple value tokens with ']' characters. Third, we delete all
// open brackets that follow a colon or comma or that begin the text. Finally,
// we look to see that the remaining characters are only whitespace or ']' or
// ',' or ':' or '{' or '}'. If that is so, then the text is safe for eval.

            if (/^[\],:{}\s]*$/
                    .test(text.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, '@')
                        .replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g, ']')
                        .replace(/(?:^|:|,)(?:\s*\[)+/g, ''))) {

// In the third stage we use the eval function to compile the text into a
// JavaScript structure. The '{' operator is subject to a syntactic ambiguity
// in JavaScript: it can begin a block or an object literal. We wrap the text
// in parens to eliminate the ambiguity.

                j = eval('(' + text + ')');

// In the optional fourth stage, we recursively walk the new structure, passing
// each name/value pair to a reviver function for possible transformation.

                return typeof reviver === 'function'
                    ? walk({'': j}, '')
                    : j;
            }

// If the text is not JSON parseable, then a SyntaxError is thrown.

            throw new SyntaxError('JSON.parse');
        };
    }
}());

},{}],11:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function Receiver (callback) {
  this.postMessageReceiver(callback);
  this.hashChangeReceiver(callback);
}

Receiver.prototype.postMessageReceiver = function (callback) {
  var self = this;

  this.wrappedCallback = function (event) {
    // TODO: Security - We should probably check event.origin in order to only act on our own events.
    callback(event.data);
    self.stopListening();
  };

  utils.addEventListener(window, 'message', this.wrappedCallback);
};

Receiver.prototype.hashChangeReceiver = function (callback) {
  var hash,
      originalHash = window.location.hash,
      self = this;

  this.poll = setInterval(function () {
    hash = window.location.hash;

    if (hash.length > 0 && (hash !== originalHash)) {
      self.stopListening();

      hash = hash.substring(1, hash.length);
      callback(hash);

      if (originalHash.length > 0) {
        window.location.hash = originalHash;
      } else {
        window.location.hash = '';
      }
    }
  }, 10);
};

Receiver.prototype.stopListening = function () {
  clearTimeout(this.poll);

  utils.removeEventListener(window, 'message', this.wrappedCallback);
};

module.exports = Receiver;

},{"braintree-utilities":6}],12:[function(require,module,exports){
(function (global){
'use strict';

var braintreeUtils = require('braintree-utilities');
var braintree3ds = require('braintree-3ds');
var parseClientToken = require('./parse-client-token');
var JSONPDriver = require('./jsonp-driver');
var util = require('./util');
var SEPAMandate = require('./sepa-mandate');
var SEPABankAccount = require('./sepa-bank-account');
var CreditCard = require('./credit-card');
var CoinbaseAccount = require('./coinbase-account');
var rootData = require('./root-data');
var normalizeCreditCardFields = require('./normalize-api-fields').normalizeCreditCardFields;

function deserialize(response, mapper) {
  if (response.status >= 400) {
    return [response, null];
  } else {
    return [null, mapper(response)];
  }
}

function Client(options) {
  var parsedClientToken;

  this.attrs = {};

  if (options.hasOwnProperty('sharedCustomerIdentifier')) {
    this.attrs.sharedCustomerIdentifier = options.sharedCustomerIdentifier;
  }

  parsedClientToken = parseClientToken(options.clientToken);

  this.driver = options.driver || JSONPDriver;
  this.authUrl = parsedClientToken.authUrl;
  this.analyticsUrl = parsedClientToken.analytics ? parsedClientToken.analytics.url : undefined;
  this.clientApiUrl = parsedClientToken.clientApiUrl;
  this.customerId = options.customerId;
  this.challenges = parsedClientToken.challenges;
  this.integration = options.integration || '';

  if (parsedClientToken.threeDSecureEnabled) {
    var secure3d = braintree3ds.create(this, {
      container: options.container,
      clientToken: parsedClientToken
    });
    this.verify3DS = braintreeUtils.bind(secure3d.verify, secure3d);
  }

  this.attrs.authorizationFingerprint = parsedClientToken.authorizationFingerprint;
  this.attrs.sharedCustomerIdentifierType = options.sharedCustomerIdentifierType;

  if (parsedClientToken.merchantAccountId) {
    this.attrs.merchantAccountId = parsedClientToken.merchantAccountId;
  }

  this.timeoutWatchers = [];
  if (options.hasOwnProperty('timeout')) {
    this.requestTimeout = options.timeout;
  } else {
    this.requestTimeout = 60000;
  }
}

function noop () {}

function mergeOptions(obj1, obj2) {
  var obj3 = {};
  var attrname;
  for (attrname in obj1) {
    if (obj1.hasOwnProperty(attrname)) {
      obj3[attrname] = obj1[attrname];
    }
  }
  for (attrname in obj2) {
    if (obj2.hasOwnProperty(attrname)) {
      obj3[attrname] = obj2[attrname];
    }
  }
  return obj3;
}

Client.prototype.requestWithTimeout = function (url, attrs, deserializer, method, callback) {
  callback = callback || noop;

  var uniqueName, version;
  var client = this;

  rootData.get(function (payload) {
    version = 'braintree/web/' + payload.sdkVersion;

    attrs.braintreeLibraryVersion = version;

    if (attrs.hasOwnProperty('analytics') && attrs.hasOwnProperty('_meta')) {
      attrs._meta.sdkVersion = version;
      attrs._meta.merchantAppId = payload.merchantAppId;
    }

    uniqueName = method(url, attrs, function (data, uniqueName) {
      if (client.timeoutWatchers[uniqueName]) {
        clearTimeout(client.timeoutWatchers[uniqueName]);
        var args = deserialize(data, function (d) { return deserializer(d);});
        callback.apply(null, args);
      }
    });

    if (client.requestTimeout > 0) {
      this.timeoutWatchers[uniqueName] = setTimeout(function () {
        client.timeoutWatchers[uniqueName] = null;
        callback.apply(null, [{'errors': 'Unknown error'}, null]);
      }, client.requestTimeout);
    } else {
      callback.apply(null, [{'errors': 'Unknown error'}, null]);
    }
  }, this);
};

Client.prototype.post = function (url, attrs, deserializer, callback) {
  this.requestWithTimeout(url, attrs, deserializer, this.driver.post, callback);
};

Client.prototype.get = function (url, attrs, deserializer, callback) {
  this.requestWithTimeout(url, attrs, deserializer, this.driver.get, callback);
};

Client.prototype.put = function (url, attrs, deserializer, callback) {
  this.requestWithTimeout(url, attrs, deserializer, this.driver.put, callback);
};

Client.prototype.getCreditCards = function (callback) {
  this.get(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods']),
    this.attrs,
    function (d) {
      var i = 0;
      var len = d.paymentMethods.length;
      var creditCards = [];

      for (i; i < len; i++) {
        creditCards.push(new CreditCard(d.paymentMethods[i]));
      }

      return creditCards;
    },
    callback
  );
};

Client.prototype.tokenizeCoinbase = function (attrs, callback) {
  attrs.options = { validate: false };
  this.addCoinbase(attrs, function (err, result) {
    if (err) {
      callback(err, null);
    } else if (result && result.nonce) {
      callback(err, result);
    } else {
      callback('Unable to tokenize coinbase account.', null);
    }
  });
};

Client.prototype.tokenizeCard = function (attrs, callback) {
  attrs.options = { validate: false };
  this.addCreditCard(attrs, function (err, result) {
    if (result && result.nonce) {
      callback(err, result.nonce, {type: result.type});
    } else {
      callback('Unable to tokenize card.', null);
    }
  });
};

Client.prototype.lookup3DS = function (attrs, callback) {
  var url = util.joinUrlFragments([this.clientApiUrl, 'v1/payment_methods', attrs.nonce, 'three_d_secure/lookup']);
  var mergedAttrs = mergeOptions(this.attrs, {amount: attrs.amount});
  this.post(url, mergedAttrs, function (d) {
      return d;
    },
    callback
  );
};

Client.prototype.addSEPAMandate = function (attrs, callback) {
  var mergedAttrs = mergeOptions(this.attrs, {sepaMandate: attrs});
  this.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'sepa_mandates.json']),
    mergedAttrs,
    function (d) { return new SEPAMandate(d.sepaMandates[0]); },
    callback
  );
};

Client.prototype.acceptSEPAMandate = function (mandateReferenceNumber, callback) {
  this.put(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'sepa_mandates', mandateReferenceNumber, 'accept']),
    this.attrs,
    function (d) { return new SEPABankAccount(d.sepaBankAccounts[0]); },
    callback
  );
};

Client.prototype.getSEPAMandate = function (mandateIdentifier, callback) {
  var mergedAttrs;
  if (mandateIdentifier.paymentMethodToken) {
    mergedAttrs = mergeOptions(this.attrs, {paymentMethodToken: mandateIdentifier.paymentMethodToken});
  } else {
    mergedAttrs = this.attrs;
  }
  this.get(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'sepa_mandates', mandateIdentifier.mandateReferenceNumber || '']),
    mergedAttrs,
    function (d) { return new SEPAMandate(d.sepaMandates[0]); },
    callback
  );
};

Client.prototype.addCoinbase = function (attrs, callback) {
  var mergedAttrs;
  delete attrs.share;

  mergedAttrs = mergeOptions(this.attrs, {
    coinbaseAccount: attrs,
    _meta: {
      integration: this.integration || 'custom',
      source: 'coinbase'
    }
  });

  this.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods/coinbase_accounts']),
    mergedAttrs,
    function (d) {
      return new CoinbaseAccount(d.coinbaseAccounts[0]);
    },
    callback
  );
};

Client.prototype.addCreditCard = function (attrs, callback) {
  var mergedAttrs;
  var share = attrs.share;
  delete attrs.share;

  var creditCard = normalizeCreditCardFields(attrs);

  mergedAttrs = mergeOptions(this.attrs, {
    share: share,
    creditCard: creditCard,
    _meta: {
      integration: this.integration || 'custom',
      source: 'form'
    }
  });

  this.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods/credit_cards']),
    mergedAttrs,
    function (d) {
      return new CreditCard(d.creditCards[0]);
    },
    callback
  );
};

Client.prototype.unlockCreditCard = function (creditCard, params, callback) {
  var attrs = mergeOptions(this.attrs, {challengeResponses: params});
  this.put(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods/', creditCard.nonce]),
    attrs,
    function (d) { return new CreditCard(d.paymentMethods[0]); },
    callback
  );
};

Client.prototype.sendAnalyticsEvents = function (events, callback) {
  var attrs;
  var url = this.analyticsUrl;
  var eventObjects = [];
  events = util.isArray(events) ? events : [events];

  if (!url) {
    if (callback) {
      callback.apply(null, [null, {}]);
    }
    return;
  }

  for (var event in events) {
    if (events.hasOwnProperty(event)) {
      eventObjects.push({ kind: events[event] });
    }
  }

  attrs = mergeOptions(this.attrs, {
    analytics: eventObjects,
    _meta: {
      platform: 'web',
      platformVersion: global.navigator.userAgent,
      integrationType: this.integration
    }
  });

  this.post(url, attrs, function (d) { return d; }, callback);
};

module.exports = Client;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./coinbase-account":13,"./credit-card":14,"./jsonp-driver":15,"./normalize-api-fields":17,"./parse-client-token":18,"./root-data":20,"./sepa-bank-account":21,"./sepa-mandate":22,"./util":23,"braintree-3ds":9,"braintree-utilities":41}],13:[function(require,module,exports){
'use strict';

var ATTRIBUTES = [
  'nonce',
  'type',
  'description',
  'details'
];

function CoinbaseAccount(attributes) {
  for (var i = 0; i < ATTRIBUTES.length; i++) {
    var attribute = ATTRIBUTES[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = CoinbaseAccount;

},{}],14:[function(require,module,exports){
'use strict';

var ATTRIBUTES = [
  'billingAddress',
  'branding',
  'createdAt',
  'createdAtMerchant',
  'createdAtMerchantName',
  'details',
  'isLocked',
  'lastUsedAt',
  'lastUsedAtMerchant',
  'lastUsedAtMerchantName',
  'lastUsedByCurrentMerchant',
  'nonce',
  'securityQuestions',
  'type'
];

function CreditCard(attributes) {
  for (var i = 0; i < ATTRIBUTES.length; i++) {
    var attribute = ATTRIBUTES[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = CreditCard;

},{}],15:[function(require,module,exports){
'use strict';

var JSONP = require('./jsonp');

function get(path, params, callback) {
  return JSONP.get(path, params, callback);
}

function post(path, params, callback) {
  params._method = 'POST';
  return JSONP.get(path, params, callback);
}

function put(path, params, callback) {
  params._method = 'PUT';
  return JSONP.get(path, params, callback);
}

module.exports = {
  get: get,
  post: post,
  put: put
};

},{"./jsonp":16}],16:[function(require,module,exports){
(function (global){
'use strict';

var util = require('./util');

/*
* Lightweight JSONP fetcher
* Copyright 2010-2012 Erik Karlsson. All rights reserved.
* BSD licensed
*/
var head,
    window = global,
    config = {};

function load(url, pfnError) {
  var script = document.createElement('script'),
  done = false;
  script.src = url;
  script.async = true;

  var errorHandler = pfnError || config.error;
  if ( typeof errorHandler === 'function' ) {
    script.onerror = function (ex){
      errorHandler({url: url, event: ex});
    };
  }

  script.onload = script.onreadystatechange = function () {
    if ( !done && (!this.readyState || this.readyState === "loaded" || this.readyState === "complete") ) {
      done = true;
      script.onload = script.onreadystatechange = null;
      if ( script && script.parentNode ) {
        script.parentNode.removeChild( script );
      }
    }
  };

  if ( !head ) {
    head = document.getElementsByTagName('head')[0];
  }
  head.appendChild( script );
}

function encode(str) {
  return encodeURIComponent(str);
}

function stringify(params, namespace) {
  var query = [], k, v, p;
  for(var p in params) {
    if (!params.hasOwnProperty(p)) {
      continue;
    }

    v = params[p];
    if (namespace) {
      if (util.isArray(params)) {
        k = namespace + "[]";
      } else {
        k = namespace + "[" + p + "]";
      }
    } else {
      k = p;
    }
    if (typeof v == "object") {
      query.push(stringify(v, k));
    } else {
      query.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
    }
  }
  return query.join("&");
}

function jsonp(url, params, callback, callbackName) {
  var query = (url||'').indexOf('?') === -1 ? '?' : '&', key;

  callbackName = (callbackName||config['callbackName']||'callback');
  var uniqueName = callbackName + "_json" + util.generateUUID();

  query += stringify(params);

  window[ uniqueName ] = function (data){
    callback(data, uniqueName);
    try {
      delete window[ uniqueName ];
    } catch (e) {}
    window[ uniqueName ] = null;
  };

  load(url + query + '&' + callbackName + '=' + uniqueName);
  return uniqueName;
}

function setDefaults(obj){
  config = obj;
}

module.exports = {
  get: jsonp,
  init: setDefaults,
  stringify: stringify
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./util":23}],17:[function(require,module,exports){
'use strict';

function normalizeCreditCardFields(attrs) {
  var creditCard = {
    billingAddress: attrs.billingAddress || {}
  };

  for (var key in attrs) {
    if (!attrs.hasOwnProperty(key)) { continue; }

    switch (key.replace(/_/,'').toLowerCase()) {
      case 'postalcode':
      case 'countryname':
      case 'countrycodenumeric':
      case 'countrycodealpha2':
      case 'countrycodealpha3':
      case 'region':
      case 'extendedaddress':
      case 'locality':
      case 'firstname':
      case 'lastname':
      case 'company':
      case 'streetaddress':
        creditCard.billingAddress[key] = attrs[key];
        break;
      default:
        creditCard[key] = attrs[key];
    }
  }

  return creditCard;
}

module.exports = {
  normalizeCreditCardFields: normalizeCreditCardFields
};

},{}],18:[function(require,module,exports){
'use strict';

require('./polyfill');

function parseClientToken(rawClientToken) {
  var clientToken;

  if (!rawClientToken) {
    throw new Error('Braintree API Client Misconfigured: clientToken required.');
  }

  if (typeof rawClientToken === 'object' && rawClientToken !== null) {
    clientToken = rawClientToken;
  } else {
    try {
      rawClientToken = window.atob(rawClientToken);
    } catch (b64Error) {}

    try {
      clientToken = JSON.parse(rawClientToken);
    } catch (jsonError) {
      throw new Error('Braintree API Client Misconfigured: clientToken is invalid.');
    }
  }

  if (!clientToken.hasOwnProperty('authUrl') || !clientToken.hasOwnProperty('clientApiUrl')) {
    throw new Error('Braintree API Client Misconfigured: clientToken is invalid.');
  }
  return clientToken;
}

module.exports = parseClientToken;

},{"./polyfill":19}],19:[function(require,module,exports){
(function (global){
'use strict';

global.atob = global.atob || function (base64String) {
  var base64Matcher = new RegExp("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})([=]{1,2})?$");
  var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var result = "";

  if (!base64Matcher.test(base64String)) {
    throw new Error("Braintree API Client Misconfigured: clientToken is invalid.");
  }

  var i = 0;
  do {
    var b1 = characters.indexOf( base64String.charAt(i++) );
    var b2 = characters.indexOf( base64String.charAt(i++) );
    var b3 = characters.indexOf( base64String.charAt(i++) );
    var b4 = characters.indexOf( base64String.charAt(i++) );

    var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );
    var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );
    var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );

    result += String.fromCharCode(a) + (b?String.fromCharCode(b):"") + (c?String.fromCharCode(c):"");

  } while( i < base64String.length );

  return result;
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],20:[function(require,module,exports){
(function (global){
'use strict';

var rootData, timeout;
var rpc = require('braintree-rpc');
var bus = new rpc.MessageBus(window);
var rpcClient = new rpc.RPCClient(bus, window.parent);
var dispatched = false;
var queuedListeners = [];
var fallbackRootData = {
  sdkVersion: getFallbackVersion(),
  merchantAppId: global.location.href
};

function getFallbackVersion() {
  var globalBraintree = global.braintree;
  return (globalBraintree && globalBraintree.hasOwnProperty('VERSION')) ? globalBraintree.VERSION : undefined;
}

function get(callback, context) {
  if (rootData == null) {
    queuedListeners.push({
      callback: callback,
      context: context
    });

    if (dispatched === false) {
      timeout = setTimeout(function () {
        resolve(fallbackRootData);
      }, 200);
      rpcClient.invoke('getExternalData', [], resolve);
      dispatched = true;
    }
  } else {
    callback.call(context, rootData);
  }
}

function resolve(payload) {
  clearTimeout(timeout);

  rootData = {
    sdkVersion: payload.sdkVersion,
    merchantAppId: payload.merchantAppId
  };

  for (var i = 0; i < queuedListeners.length; i++) {
    var listener = queuedListeners[i];

    listener.callback.call(listener.context, rootData);
  }

  queuedListeners = [];
}

module.exports = {
  get: get
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"braintree-rpc":30}],21:[function(require,module,exports){
'use strict';

var ATTRIBUTES = [
  'bic',
  'maskedIBAN',
  'nonce',
  'accountHolderName'
];

function SEPABankAccount(attributes) {
  for (var i = 0; i < ATTRIBUTES.length; i++) {
    var attribute = ATTRIBUTES[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = SEPABankAccount;

},{}],22:[function(require,module,exports){
'use strict';

var ATTRIBUTES = [
  'accountHolderName',
  'bic',
  'longFormURL',
  'mandateReferenceNumber',
  'maskedIBAN',
  'shortForm'
];

function SEPAMandate(attributes) {
  for (var i = 0; i < ATTRIBUTES.length; i++) {
    var attribute = ATTRIBUTES[i];
    this[attribute] = attributes[attribute];
  }
}

module.exports = SEPAMandate;

},{}],23:[function(require,module,exports){
'use strict';

function joinUrlFragments(fragments) {
  var strippedFragments = [],
  strippedFragment,
  i;

  for (i = 0; i < fragments.length; i++) {
    strippedFragment = fragments[i];
    if (strippedFragment.charAt(strippedFragment.length - 1) === '/') {
      strippedFragment = strippedFragment.substring(0, strippedFragment.length - 1);
    }
    if (strippedFragment.charAt(0) === '/') {
      strippedFragment = strippedFragment.substring(1);
    }

    strippedFragments.push(strippedFragment);
  }

  return strippedFragments.join('/');
}

function isArray(value) {
  return value && typeof value === 'object' && typeof value.length === 'number' &&
    Object.prototype.toString.call(value) === '[object Array]' || false;
}

function generateUUID() { // RFC 4122 v4 (pseudo-random) UUID without hyphens
  return 'xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx'.replace(/[xy]/g, function (xORy) {
    var randomHex = Math.floor(Math.random() * 16);
    var uuidHex = xORy === 'x' ? randomHex : randomHex & 0x3 | 0x8; // jshint ignore:line
    return uuidHex.toString(16);
  });
}

module.exports = {
  joinUrlFragments: joinUrlFragments,
  isArray: isArray,
  generateUUID: generateUUID
};

},{}],24:[function(require,module,exports){
'use strict';

var Client = require('./lib/client');
var JSONP = require('./lib/jsonp');
var JSONPDriver = require('./lib/jsonp-driver');
var util = require('./lib/util');
var parseClientToken = require('./lib/parse-client-token');

function configure(options) {
  return new Client(options);
}

module.exports = {
  Client: Client,
  configure: configure,
  util: util,
  JSONP: JSONP,
  JSONPDriver: JSONPDriver,
  parseClientToken: parseClientToken
};

},{"./lib/client":12,"./lib/jsonp":16,"./lib/jsonp-driver":15,"./lib/parse-client-token":18,"./lib/util":23}],25:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function MessageBus(host) {
  this.host = host || window;
  this.handlers = [];

  utils.addEventListener(this.host, 'message', utils.bind(this.receive, this));
}

MessageBus.prototype.receive = function (event) {
  var i, message, parsed, type;

  try {
    parsed = JSON.parse(event.data);
  } catch (e) {
    return;
  }

  type = parsed.type;
  message = new MessageBus.Message(this, event.source, parsed.data);

  for (i = 0; i < this.handlers.length; i++) {
    if (this.handlers[i].type === type) {
      this.handlers[i].handler(message);
    }
  }
};

MessageBus.prototype.send = function (source, type, data) {
  source.postMessage(JSON.stringify({
    type: type,
    data: data
  }), '*');
};

MessageBus.prototype.register = function (type, handler) {
  this.handlers.push({
    type: type,
    handler: handler
  });
};

MessageBus.prototype.unregister = function (type, handler) {
  for (var i = this.handlers.length - 1; i >= 0; i--) {
    if (this.handlers[i].type === type && this.handlers[i].handler === handler) {
      return this.handlers.splice(i, 1);
    }
  }
};

MessageBus.Message = function (bus, source, content) {
  this.bus = bus;
  this.source = source;
  this.content = content;
};

MessageBus.Message.prototype.reply = function (type, data) {
  this.bus.send(this.source, type, data);
};

module.exports = MessageBus;

},{"braintree-utilities":35}],26:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function PubsubClient(bus, target) {
  this.bus = bus;
  this.target = target;
  this.handlers = [];

  this.bus.register('publish', utils.bind(this._handleMessage, this));
}

PubsubClient.prototype._handleMessage = function (message) {
  var i,
  content = message.content,
  handlers = this.handlers[content.channel];

  if (typeof handlers !== 'undefined') {
    for (i = 0; i < handlers.length; i++) {
      handlers[i](content.data);
    }
  }
};

PubsubClient.prototype.publish = function (channel, data) {
  this.bus.send(this.target, 'publish', { channel: channel, data: data });
};

PubsubClient.prototype.subscribe = function (channel, handler) {
  this.handlers[channel] = this.handlers[channel] || [];
  this.handlers[channel].push(handler);
};

PubsubClient.prototype.unsubscribe = function (channel, handler) {
  var i,
  handlers = this.handlers[channel];

  if (typeof handlers !== 'undefined') {
    for (i = 0; i < handlers.length; i++) {
      if (handlers[i] === handler) {
        handlers.splice(i, 1);
      }
    }
  }
};

module.exports = PubsubClient;

},{"braintree-utilities":35}],27:[function(require,module,exports){
'use strict';

function PubsubServer(bus) {
  this.bus = bus;
  this.frames = [];
  this.handlers = [];
}

PubsubServer.prototype.subscribe = function (channel, handler) {
  this.handlers[channel] = this.handlers[channel] || [];
  this.handlers[channel].push(handler);
};

PubsubServer.prototype.registerFrame = function (frame) {
  this.frames.push(frame);
};

PubsubServer.prototype.unregisterFrame = function (frame) {
  for (var i = 0; i < this.frames.length; i++) {
    if (this.frames[i] === frame) {
      this.frames.splice(i, 1);
    }
  }
};

PubsubServer.prototype.publish = function (channel, data) {
  var i,
  handlers = this.handlers[channel];

  if (typeof handlers !== 'undefined') {
    for (i = 0; i < handlers.length; i++) {
      handlers[i](data);
    }
  }

  for (i = 0; i < this.frames.length; i++) {
    this.bus.send(this.frames[i], 'publish', {
      channel: channel,
      data: data
    });
  }
};

PubsubServer.prototype.unsubscribe = function (channel, handler) {
  var i,
  handlers = this.handlers[channel];

  if (typeof handlers !== 'undefined') {
    for (i = 0; i < handlers.length; i++) {
      if (handlers[i] === handler) {
        handlers.splice(i, 1);
      }
    }
  }
};

module.exports = PubsubServer;

},{}],28:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function RPCClient(bus, target) {
  this.bus = bus;
  this.target = target || window.parent;
  this.counter = 0;
  this.callbacks = {};

  this.bus.register('rpc_response', utils.bind(this._handleResponse, this));
}

RPCClient.prototype._handleResponse = function (message) {
  var content = message.content,
  thisCallback = this.callbacks[content.id];

  if (typeof thisCallback === 'function') {
    thisCallback.apply(null, content.response);
    delete this.callbacks[content.id];
  }
};

RPCClient.prototype.invoke = function (method, args, callback) {
  var counter = this.counter++;

  this.callbacks[counter] = callback;
  this.bus.send(this.target, 'rpc_request', { id: counter, method: method, args: args });
};

module.exports = RPCClient;

},{"braintree-utilities":35}],29:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function RPCServer(bus) {
  this.bus = bus;
  this.methods = {};

  this.bus.register('rpc_request', utils.bind(this._handleRequest, this));
}

RPCServer.prototype._handleRequest = function (message) {
  var reply,
  content = message.content,
  args = content.args || [],
  thisMethod = this.methods[content.method];

  if (typeof thisMethod === 'function') {
    reply = function () {
      message.reply('rpc_response', {
        id: content.id,
        response: Array.prototype.slice.call(arguments)
      });
    };

    args.push(reply);

    thisMethod.apply(null, args);
  }
};

RPCServer.prototype.define = function (method, handler) {
  this.methods[method] = handler;
};

module.exports = RPCServer;

},{"braintree-utilities":35}],30:[function(require,module,exports){
var MessageBus = require('./lib/message-bus');
var PubsubClient = require('./lib/pubsub-client');
var PubsubServer = require('./lib/pubsub-server');
var RPCClient = require('./lib/rpc-client');
var RPCServer = require('./lib/rpc-server');

module.exports = {
  MessageBus: MessageBus,
  PubsubClient: PubsubClient,
  PubsubServer: PubsubServer,
  RPCClient: RPCClient,
  RPCServer: RPCServer
};

},{"./lib/message-bus":25,"./lib/pubsub-client":26,"./lib/pubsub-server":27,"./lib/rpc-client":28,"./lib/rpc-server":29}],31:[function(require,module,exports){
'use strict';

function normalizeElement (element, errorMessage) {
  errorMessage = errorMessage || '[' + element + '] is not a valid DOM Element';

  if (element && element.nodeType && element.nodeType === 1) {
    return element;
  }
  if (element && window.jQuery && element instanceof jQuery && element.length !== 0) {
    return element[0];
  }

  if (typeof element === 'string' && document.getElementById(element)) {
    return document.getElementById(element);
  }

  throw new Error(errorMessage);
}

module.exports = {
  normalizeElement: normalizeElement
};

},{}],32:[function(require,module,exports){
'use strict';

function addEventListener(context, event, handler) {
  if (context.addEventListener) {
    context.addEventListener(event, handler, false);
  } else if (context.attachEvent)  {
    context.attachEvent('on' + event, handler);
  }
}

function removeEventListener(context, event, handler) {
  if (context.removeEventListener) {
    context.removeEventListener(event, handler, false);
  } else if (context.detachEvent)  {
    context.detachEvent('on' + event, handler);
  }
}

module.exports = {
  removeEventListener: removeEventListener,
  addEventListener: addEventListener
};

},{}],33:[function(require,module,exports){
'use strict';

function isFunction(func) {
  return Object.prototype.toString.call(func) === '[object Function]';
}

function bind(func, context) {
  return function () {
    func.apply(context, arguments);
  };
}

module.exports = {
  bind: bind,
  isFunction: isFunction
};

},{}],34:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],35:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":31,"./lib/events":32,"./lib/fn":33,"./lib/url":34,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],36:[function(require,module,exports){
module.exports=require(2)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/dom.js":2}],37:[function(require,module,exports){
module.exports=require(3)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/events.js":3}],38:[function(require,module,exports){
module.exports=require(4)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/fn.js":4}],39:[function(require,module,exports){
'use strict';

function getMaxCharLength(width) {
  var max, i, range, len;
  var ranges = [
    { min: 0, max: 180, chars: 7 },
    { min: 181, max: 620, chars: 14 },
    { min: 621, max: 960, chars: 22 }
  ];

  len = ranges.length;

  width = width || window.innerWidth;

  for (i = 0; i < len; i++) {
    range = ranges[i];

    if (width >= range.min && width <= range.max) {
      max = range.chars;
    }
  }

  return max || 60;
}

function truncateEmail(email, maxLength) {
  var address, domain;

  if (email.indexOf('@') === -1) {
    return email;
  }

  email = email.split('@');
  address = email[0];
  domain = email[1];

  if (address.length > maxLength) {
    address = address.slice(0, maxLength) + '...';
  }

  if (domain.length > maxLength) {
    domain = '...' + domain.slice(-maxLength);
  }

  return address + '@' + domain;
}

module.exports = {
  truncateEmail: truncateEmail,
  getMaxCharLength: getMaxCharLength
};

},{}],40:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],41:[function(require,module,exports){
var dom = require('./lib/dom');
var url = require('./lib/url');
var fn = require('./lib/fn');
var events = require('./lib/events');
var string = require('./lib/string');

module.exports = {
  string: string,
  normalizeElement: dom.normalizeElement,
  isBrowserHttps: url.isBrowserHttps,
  makeQueryString: url.makeQueryString,
  decodeQueryString: url.decodeQueryString,
  getParams: url.getParams,
  removeEventListener: events.removeEventListener,
  addEventListener: events.addEventListener,
  bind: fn.bind,
  isFunction: fn.isFunction
};

},{"./lib/dom":36,"./lib/events":37,"./lib/fn":38,"./lib/string":39,"./lib/url":40}],42:[function(require,module,exports){
(function (global){
'use strict';

var parseClientToken = require('./parse-client-token');
var JSONPDriver = require('./jsonp-driver');
var util = require('./util');
var SEPAMandate = require('./sepa-mandate');
var SEPABankAccount = require('./sepa-bank-account');
var CreditCard = require('./credit-card');
var rootData = require('./root-data');

function deserialize(response, mapper) {
  if (response.status >= 400) {
    return [response, null];
  } else {
    return [null, mapper(response)];
  }
}

function Client(options) {
  var parsedClientToken;

  this.attrs = {};

  if (options.hasOwnProperty('sharedCustomerIdentifier')) {
    this.attrs.sharedCustomerIdentifier = options.sharedCustomerIdentifier;
  }

  parsedClientToken = parseClientToken(options.clientToken);

  this.driver = options.driver || JSONPDriver;
  this.authUrl = parsedClientToken.authUrl;
  this.analyticsUrl = parsedClientToken.analytics ? parsedClientToken.analytics.url : undefined;
  this.clientApiUrl = parsedClientToken.clientApiUrl;
  this.customerId = options.customerId;
  this.challenges = parsedClientToken.challenges;
  this.integration = options.integration || '';

  this.attrs.authorizationFingerprint = parsedClientToken.authorizationFingerprint;
  this.attrs.sharedCustomerIdentifierType = options.sharedCustomerIdentifierType;

  this.timeoutWatchers = [];
  if (options.hasOwnProperty('timeout')) {
    this.requestTimeout = options.timeout;
  } else {
    this.requestTimeout = 60000;
  }
}

function noop () {}

function mergeOptions(obj1, obj2) {
  var obj3 = {};
  var attrname;
  for (attrname in obj1) {
    if (obj1.hasOwnProperty(attrname)) {
      obj3[attrname] = obj1[attrname];
    }
  }
  for (attrname in obj2) {
    if (obj2.hasOwnProperty(attrname)) {
      obj3[attrname] = obj2[attrname];
    }
  }
  return obj3;
}

Client.prototype.requestWithTimeout = function (url, attrs, deserializer, method, callback) {
  callback = callback || noop;

  var uniqueName, version;
  var client = this;

  rootData.get(function (payload) {
    version = 'braintree/web/' + payload.sdkVersion;

    attrs.braintreeLibraryVersion = version;

    if (attrs.hasOwnProperty('analytics') && attrs.hasOwnProperty('_meta')) {
      attrs._meta.sdkVersion = version;
      attrs._meta.merchantAppId = payload.merchantAppId;
    }

    uniqueName = method(url, attrs, function (data, uniqueName) {
      if (client.timeoutWatchers[uniqueName]) {
        clearTimeout(client.timeoutWatchers[uniqueName]);
        var args = deserialize(data, function (d) { return deserializer(d);});
        callback.apply(null, args);
      }
    });

    if (client.requestTimeout > 0) {
      this.timeoutWatchers[uniqueName] = setTimeout(function () {
        client.timeoutWatchers[uniqueName] = null;
        callback.apply(null, [{'errors': 'Unknown error'}, null]);
      }, client.requestTimeout);
    } else {
      callback.apply(null, [{'errors': 'Unknown error'}, null]);
    }
  }, this);
};

Client.prototype.post = function (url, attrs, deserializer, callback) {
  this.requestWithTimeout(url, attrs, deserializer, this.driver.post, callback);
};

Client.prototype.get = function (url, attrs, deserializer, callback) {
  this.requestWithTimeout(url, attrs, deserializer, this.driver.get, callback);
};

Client.prototype.put = function (url, attrs, deserializer, callback) {
  this.requestWithTimeout(url, attrs, deserializer, this.driver.put, callback);
};

Client.prototype.getCreditCards = function (callback) {
  this.get(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods']),
    this.attrs,
    function (d) {
      var i = 0;
      var len = d.paymentMethods.length;
      var creditCards = [];

      for (i; i < len; i++) {
        creditCards.push(new CreditCard(d.paymentMethods[i]));
      }

      return creditCards;
    },
    callback
  );
};

Client.prototype.tokenizeCard = function (attrs, callback) {
  attrs.options = { validate: false };
  this.addCreditCard(attrs, function (err, result) {
    if (result && result.nonce) {
      callback(err, result.nonce);
    } else {
      callback('Unable to tokenize card.', null);
    }
  });
};

Client.prototype.addSEPAMandate = function (attrs, callback) {
  var mergedAttrs = mergeOptions(this.attrs, {sepaMandate: attrs});
  this.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'sepa_mandates.json']),
    mergedAttrs,
    function (d) { return new SEPAMandate(d.sepaMandates[0]); },
    callback
  );
};

Client.prototype.acceptSEPAMandate = function (mandateReferenceNumber, callback) {
  this.put(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'sepa_mandates', mandateReferenceNumber, 'accept']),
    this.attrs,
    function (d) { return new SEPABankAccount(d.sepaBankAccounts[0]); },
    callback
  );
};

Client.prototype.getSEPAMandate = function (mandateIdentifier, callback) {
  var mergedAttrs;
  if (mandateIdentifier.paymentMethodToken) {
    mergedAttrs = mergeOptions(this.attrs, {paymentMethodToken: mandateIdentifier.paymentMethodToken});
  } else {
    mergedAttrs = this.attrs;
  }
  this.get(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'sepa_mandates', mandateIdentifier.mandateReferenceNumber || '']),
    mergedAttrs,
    function (d) { return new SEPAMandate(d.sepaMandates[0]); },
    callback
  );
};

Client.prototype.addCreditCard = function (attrs, callback) {
  var mergedAttrs;
  var share = attrs.share;

  delete attrs.share;

  mergedAttrs = mergeOptions(this.attrs, {
    share: share,
    creditCard: attrs,
    _meta: {
      integration: this.integration || 'custom',
      source: 'form'
    }
  });

  this.post(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods/credit_cards']),
    mergedAttrs,
    function (d) {
      return new CreditCard(d.creditCards[0]);
    },
    callback
  );
};

Client.prototype.unlockCreditCard = function (creditCard, params, callback) {
  var attrs = mergeOptions(this.attrs, {challengeResponses: params});
  this.put(
    util.joinUrlFragments([this.clientApiUrl, 'v1', 'payment_methods/', creditCard.nonce]),
    attrs,
    function (d) { return new CreditCard(d.paymentMethods[0]); },
    callback
  );
};

Client.prototype.sendAnalyticsEvents = function (events, callback) {
  var attrs;
  var url = this.analyticsUrl;
  var eventObjects = [];
  events = util.isArray(events) ? events : [events];

  if (!url) {
    if (callback) {
      callback.apply(null, [null, {}]);
    }
    return;
  }

  for (var event in events) {
    if (events.hasOwnProperty(event)) {
      eventObjects.push({ kind: events[event] });
    }
  }

  attrs = mergeOptions(this.attrs, {
    analytics: eventObjects,
    _meta: {
      platform: 'web',
      platformVersion: global.navigator.userAgent,
      integrationType: this.integration
    }
  });

  this.post(url, attrs, function (d) { return d; }, callback);
};

module.exports = Client;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./credit-card":43,"./jsonp-driver":44,"./parse-client-token":46,"./root-data":48,"./sepa-bank-account":49,"./sepa-mandate":50,"./util":51}],43:[function(require,module,exports){
module.exports=require(14)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/credit-card.js":14}],44:[function(require,module,exports){
arguments[4][15][0].apply(exports,arguments)
},{"./jsonp":45,"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/jsonp-driver.js":15}],45:[function(require,module,exports){
(function (global){
var util = require('./util');

/*
* Lightweight JSONP fetcher
* Copyright 2010-2012 Erik Karlsson. All rights reserved.
* BSD licensed
*/
var head,
    counter = 0,
    window = global,
    config = {};

function load(url, pfnError) {
  var script = document.createElement('script'),
  done = false;
  script.src = url;
  script.async = true;

  var errorHandler = pfnError || config.error;
  if ( typeof errorHandler === 'function' ) {
    script.onerror = function(ex){
      errorHandler({url: url, event: ex});
    };
  }

  script.onload = script.onreadystatechange = function() {
    if ( !done && (!this.readyState || this.readyState === "loaded" || this.readyState === "complete") ) {
      done = true;
      script.onload = script.onreadystatechange = null;
      if ( script && script.parentNode ) {
        script.parentNode.removeChild( script );
      }
    }
  };

  if ( !head ) {
    head = document.getElementsByTagName('head')[0];
  }
  head.appendChild( script );
}

function encode(str) {
  return encodeURIComponent(str);
}

function stringify(params, namespace) {
  var query = [], k, v, p;
  for(var p in params) {
    if (!params.hasOwnProperty(p)) {
      continue;
    }

    v = params[p];
    if (namespace) {
      if (util.isArray(params)) {
        k = namespace + "[]";
      } else {
        k = namespace + "[" + p + "]";
      }
    } else {
      k = p;
    }
    if (typeof v == "object") {
      query.push(stringify(v, k));
    } else {
      query.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
    }
  }
  return query.join("&");
}

function jsonp(url, params, callback, callbackName) {
  var query = (url||'').indexOf('?') === -1 ? '?' : '&', key;

  callbackName = (callbackName||config['callbackName']||'callback');
  var uniqueName = callbackName + "_json" + (++counter);

  query += stringify(params);

  window[ uniqueName ] = function(data){
    callback(data, uniqueName);
    try {
      delete window[ uniqueName ];
    } catch (e) {}
    window[ uniqueName ] = null;
  };

  load(url + query + '&' + callbackName + '=' + uniqueName);
  return uniqueName;
}

function setDefaults(obj){
  config = obj;
}

module.exports = {
  get: jsonp,
  init: setDefaults,
  stringify: stringify
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"./util":51}],46:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"./polyfill":47,"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/parse-client-token.js":18}],47:[function(require,module,exports){
(function (global){
'use strict';
global.atob = global.atob || function (base64String) {
  var base64Matcher = new RegExp("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})([=]{1,2})?$");
  var characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var result = "";

  if (!base64Matcher.test(base64String)) {
    throw new Error("Braintree API Client Misconfigured: clientToken is invalid.");
  }

  var i = 0;
  do {
    var b1 = characters.indexOf( base64String.charAt(i++) );
    var b2 = characters.indexOf( base64String.charAt(i++) );
    var b3 = characters.indexOf( base64String.charAt(i++) );
    var b4 = characters.indexOf( base64String.charAt(i++) );

    var a = ( ( b1 & 0x3F ) << 2 ) | ( ( b2 >> 4 ) & 0x3 );
    var b = ( ( b2 & 0xF  ) << 4 ) | ( ( b3 >> 2 ) & 0xF );
    var c = ( ( b3 & 0x3  ) << 6 ) | ( b4 & 0x3F );

    result += String.fromCharCode(a) + (b?String.fromCharCode(b):"") + (c?String.fromCharCode(c):"");

  } while( i < base64String.length );

  return result;
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}],48:[function(require,module,exports){
(function (global){
'use strict';

var rpc = require('braintree-rpc');
var bus = new rpc.MessageBus(window);
var rpcClient = new rpc.RPCClient(bus, window.parent);
var isResolved = false;

var rootData = {
  sdkVersion: getInitialVersionValue(),
  merchantAppId: global.location.href
};

function getInitialVersionValue() {
  var globalBraintree = global.braintree;

  return (globalBraintree && globalBraintree.hasOwnProperty('VERSION')) ? globalBraintree.VERSION : undefined;
}

function requestFromRoot(callback) {
  function resolve(version) {
    if (!isResolved) {
      isResolved = true;
      callback(version);
    }
  }

  rpcClient.invoke('getExternalData', [], resolve);

  setTimeout(function () {
    if (!isResolved) {
      resolve();
    }
  }, 250);
}

function get(callback, context) {
  if (isResolved) {
    callback.call(context, rootData);
  } else {
    requestFromRoot(function (payload) {
      for (var key in payload) {
        if (payload.hasOwnProperty(key)) {
          rootData[key] = payload[key] || rootData[key];
        }
      }

      callback.call(context, rootData);
    });
  }
}

module.exports = {
  get: get
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"braintree-rpc":58}],49:[function(require,module,exports){
module.exports=require(21)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/sepa-bank-account.js":21}],50:[function(require,module,exports){
module.exports=require(22)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/sepa-mandate.js":22}],51:[function(require,module,exports){
'use strict';

function joinUrlFragments(fragments) {
  var strippedFragments = [],
  strippedFragment,
  i;

  for (i = 0; i < fragments.length; i++) {
    strippedFragment = fragments[i];
    if (strippedFragment.charAt(strippedFragment.length - 1) === '/') {
      strippedFragment = strippedFragment.substring(0, strippedFragment.length - 1);
    }
    if (strippedFragment.charAt(0) === '/') {
      strippedFragment = strippedFragment.substring(1);
    }

    strippedFragments.push(strippedFragment);
  }

  return strippedFragments.join('/');
}

function isArray(value) {
  return value && typeof value === 'object' && typeof value.length === 'number' &&
    Object.prototype.toString.call(value) === '[object Array]' || false;
}

module.exports = {
  joinUrlFragments: joinUrlFragments,
  isArray: isArray
};

},{}],52:[function(require,module,exports){
arguments[4][24][0].apply(exports,arguments)
},{"./lib/client":42,"./lib/jsonp":45,"./lib/jsonp-driver":44,"./lib/parse-client-token":46,"./lib/util":51,"/home/pair/bt/braintree.js/node_modules/braintree-api/main.js":24}],53:[function(require,module,exports){
module.exports=require(25)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/message-bus.js":25,"braintree-utilities":63}],54:[function(require,module,exports){
module.exports=require(26)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-client.js":26,"braintree-utilities":63}],55:[function(require,module,exports){
module.exports=require(27)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-server.js":27}],56:[function(require,module,exports){
module.exports=require(28)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-client.js":28,"braintree-utilities":63}],57:[function(require,module,exports){
module.exports=require(29)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-server.js":29,"braintree-utilities":63}],58:[function(require,module,exports){
module.exports=require(30)
},{"./lib/message-bus":53,"./lib/pubsub-client":54,"./lib/pubsub-server":55,"./lib/rpc-client":56,"./lib/rpc-server":57,"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/main.js":30}],59:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],60:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],61:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],62:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],63:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":59,"./lib/events":60,"./lib/fn":61,"./lib/url":62,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],64:[function(require,module,exports){
module.exports=require(42)
},{"./credit-card":65,"./jsonp-driver":66,"./parse-client-token":68,"./root-data":70,"./sepa-bank-account":71,"./sepa-mandate":72,"./util":73,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/client.js":42}],65:[function(require,module,exports){
module.exports=require(14)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/credit-card.js":14}],66:[function(require,module,exports){
arguments[4][15][0].apply(exports,arguments)
},{"./jsonp":67,"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/jsonp-driver.js":15}],67:[function(require,module,exports){
module.exports=require(45)
},{"./util":73,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/jsonp.js":45}],68:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"./polyfill":69,"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/parse-client-token.js":18}],69:[function(require,module,exports){
module.exports=require(47)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/polyfill.js":47}],70:[function(require,module,exports){
module.exports=require(48)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/root-data.js":48,"braintree-rpc":80}],71:[function(require,module,exports){
module.exports=require(21)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/sepa-bank-account.js":21}],72:[function(require,module,exports){
module.exports=require(22)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/sepa-mandate.js":22}],73:[function(require,module,exports){
module.exports=require(51)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/util.js":51}],74:[function(require,module,exports){
arguments[4][24][0].apply(exports,arguments)
},{"./lib/client":64,"./lib/jsonp":67,"./lib/jsonp-driver":66,"./lib/parse-client-token":68,"./lib/util":73,"/home/pair/bt/braintree.js/node_modules/braintree-api/main.js":24}],75:[function(require,module,exports){
module.exports=require(25)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/message-bus.js":25,"braintree-utilities":85}],76:[function(require,module,exports){
module.exports=require(26)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-client.js":26,"braintree-utilities":85}],77:[function(require,module,exports){
module.exports=require(27)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-server.js":27}],78:[function(require,module,exports){
module.exports=require(28)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-client.js":28,"braintree-utilities":85}],79:[function(require,module,exports){
module.exports=require(29)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-server.js":29,"braintree-utilities":85}],80:[function(require,module,exports){
module.exports=require(30)
},{"./lib/message-bus":75,"./lib/pubsub-client":76,"./lib/pubsub-server":77,"./lib/rpc-client":78,"./lib/rpc-server":79,"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/main.js":30}],81:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],82:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],83:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],84:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],85:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":81,"./lib/events":82,"./lib/fn":83,"./lib/url":84,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],86:[function(require,module,exports){
module.exports=require(25)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/message-bus.js":25,"braintree-utilities":96}],87:[function(require,module,exports){
module.exports=require(26)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-client.js":26,"braintree-utilities":96}],88:[function(require,module,exports){
module.exports=require(27)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-server.js":27}],89:[function(require,module,exports){
module.exports=require(28)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-client.js":28,"braintree-utilities":96}],90:[function(require,module,exports){
module.exports=require(29)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-server.js":29,"braintree-utilities":96}],91:[function(require,module,exports){
module.exports=require(30)
},{"./lib/message-bus":86,"./lib/pubsub-client":87,"./lib/pubsub-server":88,"./lib/rpc-client":89,"./lib/rpc-server":90,"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/main.js":30}],92:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],93:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],94:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],95:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],96:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":92,"./lib/events":93,"./lib/fn":94,"./lib/url":95,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],97:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],98:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],99:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],100:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],101:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":97,"./lib/events":98,"./lib/fn":99,"./lib/url":100,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],102:[function(require,module,exports){
var braintreeApi = require('braintree-api');
var braintreeRpc = require('braintree-rpc');
var braintreeUtil = require('braintree-utilities');
var LoggedInView = require('./logged-in-view');
var LoggedOutView = require('./logged-out-view');
var browser = require('../shared/util/browser');
var dom = require('../shared/util/dom');
var constants = require('../shared/constants');
var util = require('../shared/util/util');

function getStyles(element) {
  var computedStyles = window.getComputedStyle ? getComputedStyle(element) : element.currentStyle;
  return {
    overflow: computedStyles.overflow || '',
    height: element.style.height || ''
  };
}

function getMerchantPageDefaultStyles() {
  return {
    html: {
      node: document.documentElement,
      styles: getStyles(document.documentElement)
    },
    body: {
      node: document.body,
      styles: getStyles(document.body)
    }
  };
}

function Client(clientToken, options) {
  if (!clientToken) {
    throw new Error('Parameter "clientToken" cannot be null');
  }
  options = options || {};

  this._clientToken = braintreeApi.parseClientToken(clientToken);
  this._clientOptions = options;

  this.container = options.container;
  this.merchantPageDefaultStyles = null;
  this.paymentMethodNonceInputField = options.paymentMethodNonceInputField;
  this.frame = null;
  this.popup = null;

  this.insertFrameFunction = options.insertFrame;
  this.onSuccess = options.onSuccess;
  this.onCancelled = options.onCancelled;
  this.onUnsupported = options.onUnsupported;
  this.loggedInView = null;
  this.loggedOutView = null;

  this.insertUI = true;
}

Client.prototype.getViewerUrl = function () {
  var assetsUrl = this._clientToken.paypal.assetsUrl;
  return assetsUrl + '/pwpp/' + constants.VERSION + '/html/braintree-frame.html';
};

Client.prototype.initialize = function () {
  if (!this._clientToken.paypalEnabled) {
    if (typeof this.onUnsupported === 'function') {
      this.onUnsupported(new Error('PayPal is not enabled'));
    }
    return;
  }
  if (!this._isBrowserSecure()) {
    if (typeof this.onUnsupported === 'function') {
      this.onUnsupported(new Error('unsupported protocol detected'));
    }
    return;
  }
  this._overrideClientTokenProperties();
  this._setupDomElements();
  this._setupPaymentMethodNonceInputField();
  this._setupViews();
  this._createRpcServer();
};

Client.prototype._isBrowserSecure = function () {
  return braintreeUtil.isBrowserHttps() || this._clientToken.paypal.allowHttp;
};

Client.prototype._overrideClientTokenProperties = function () {
  if (this._clientOptions.displayName) {
    this._clientToken.paypal.displayName = this._clientOptions.displayName;
  }
};

Client.prototype._setupDomElements = function () {
  if (this.insertUI) {
    this.container = braintreeUtil.normalizeElement(this.container);
  }
};

Client.prototype._setupPaymentMethodNonceInputField = function () {
  if (!this.insertUI) {
    return;
  }
  var inputField = this.paymentMethodNonceInputField;
  if (!braintreeUtil.isFunction(inputField)) {
    if (inputField !== undefined) {
      inputField = braintreeUtil.normalizeElement(inputField);
    } else {
      inputField = this._createPaymentMethodNonceInputField();
    }
    this.paymentMethodNonceInputField = inputField;
  }
};

Client.prototype._setupViews = function () {
  var assetsUrl = this._clientToken.paypal.assetsUrl;
  if (this.insertUI) {
    this.loggedInView = new LoggedInView({
      container: this.container,
      assetsUrl: assetsUrl
    });
    this.loggedOutView = new LoggedOutView({
      assetsUrl: assetsUrl,
      container: this.container
    });

    braintreeUtil.addEventListener(this.loggedOutView.buttonNode, 'click', braintreeUtil.bind(this._handleButtonClick, this));
    braintreeUtil.addEventListener(this.loggedInView.logoutNode, 'click', braintreeUtil.bind(this._handleLogout, this));
  }
};

Client.prototype._createRpcServer = function () {
  var bus = new braintreeRpc.MessageBus(window);
  var rpc = new braintreeRpc.RPCServer(bus, window);

  rpc.define('getClientToken',
    braintreeUtil.bind(this._handleGetClientToken, this));
  rpc.define('getClientOptions',
    braintreeUtil.bind(this._handleGetClientOptions, this));
  rpc.define('closePayPalModal',
    braintreeUtil.bind(this._handleCloseMessage, this));
  rpc.define('receivePayPalData',
    braintreeUtil.bind(this._handleSuccessfulAuthentication, this));
};

Client.prototype._createPaymentMethodNonceInputField = function () {
  var input = document.createElement('input');
  input.name = 'payment_method_nonce';
  input.type = 'hidden';
  return this.container.appendChild(input);
};

Client.prototype._createFrame = function () {
  var iframe = document.createElement('iframe');
  iframe.src = this.getViewerUrl();
  iframe.id = constants.FRAME_NAME;
  iframe.name = constants.FRAME_NAME;
  iframe.allowTransparency = true;
  iframe.height = '100%';
  iframe.width = '100%';
  iframe.frameBorder = 0;
  iframe.style.position = browser.isMobile() ? 'absolute' : 'fixed';
  iframe.style.top = 0;
  iframe.style.left = 0;
  iframe.style.bottom = 0;
  iframe.style.zIndex = 20001;
  iframe.style.padding = 0;
  iframe.style.margin = 0;
  iframe.style.border = 0;
  iframe.style.outline = 'none';
  return iframe;
};

Client.prototype._removeFrame = function (parent) {
  parent = parent || document.body;
  if (this.frame && parent.contains(this.frame)) {
    parent.removeChild(this.frame);
    this._unlockMerchantWindowSize();
  }
};

Client.prototype._insertFrame = function () {
  if (this.insertFrameFunction) {
    this.insertFrameFunction(this.getViewerUrl());
  } else {
    this.frame = this._createFrame();
    document.body.appendChild(this.frame);
  }
  this._lockMerchantWindowSize();
};

Client.prototype._handleButtonClick = function (event) {
  if (event.preventDefault) {
    event.preventDefault();
  } else {
    event.returnValue = false;
  }
  this._open();
};

Client.prototype._setMerchantPageDefaultStyles = function () {
  this.merchantPageDefaultStyles = getMerchantPageDefaultStyles();
};

Client.prototype._open = function () {
  if (browser.isPopupSupported()) {
    this._openPopup();
  } else {
    this._openModal();
  }
};

Client.prototype._close = function () {
  if (browser.isPopupSupported()) {
    this._closePopup();
  } else {
    this._closeModal();
  }
};

Client.prototype._openModal = function () {
  this._removeFrame();
  this._insertFrame();
};

Client.prototype._openPopup = function () {
  var name = constants.POPUP_NAME;
  var opts = constants.POPUP_OPTIONS;
  this.popup = window.open(this.getViewerUrl(), name, opts);
  this.popup.focus();

  return this.popup;
};

Client.prototype._closeModal = function () {
  this._removeFrame();
};

Client.prototype._closePopup = function () {
  if (this.popup) {
    this.popup.close();
    this.popup = null;
  }
};

Client.prototype._handleGetClientToken = function (callback) {
  var dataToSend = {
    analyticsUrl: this._clientToken.analytics ?
      this._clientToken.analytics.url : undefined,
    authorizationFingerprint: this._clientToken.authorizationFingerprint,
    authUrl: this._clientToken.authUrl,
    clientApiUrl: this._clientToken.clientApiUrl,
    displayName: this._clientToken.paypal.displayName,
    paypalBaseUrl: this._clientToken.paypal.assetsUrl,
    paypalClientId: this._clientToken.paypal.clientId,
    paypalPrivacyUrl: this._clientToken.paypal.privacyUrl,
    paypalUserAgreementUrl: this._clientToken.paypal.userAgreementUrl,
    offline: this._clientToken.paypal.environmentNoNetwork
  };
  callback(dataToSend);
};

Client.prototype._handleGetClientOptions = function (callback) {
  var dataToSend = {
    demo: this._clientOptions.demo || false,
    locale: this._clientOptions.locale || 'en_us',
    onetime: this._clientOptions.singleUse || false,
    integration: this._clientOptions.integration || 'paypal',
    enableShippingAddress: this._clientOptions.enableShippingAddress || false
  };
  callback(dataToSend);
};

Client.prototype._handleSuccessfulAuthentication = function (bundle) {
  this._close();

  if (braintreeUtil.isFunction(this.paymentMethodNonceInputField)) {
    this.paymentMethodNonceInputField(bundle.nonce);
  } else {
    this._showLoggedInContent(bundle.email);
    this._setNonceInputValue(bundle.nonce);
  }

  if (braintreeUtil.isFunction(this.onSuccess)) {
    this.onSuccess(bundle);
  }
};

Client.prototype._lockMerchantWindowSize = function () {
  this._setMerchantPageDefaultStyles();
  document.documentElement.style.height = '100%';
  document.documentElement.style.overflow = 'hidden';
  document.body.style.height = '100%';
  document.body.style.overflow = 'hidden';
};

Client.prototype._unlockMerchantWindowSize = function () {
  if (this.merchantPageDefaultStyles) {
    document.documentElement.style.height = this.merchantPageDefaultStyles.html.styles.height;
    document.documentElement.style.overflow = this.merchantPageDefaultStyles.html.styles.overflow;
    document.body.style.height = this.merchantPageDefaultStyles.body.styles.height;
    document.body.style.overflow = this.merchantPageDefaultStyles.body.styles.overflow;
  }
};

Client.prototype._handleCloseMessage = function () {
  this._removeFrame();
};

Client.prototype._showLoggedInContent = function (email) {
  this.loggedOutView.hide();

  dom.setTextContent(this.loggedInView.emailNode, email);
  this.loggedInView.show();
};

Client.prototype._handleLogout = function (event) {
  if (event.preventDefault) {
    event.preventDefault();
  } else {
    event.returnValue = false;
  }

  this.loggedInView.hide();
  this.loggedOutView.show();
  this._setNonceInputValue('');

  if (braintreeUtil.isFunction(this.onCancelled)) {
    this.onCancelled();
  }
};

Client.prototype._setNonceInputValue = function (value) {
  this.paymentMethodNonceInputField.value = value;
};

module.exports = Client;

},{"../shared/constants":105,"../shared/util/browser":110,"../shared/util/dom":111,"../shared/util/util":112,"./logged-in-view":103,"./logged-out-view":104,"braintree-api":74,"braintree-rpc":91,"braintree-utilities":101}],103:[function(require,module,exports){
var constants = require('../shared/constants');

function LoggedInView (options) {
  this.options = options;
  this.container = this.createViewContainer();
  this.createPayPalName();
  this.emailNode = this.createEmailNode();
  this.logoutNode = this.createLogoutNode();
}

LoggedInView.prototype.createViewContainer = function () {
  var container = document.createElement('div');
  container.id = 'braintree-paypal-loggedin';
  var cssStyles = [
    'display: none',
    'max-width: 500px',
    'overflow: hidden',
    'padding: 16px',
    'background-image: url(' + this.options.assetsUrl + '/pwpp/' + constants.VERSION + '/images/paypal-small.png)',
    'background-image: url(' + this.options.assetsUrl + '/pwpp/' + constants.VERSION + '/images/paypal-small.svg), none',
    'background-position: 20px 50%',
    'background-repeat: no-repeat',
    'background-size: 13px 15px',
    'border-top: 1px solid #d1d4d6',
    'border-bottom: 1px solid #d1d4d6'
  ].join(';');
  container.style.cssText = cssStyles;
  this.options.container.appendChild(container);

  return container;
};

LoggedInView.prototype.createPayPalName = function () {
  var element = document.createElement('span');
  element.id = 'bt-pp-name';
  element.innerHTML = 'PayPal';
  var cssStyles = [
    'color: #283036',
    'font-size: 13px',
    'font-weight: 800',
    'font-family: "Helvetica Neue", Helvetica, Arial, sans-serif',
    'margin-left: 36px',
    '-webkit-font-smoothing: antialiased',
    '-moz-font-smoothing: antialiased',
    '-ms-font-smoothing: antialiased',
    'font-smoothing: antialiased'
  ].join(';');
  element.style.cssText = cssStyles;
  return this.container.appendChild(element);
};

LoggedInView.prototype.createEmailNode = function () {
  var element = document.createElement('span');
  element.id = 'bt-pp-email';
  var cssStyles = [
    'color: #6e787f',
    'font-size: 13px',
    'font-family: "Helvetica Neue", Helvetica, Arial, sans-serif',
    'margin-left: 5px',
    '-webkit-font-smoothing: antialiased',
    '-moz-font-smoothing: antialiased',
    '-ms-font-smoothing: antialiased',
    'font-smoothing: antialiased'
  ].join(';');
  element.style.cssText = cssStyles;
  return this.container.appendChild(element);
};

LoggedInView.prototype.createLogoutNode = function () {
  var element = document.createElement('button');
  element.id = 'bt-pp-cancel';
  element.innerHTML = 'Cancel';
  var cssStyles = [
    'color: #3d95ce',
    'font-size: 11px',
    'font-family: "Helvetica Neue", Helvetica, Arial, sans-serif',
    'line-height: 20px',
    'margin: 0 0 0 25px',
    'padding: 0',
    'background-color: transparent',
    'border: 0',
    'cursor: pointer',
    'text-decoration: underline',
    'float: right',
    '-webkit-font-smoothing: antialiased',
    '-moz-font-smoothing: antialiased',
    '-ms-font-smoothing: antialiased',
    'font-smoothing: antialiased'
  ].join(';');
  element.style.cssText = cssStyles;
  return this.container.appendChild(element);
};

LoggedInView.prototype.show = function () {
  this.container.style.display = 'block';
};

LoggedInView.prototype.hide = function () {
  this.container.style.display = 'none';
};

module.exports = LoggedInView;

},{"../shared/constants":105}],104:[function(require,module,exports){
var constants = require('../shared/constants');

function LoggedOutView (options) {
  this.options = options;

  this.assetsUrl = this.options.assetsUrl;
  this.container = this.createViewContainer();
  this.buttonNode = this.createPayWithPayPalButton();
}

LoggedOutView.prototype.createViewContainer = function () {
  var container = document.createElement('div');
  container.id = 'braintree-paypal-loggedout';

  this.options.container.appendChild(container);

  return container;
};

LoggedOutView.prototype.createPayWithPayPalButton = function () {
  var element = document.createElement('a');
  element.id = 'braintree-paypal-button';
  element.href = '#';
  var cssStyles = [
    'display: block',
    'width: 115px',
    'height: 44px',
    'overflow: hidden'
  ].join(';');
  element.style.cssText = cssStyles;

  var image = new Image();
  image.src = this.assetsUrl + '/pwpp/' + constants.VERSION + '/images/pay-with-paypal.png';
  image.setAttribute('alt', 'Pay with PayPal');
  var imageCssText = [
    'max-width: 100%',
    'display: block',
    'width: 100%',
    'height: 100%',
    'outline: none',
    'border: 0'
  ].join(';');
  image.style.cssText = imageCssText;

  element.appendChild(image);
  return this.container.appendChild(element);
};

LoggedOutView.prototype.show = function () {
  this.container.style.display = 'block';
};

LoggedOutView.prototype.hide = function () {
  this.container.style.display = 'none';
};

module.exports = LoggedOutView;

},{"../shared/constants":105}],105:[function(require,module,exports){
var version = "1.2.1";

exports.VERSION = version;
exports.POPUP_NAME = 'braintree_paypal_popup';
exports.FRAME_NAME = 'braintree-paypal-frame';
exports.POPUP_PATH = '/pwpp/' + version  + '/html/braintree-frame.html';
exports.POPUP_OPTIONS = 'height=470,width=410,resizable,scrollbars';

},{}],106:[function(require,module,exports){
var userAgent = require('./useragent');

var toString = Object.prototype.toString;

function isAndroid() {
  return userAgent.matchUserAgent('Android') && !isChrome();
}

function isChrome() {
  return userAgent.matchUserAgent('Chrome') || userAgent.matchUserAgent('CriOS');
}

function isFirefox() {
  return userAgent.matchUserAgent('Firefox');
}

function isIE() {
  return userAgent.matchUserAgent('Trident') || userAgent.matchUserAgent('MSIE');
}

function isOpera() {
  return userAgent.matchUserAgent('Opera') || userAgent.matchUserAgent('OPR');
}

function isOperaMini() {
  return isOpera() && toString.call(window.operamini) === '[object OperaMini]';
}

function isSafari() {
  return userAgent.matchUserAgent('Safari') && !isChrome() && !isAndroid();
}

module.exports = {
  isAndroid: isAndroid,
  isChrome: isChrome,
  isFirefox: isFirefox,
  isIE: isIE,
  isOpera: isOpera,
  isOperaMini: isOperaMini,
  isSafari: isSafari
};

},{"./useragent":109}],107:[function(require,module,exports){
var userAgent = require('./useragent');
var platform = require('./platform');

function isMobile() {
  return !isTablet() &&
      (platform.isAndroid() || platform.isIpod() || platform.isIphone() ||
       userAgent.matchUserAgent('IEMobile'));
}

function isTablet() {
  return platform.isIpad() || (platform.isAndroid() &&
      !userAgent.matchUserAgent('Mobile'));
}

function isDesktop() {
  return !isMobile() && !isTablet();
}

module.exports = {
  isMobile: isMobile,
  isTablet: isTablet,
  isDesktop: isDesktop
};

},{"./platform":108,"./useragent":109}],108:[function(require,module,exports){
var userAgent = require('./useragent');

function isAndroid() {
  return userAgent.matchUserAgent('Android');
}

function isIpad() {
  return userAgent.matchUserAgent('iPad');
}

function isIpod() {
  return userAgent.matchUserAgent('iPod');
}

function isIphone() {
  return userAgent.matchUserAgent('iPhone') && !isIpod();
}

function isIos() {
  return isIpad() || isIpod() || isIphone();
}

module.exports = {
  isAndroid: isAndroid,
  isIpad: isIpad,
  isIpod: isIpod,
  isIphone: isIphone,
  isIos: isIos
};

},{"./useragent":109}],109:[function(require,module,exports){
var nativeUserAgent = window.navigator.userAgent;

function getNativeUserAgent() {
  return nativeUserAgent;
}

function matchUserAgent(pattern) {
  var userAgent = exports.getNativeUserAgent();
  var matches = userAgent.match(pattern);
  if (matches) {
    return true;
  }
  return false;
}

exports.getNativeUserAgent = getNativeUserAgent;
exports.matchUserAgent = matchUserAgent;

},{}],110:[function(require,module,exports){
var browser = require('../useragent/browser');
var device = require('../useragent/device');
var platform = require('../useragent/platform');
var userAgent = require('../useragent/useragent');

var uaString = window.navigator.userAgent;
var mobileRe = /[Mm]obi|tablet|iOS|Android|IEMobile|Windows\sPhone/;

function isMobile() {
  return isMobileDevice() && window.outerWidth < 600;
}

function isMobileDevice() {
  return mobileRe.test(uaString);
}

function detectedPostMessage() {
  return !!window.postMessage;
}

function isPopupSupported() {
  if (browser.isOpera() || browser.isOperaMini() ||
      (platform.isIos() && browser.isSafari() && userAgent.matchUserAgent(/Version\/8/i))) {
    return false;
  }
  if (platform.isIos() && browser.isSafari()) {
    return true;
  }
  if (device.isDesktop() && (browser.isChrome() ||
      browser.isFirefox() || browser.isSafari() ||
      (userAgent.matchUserAgent(/MSIE 10\.0/) && !isMetroBrowser()))) {
    return true;
  }
  return false;
}

function isMetroBrowser() {
  var supported = null;
  var errorName = '';
  try {
    new ActiveXObject('');
  } catch (e) {
    errorName = e.name;
  }
  try {
    supported = !!new ActiveXObject('htmlfile');
  } catch (e) {
    supported = false;
  }
  if (errorName !== 'ReferenceError' && supported === false) {
    supported = false;
  } else {
    supported = true;
  }
  return !supported;
}

module.exports = {
  isMobile: isMobile,
  isMobileDevice: isMobileDevice,
  detectedPostMessage: detectedPostMessage,
  isPopupSupported: isPopupSupported
};

},{"../useragent/browser":106,"../useragent/device":107,"../useragent/platform":108,"../useragent/useragent":109}],111:[function(require,module,exports){
function setTextContent(element, content) {
  var property = 'innerText';
  if (document && document.body) {
    if ('textContent' in document.body) {
      property = 'textContent';
    }
  }
  element[property] = content;
}

module.exports = {
  setTextContent: setTextContent
};

},{}],112:[function(require,module,exports){
var trim = typeof String.prototype.trim === 'function' ?
  function (str) { return str.trim(); } :
  function (str) { return str.replace(/^\s+|\s+$/, ''); };

var btoa = typeof window.btoa === 'function' ?
  function (str) { return window.btoa(str); } :
  function (str) {
    var keyStr =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
    var output = '';
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var i = 0;

    while (i < str.length) {
      chr1 = str.charCodeAt(i++);
      chr2 = str.charCodeAt(i++);
      chr3 = str.charCodeAt(i++);

      enc1 = chr1 >> 2;
      enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
      enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
      enc4 = chr3 & 63;

      if (isNaN(chr2)) {
        enc3 = enc4 = 64;
      } else if (isNaN(chr3)) {
        enc4 = 64;
      }

      output = output + keyStr.charAt(enc1) + keyStr.charAt(enc2) +
          keyStr.charAt(enc3) + keyStr.charAt(enc4);
    }

    return output;
  };

function generateUid() {
  var uid = '';
  for (var i = 0; i < 32; i++) {
    var r = Math.floor(Math.random() * 16);
    uid += r.toString(16);
  }
  return uid;
}

function castToBoolean(value) {
  return /^(true|1)$/i.test(value);
}

function htmlEscape(str) {
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\"/g, '&quot;')
            .replace(/\'/g, '&apos;');
}

module.exports = {
  trim: trim,
  btoa: btoa,
  generateUid: generateUid,
  castToBoolean: castToBoolean,
  htmlEscape: htmlEscape
};

},{}],113:[function(require,module,exports){
module.exports=require(25)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/message-bus.js":25,"braintree-utilities":123}],114:[function(require,module,exports){
module.exports=require(26)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-client.js":26,"braintree-utilities":123}],115:[function(require,module,exports){
module.exports=require(27)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-server.js":27}],116:[function(require,module,exports){
module.exports=require(28)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-client.js":28,"braintree-utilities":123}],117:[function(require,module,exports){
module.exports=require(29)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-server.js":29,"braintree-utilities":123}],118:[function(require,module,exports){
module.exports=require(30)
},{"./lib/message-bus":113,"./lib/pubsub-client":114,"./lib/pubsub-server":115,"./lib/rpc-client":116,"./lib/rpc-server":117,"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/main.js":30}],119:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],120:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],121:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],122:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],123:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":119,"./lib/events":120,"./lib/fn":121,"./lib/url":122,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],124:[function(require,module,exports){
module.exports=require(2)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/dom.js":2}],125:[function(require,module,exports){
module.exports=require(3)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/events.js":3}],126:[function(require,module,exports){
module.exports=require(4)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/fn.js":4}],127:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],128:[function(require,module,exports){
module.exports=require(6)
},{"./lib/dom":124,"./lib/events":125,"./lib/fn":126,"./lib/url":127,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],129:[function(require,module,exports){
'use strict';

var RPC_METHOD_NAMES = ['getCreditCards', 'unlockCreditCard', 'sendAnalyticsEvents'];

function APIProxyServer(apiClient) {
  this.apiClient = apiClient;
}

APIProxyServer.prototype.attach = function (rpcServer) {
  var self = this;
  var i = 0;
  var len = RPC_METHOD_NAMES.length;

  function attachDefine(name) {
    rpcServer.define(name, function () {
      self.apiClient[name].apply(self.apiClient, arguments);
    });
  }

  for (i; i < len; i++) {
    attachDefine(RPC_METHOD_NAMES[i]);
  }
};

module.exports = APIProxyServer;

},{}],130:[function(require,module,exports){
'use strict';

var htmlNode, bodyNode;
var api = require('braintree-api');
var rpc = require('braintree-rpc');
var utils = require('braintree-utilities');
var APIProxyServer = require('./api-proxy-server');
var MerchantFormManager = require('./merchant-form-manager');
var FrameContainer = require('./frame-container');
var PayPalService = require('../shared/paypal-service');
var paypalBrowser = require('braintree-paypal/src/shared/util/browser');
var version = "1.1.9";

function getElementStyle(element, style) {
  var computedStyle = window.getComputedStyle ? getComputedStyle(element) : element.currentStyle;

  return computedStyle[style];
}

function getMerchantPageDefaultStyles() {
  return {
    html: {
      height: htmlNode.style.height || '',
      overflow: getElementStyle(htmlNode, 'overflow'),
      position: getElementStyle(htmlNode, 'position')
    },
    body: {
      height: bodyNode.style.height || '',
      overflow: getElementStyle(bodyNode, 'overflow')
    }
  };
}

function isMobile() {
  var isMobileUserAgent = /Android|iPhone|iPod|iPad/i.test(window.navigator.userAgent);
  return isMobileUserAgent;
}

function Client(settings) {
  var inlineFramePath, modalFramePath, formElement;

  this.encodedClientToken = settings.clientToken;
  this.paypalOptions = settings.paypal;
  this.container = null;
  this.merchantFormManager = null;
  this.root = settings.root;
  this.configurationRequests = [];
  this.braintreeApiClient = api.configure({ clientToken: settings.clientToken, integration: 'dropin' });
  this.paymentMethodNonceReceivedCallback = settings.paymentMethodNonceReceived;
  this.clientToken = api.parseClientToken(settings.clientToken);

  this.bus = new rpc.MessageBus(this.root);
  this.rpcServer = new rpc.RPCServer(this.bus);
  this.apiProxyServer = new APIProxyServer(this.braintreeApiClient);

  this.apiProxyServer.attach(this.rpcServer);

  inlineFramePath = settings.inlineFramePath || this.clientToken.assetsUrl + '/dropin/' + version + '/inline-frame.html';
  modalFramePath = settings.modalFramePath || this.clientToken.assetsUrl + '/dropin/' + version + '/modal-frame.html';
  htmlNode = document.documentElement;
  bodyNode = document.body;

  this.frames = {
    inline: this._createFrame(inlineFramePath),
    modal: this._createFrame(modalFramePath)
  };

  this.container = utils.normalizeElement(settings.container, 'Unable to find valid container.');

  formElement = utils.normalizeElement(settings.form || this._findClosest(this.container, 'form'));

  this.merchantFormManager = new MerchantFormManager({
    form: formElement,
    frames: this.frames,
    onSubmit: this.paymentMethodNonceReceivedCallback,
    apiClient: this.braintreeApiClient
  }).initialize();

  if (this.clientToken.paypalEnabled && (this.clientToken.paypal && (utils.isBrowserHttps() || this.clientToken.paypal.allowHttp))) {
    this._configurePayPal();
  }

  this.braintreeApiClient.sendAnalyticsEvents('dropin.web.initialized');
}

Client.prototype.initialize = function () {
  var self = this;

  this._initializeModal();

  this.container.appendChild(this.frames.inline.element);
  bodyNode.appendChild(this.frames.modal.element);

  this.rpcServer.define('receiveSharedCustomerIdentifier', function (sharedCustomerIdentifier) {
    self.braintreeApiClient.attrs.sharedCustomerIdentifier = sharedCustomerIdentifier;
    self.braintreeApiClient.attrs.sharedCustomerIdentifierType = 'browser_session_cookie_store';

    for (var i = 0; i < self.configurationRequests.length; i++) {
      self.configurationRequests[i](self.encodedClientToken);
    }

    self.configurationRequests = [];
  });

  this.rpcServer.define('getConfiguration', function (reply) {
    reply({
      clientToken: self.encodedClientToken,
      merchantHttps: utils.isBrowserHttps()
    });
  });

  this.rpcServer.define('getPayPalOptions', function (reply) {
    reply(self.paypalOptions);
  });

  this.rpcServer.define('selectPaymentMethod', function (paymentMethods) {
    self.frames.modal.rpcClient.invoke('selectPaymentMethod', [paymentMethods]);
    self._showModal();
  });

  this.rpcServer.define('sendAddedPaymentMethod', function (paymentMethod) {
    self.merchantFormManager.setNoncePayload({ nonce: paymentMethod.nonce });
    self.frames.inline.rpcClient.invoke('receiveNewPaymentMethod', [paymentMethod]);
  });

  this.rpcServer.define('sendUsedPaymentMethod', function (paymentMethod) {
    self.frames.inline.rpcClient.invoke('selectPaymentMethod', [paymentMethod]);
  });

  this.rpcServer.define('sendUnlockedNonce', function (nonce) {
    self.merchantFormManager.setNoncePayload({ nonce: nonce });
  });

  this.rpcServer.define('clearNonce', function () {
    self.merchantFormManager.clearNoncePayload();
  });

  this.rpcServer.define('closeDropInModal', function () {
    self._hideModal();
  });

  this.rpcServer.define('setInlineFrameHeight', function (height) {
    self.frames.inline.element.style.height = height + 'px';
  });

  this.bus.register('ready', function (message) {
    if (message.source === self.frames.inline.element.contentWindow) {
      self.frames.inline.rpcClient = new rpc.RPCClient(self.bus, message.source);
    } else if (message.source === self.frames.modal.element.contentWindow) {
      self.frames.modal.rpcClient = new rpc.RPCClient(self.bus, message.source);
    }
  });
};

Client.prototype._createFrame = function (endpoint) {
  return new FrameContainer(endpoint);
};

Client.prototype._initializeModal = function () {
  this.frames.modal.element.style.display = 'none';
  this.frames.modal.element.style.position = isMobile() ? 'absolute' : 'fixed';
  this.frames.modal.element.style.top = '0';
  this.frames.modal.element.style.left = '0';
  this.frames.modal.element.style.height = '100%';
  this.frames.modal.element.style.width = '100%';
};

Client.prototype._lockMerchantWindowSize = function () {
  setTimeout(function () {
    htmlNode.style.overflow = 'hidden';
    bodyNode.style.overflow = 'hidden';
    bodyNode.style.height = '100%';

    if (isMobile()) {
      htmlNode.style.position = 'relative';
      htmlNode.style.height = window.innerHeight + 'px';
    }
  }, 160);
};

Client.prototype._unlockMerchantWindowSize = function () {
  var defaultStyles = this.merchantPageDefaultStyles;

  bodyNode.style.height = defaultStyles.body.height;
  bodyNode.style.overflow = defaultStyles.body.overflow;

  htmlNode.style.overflow = defaultStyles.html.overflow;

  if (isMobile()) {
    htmlNode.style.height = defaultStyles.html.height;
    htmlNode.style.position = defaultStyles.html.position;
  }
};

Client.prototype._showModal = function () {
  var self = this;
  var el = this.frames.modal.element;

  this.merchantPageDefaultStyles = getMerchantPageDefaultStyles();

  el.style.display = 'block';

  this.frames.modal.rpcClient.invoke('open', [], function () {
    setTimeout(function () {
      self._lockMerchantWindowSize();
      el.contentWindow.focus();
    }, 200);
  });
};

Client.prototype._hideModal = function () {
  this._unlockMerchantWindowSize();
  this.frames.modal.element.style.display = 'none';
};

Client.prototype._configurePayPal = function () {
  if (!paypalBrowser.isPopupSupported()) {
    this.ppClient = new PayPalService({
      clientToken: this.clientToken,
      paypal: this.paypalOptions
    });

    this.rpcServer.define('openPayPalModal', utils.bind(this.ppClient._openModal, this.ppClient));
  }

  this.rpcServer.define('receivePayPalData', utils.bind(this._handlePayPalData, this));
};

Client.prototype._handlePayPalData = function (payload) {
  this.merchantFormManager.setNoncePayload(payload);
  this.frames.inline.rpcClient.invoke('receiveNewPaymentMethod', [payload]);
  this.frames.modal.rpcClient.invoke('paypalViewClose');
};

Client.prototype._findClosest = function (node, tagName) {
  tagName = tagName.toUpperCase();

  do {
    if (node.nodeName === tagName) {
      return node;
    }
  } while (node = node.parentNode);

  throw 'Unable to find a valid ' + tagName;
};

module.exports = Client;

},{"../shared/paypal-service":134,"./api-proxy-server":129,"./frame-container":132,"./merchant-form-manager":133,"braintree-api":52,"braintree-paypal/src/shared/util/browser":110,"braintree-rpc":118,"braintree-utilities":128}],131:[function(require,module,exports){
'use strict';

var Client = require('./client');
var VERSION = "1.1.9";

function create(clientToken, options) {
  options.clientToken = clientToken;
  var client = new Client(options);

  client.initialize();

  return client;
}

module.exports = {
  create: create,
  VERSION: VERSION
};

},{"./client":130}],132:[function(require,module,exports){
'use strict';

function FrameContainer(endpoint) {
  this.element = document.createElement('iframe');
  this.element.setAttribute('allowtransparency', 'true');
  this.element.setAttribute('width', '100%');
  this.element.setAttribute('height', '68');
  this.element.setAttribute('style', '-webkit-transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000); -moz-transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000); -ms-transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000); -o-transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000); transition: height 210ms cubic-bezier(0.390, 0.575, 0.565, 1.000);');
  this.element.src = endpoint;

  this.element.setAttribute('frameborder', '0');
  this.element.setAttribute('allowtransparency', 'true');
  this.element.style.border = '0';
  this.element.style.zIndex = '9999';
}

module.exports = FrameContainer;

},{}],133:[function(require,module,exports){
'use strict';

var utils = require('braintree-utilities');

function MerchantFormManager(options) {
  this.form = options.form;
  this.frames = options.frames;
  this.onSubmit = options.onSubmit;
  this.apiClient = options.apiClient;
}

MerchantFormManager.prototype.initialize = function () {
  if (this._isSubmitBased()) {
    this._setElements();
  }

  this._setEvents();

  return this;
};

MerchantFormManager.prototype.setNoncePayload = function (payload) {
  this.noncePayload = payload;
};

MerchantFormManager.prototype.clearNoncePayload = function () {
  this.noncePayload = null;
};

MerchantFormManager.prototype._isSubmitBased = function () {
  return !this.onSubmit;
};

MerchantFormManager.prototype._isCallbackBased = function () {
  return !!this.onSubmit;
};

MerchantFormManager.prototype._setElements = function () {
  if (!this.form.payment_method_nonce) {
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'payment_method_nonce';
    this.form.appendChild(input);
  }

  this.nonceField = this.form.payment_method_nonce;
};

MerchantFormManager.prototype._setEvents = function () {
  var self = this;

  utils.addEventListener(this.form, 'submit', function () {
    self._handleFormSubmit.apply(self, arguments);
  });
};

MerchantFormManager.prototype._handleFormSubmit = function (event) {
  if (this._shouldSubmit()) { return; }

  if (event && event.preventDefault) {
    event.preventDefault();
  } else {
    event.returnValue = false;
  }

  if (this.noncePayload && this.noncePayload.nonce) {
    this._handleNonceReply(event);
  } else {
    this.frames.inline.rpcClient.invoke('requestNonce', [], utils.bind(function (nonce) {
      this.setNoncePayload({ nonce: nonce });
      this._handleNonceReply(event);
    }, this));
  }
};

MerchantFormManager.prototype._shouldSubmit = function () {
  return this._isCallbackBased() ? false : this.nonceField.value.length > 0;
};

MerchantFormManager.prototype._handleNonceReply = function (event) {
  if (this._isCallbackBased()) {
    this.apiClient.sendAnalyticsEvents('dropin.web.end.callback', utils.bind(function () {
      var payload = this.noncePayload;

      payload.originalEvent = event;

      this.onSubmit(payload);

      setTimeout(utils.bind(function () {
        this.frames.inline.rpcClient.invoke('clearLoadingState');
      }, this), 200);
    }, this));
  } else {
    this._triggerFormSubmission();
  }
};

MerchantFormManager.prototype._triggerFormSubmission = function () {
  this.nonceField.value = this.noncePayload.nonce;

  this.apiClient.sendAnalyticsEvents('dropin.web.end.auto-submit', utils.bind(function () {
    if (typeof this.form.submit === 'function') {
      this.form.submit();
    } else {
      this.form.querySelector('[type="submit"]').click();
    }
  }, this));
};

module.exports = MerchantFormManager;

},{"braintree-utilities":128}],134:[function(require,module,exports){
'use strict';

var PaypalClient = require('braintree-paypal/src/external/client');

function PayPalService(options) {
  var clientToken = options.clientToken;
  var paypalOptions = options.paypal || {};

  // TODO: use module when ready
  var client = new PaypalClient(clientToken, {
    container: document.createElement('div'),
    displayName: paypalOptions.displayName,
    locale: paypalOptions.locale,
    singleUse: paypalOptions.singleUse,
    onSuccess: paypalOptions.onSuccess,
    enableShippingAddress: paypalOptions.enableShippingAddress
  });

  client.initialize();

  return client;
}

module.exports = PayPalService;

},{"braintree-paypal/src/external/client":102}],135:[function(require,module,exports){
'use strict';

function getNonceInput(paymentMethodNonceInputField) {
  if (typeof paymentMethodNonceInputField === 'object') {
    return paymentMethodNonceInputField;
  }

  var nonceInputName = 'payment_method_nonce';

  if (typeof paymentMethodNonceInputField === 'string') {
    nonceInputName = paymentMethodNonceInputField;
  }

  var nonceInput = document.createElement('input');
  nonceInput.name = nonceInputName;
  nonceInput.type = 'hidden';

  return nonceInput;
}

function validateAnnotations(htmlForm) {
  var inputs = htmlForm.getElementsByTagName('*');
  var valid = {};

  for (var i = 0; i < inputs.length; i++) {
    var field = inputs[i].getAttribute('data-braintree-name');
    valid[field] = true;
  }

  if (!valid.number) {
    throw 'Unable to find an input with data-braintree-name="number" in your form. Please add one.';
  }

  if (valid.expiration_date) {
    if (valid.expiration_month || valid.expiration_year) {
      throw 'You have inputs with data-braintree-name="expiration_date" AND data-braintree-name="expiration_(year|month)". Please use either "expiration_date" or "expiration_year" and "expiration_month".';
    }
  } else {
    if (!valid.expiration_month && !valid.expiration_year) {
      throw 'Unable to find an input with data-braintree-name="expiration_date" in your form. Please add one.';
    }

    if (!valid.expiration_month) {
      throw 'Unable to find an input with data-braintree-name="expiration_month" in your form. Please add one.';
    }

    if (!valid.expiration_year) {
      throw 'Unable to find an input with data-braintree-name="expiration_year" in your form. Please add one.';
    }
  }
}

function Form(client, htmlForm, nonceInput) {
  this.client = client;
  this.htmlForm = htmlForm;
  this.paymentMethodNonce = nonceInput;
}

Form.setup = function (client, options) {
  var htmlForm = document.getElementById(options.id);

  if (!htmlForm) {
    throw 'Unable to find form with id: "' + options.id + '"';
  }

  validateAnnotations(htmlForm);

  var nonceInput = getNonceInput(options.paymentMethodNonceInputField);
  htmlForm.appendChild(nonceInput);

  var form = new Form(client, htmlForm, nonceInput);
  form.hijackForm();

  return form;
};

Form.prototype.registerAsyncTaskOnSubmit = function (form, asyncTask) {
  function onsubmitHandler(event) {
    if (event.preventDefault) {
      event.preventDefault();
    } else {
      event.returnValue = false;
    }

    asyncTask(function callNativeFormSubmit() {
      stopListening();

      if (form.submit && (typeof form.submit === 'function' || form.submit.call)) {
        form.submit();
      } else {
        setTimeout(function () {
          form.querySelector('[type="submit"]').click();
        }, 1);
      }
    });
  }

  function listen() {
    if (form.addEventListener) {
      form.addEventListener('submit', onsubmitHandler); //, false);
    } else if (form.attachEvent) {
      form.attachEvent('onsubmit', onsubmitHandler);
    }
  }

  function stopListening() {
    if (form.removeEventListener) {
      form.removeEventListener('submit', onsubmitHandler); //, false);
    } else if (form.detachEvent) {
      form.detachEvent('onsubmit', onsubmitHandler);
    }
  }

  listen();
};

Form.prototype.hijackForm = function () {
  var self = this;
  this.registerAsyncTaskOnSubmit(this.htmlForm, function (submitForm) {
    if (self.paymentMethodNonce.value && self.paymentMethodNonce.value !== '') {
      submitForm();
      return;
    }

    self.client.tokenizeCard(self.extractValues(self.htmlForm), function (err, paymentMethodNonce) {
      if (err) {
        throw 'Unable to process payments at this time.';
      }

      self.paymentMethodNonce.value = paymentMethodNonce;
      submitForm();
    });
  });
};

Form.prototype.extractValues = function (node, results) {
  results = results || {};
  var child, i;
  var children = node.children;

  for (i = 0; i < children.length; i++) {
    child = children[i];

    if (child.nodeType === 1 && child.attributes['data-braintree-name']) {
      var dataAttr = child.getAttribute('data-braintree-name');

      if (dataAttr === 'postal_code') {
        results.billingAddress = {
          postalCode: child.value
        };
      } else {
        results[dataAttr] = child.value;
      }

      this.scrubAttributes(child);
    } else if (child.children && child.children.length > 0) {
      this.extractValues(child, results);
    }
  }

  return results;
};

Form.prototype.scrubAttributes = function (node) {
  try {
    node.attributes.removeNamedItem('name');
  } catch (e) {}
};

module.exports = Form;

},{}],136:[function(require,module,exports){
module.exports=require(42)
},{"./credit-card":137,"./jsonp-driver":138,"./parse-client-token":140,"./root-data":142,"./sepa-bank-account":143,"./sepa-mandate":144,"./util":145,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/client.js":42}],137:[function(require,module,exports){
module.exports=require(14)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/credit-card.js":14}],138:[function(require,module,exports){
arguments[4][15][0].apply(exports,arguments)
},{"./jsonp":139,"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/jsonp-driver.js":15}],139:[function(require,module,exports){
module.exports=require(45)
},{"./util":145,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/jsonp.js":45}],140:[function(require,module,exports){
arguments[4][18][0].apply(exports,arguments)
},{"./polyfill":141,"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/parse-client-token.js":18}],141:[function(require,module,exports){
module.exports=require(47)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/polyfill.js":47}],142:[function(require,module,exports){
module.exports=require(48)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/root-data.js":48,"braintree-rpc":152}],143:[function(require,module,exports){
module.exports=require(21)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/sepa-bank-account.js":21}],144:[function(require,module,exports){
module.exports=require(22)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/lib/sepa-mandate.js":22}],145:[function(require,module,exports){
module.exports=require(51)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-api/lib/util.js":51}],146:[function(require,module,exports){
arguments[4][24][0].apply(exports,arguments)
},{"./lib/client":136,"./lib/jsonp":139,"./lib/jsonp-driver":138,"./lib/parse-client-token":140,"./lib/util":145,"/home/pair/bt/braintree.js/node_modules/braintree-api/main.js":24}],147:[function(require,module,exports){
module.exports=require(25)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/message-bus.js":25,"braintree-utilities":157}],148:[function(require,module,exports){
module.exports=require(26)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-client.js":26,"braintree-utilities":157}],149:[function(require,module,exports){
module.exports=require(27)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-server.js":27}],150:[function(require,module,exports){
module.exports=require(28)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-client.js":28,"braintree-utilities":157}],151:[function(require,module,exports){
module.exports=require(29)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-server.js":29,"braintree-utilities":157}],152:[function(require,module,exports){
module.exports=require(30)
},{"./lib/message-bus":147,"./lib/pubsub-client":148,"./lib/pubsub-server":149,"./lib/rpc-client":150,"./lib/rpc-server":151,"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/main.js":30}],153:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],154:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],155:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],156:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],157:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":153,"./lib/events":154,"./lib/fn":155,"./lib/url":156,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],158:[function(require,module,exports){
module.exports=require(25)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/message-bus.js":25,"braintree-utilities":168}],159:[function(require,module,exports){
module.exports=require(26)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-client.js":26,"braintree-utilities":168}],160:[function(require,module,exports){
module.exports=require(27)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-server.js":27}],161:[function(require,module,exports){
module.exports=require(28)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-client.js":28,"braintree-utilities":168}],162:[function(require,module,exports){
module.exports=require(29)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-server.js":29,"braintree-utilities":168}],163:[function(require,module,exports){
module.exports=require(30)
},{"./lib/message-bus":158,"./lib/pubsub-client":159,"./lib/pubsub-server":160,"./lib/rpc-client":161,"./lib/rpc-server":162,"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/main.js":30}],164:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],165:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],166:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],167:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],168:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":164,"./lib/events":165,"./lib/fn":166,"./lib/url":167,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],169:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],170:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],171:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],172:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],173:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":169,"./lib/events":170,"./lib/fn":171,"./lib/url":172,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],174:[function(require,module,exports){
module.exports=require(102)
},{"../shared/constants":178,"../shared/util/browser":183,"../shared/util/dom":184,"../shared/util/util":185,"./logged-in-view":176,"./logged-out-view":177,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/external/client.js":102,"braintree-api":146,"braintree-rpc":163,"braintree-utilities":173}],175:[function(require,module,exports){
var Client = require('./client');
var browser = require('../shared/util/browser');
var VERSION = "1.2.1";

function create(clientToken, options) {
  if (!browser.detectedPostMessage()) {
    if (typeof options.onUnsupported === 'function') {
      options.onUnsupported(new Error('unsupported browser detected'));
    }
    return;
  }
  var client = new Client(clientToken, options);
  client.initialize();
  return client;
}

module.exports = {
  create: create,
  _browser: browser,
  VERSION: VERSION
};

},{"../shared/util/browser":183,"./client":174}],176:[function(require,module,exports){
module.exports=require(103)
},{"../shared/constants":178,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/external/logged-in-view.js":103}],177:[function(require,module,exports){
module.exports=require(104)
},{"../shared/constants":178,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/external/logged-out-view.js":104}],178:[function(require,module,exports){
module.exports=require(105)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/shared/constants.js":105}],179:[function(require,module,exports){
module.exports=require(106)
},{"./useragent":182,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/shared/useragent/browser.js":106}],180:[function(require,module,exports){
module.exports=require(107)
},{"./platform":181,"./useragent":182,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/shared/useragent/device.js":107}],181:[function(require,module,exports){
module.exports=require(108)
},{"./useragent":182,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/shared/useragent/platform.js":108}],182:[function(require,module,exports){
module.exports=require(109)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/shared/useragent/useragent.js":109}],183:[function(require,module,exports){
module.exports=require(110)
},{"../useragent/browser":179,"../useragent/device":180,"../useragent/platform":181,"../useragent/useragent":182,"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/shared/util/browser.js":110}],184:[function(require,module,exports){
module.exports=require(111)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/shared/util/dom.js":111}],185:[function(require,module,exports){
module.exports=require(112)
},{"/home/pair/bt/braintree.js/node_modules/braintree-dropin/node_modules/braintree-paypal/src/shared/util/util.js":112}],186:[function(require,module,exports){
module.exports=require(25)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/message-bus.js":25,"braintree-utilities":196}],187:[function(require,module,exports){
module.exports=require(26)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-client.js":26,"braintree-utilities":196}],188:[function(require,module,exports){
module.exports=require(27)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/pubsub-server.js":27}],189:[function(require,module,exports){
module.exports=require(28)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-client.js":28,"braintree-utilities":196}],190:[function(require,module,exports){
module.exports=require(29)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/lib/rpc-server.js":29,"braintree-utilities":196}],191:[function(require,module,exports){
module.exports=require(30)
},{"./lib/message-bus":186,"./lib/pubsub-client":187,"./lib/pubsub-server":188,"./lib/rpc-client":189,"./lib/rpc-server":190,"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/main.js":30}],192:[function(require,module,exports){
module.exports=require(31)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/dom.js":31}],193:[function(require,module,exports){
module.exports=require(32)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/events.js":32}],194:[function(require,module,exports){
module.exports=require(33)
},{"/home/pair/bt/braintree.js/node_modules/braintree-api/node_modules/braintree-rpc/node_modules/braintree-utilities/lib/fn.js":33}],195:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],196:[function(require,module,exports){
arguments[4][6][0].apply(exports,arguments)
},{"./lib/dom":192,"./lib/events":193,"./lib/fn":194,"./lib/url":195,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],197:[function(require,module,exports){
module.exports=require(2)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/dom.js":2}],198:[function(require,module,exports){
module.exports=require(3)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/events.js":3}],199:[function(require,module,exports){
module.exports=require(4)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/fn.js":4}],200:[function(require,module,exports){
module.exports=require(5)
},{"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/lib/url.js":5}],201:[function(require,module,exports){
module.exports=require(6)
},{"./lib/dom":197,"./lib/events":198,"./lib/fn":199,"./lib/url":200,"/home/pair/bt/braintree.js/node_modules/braintree-3ds/node_modules/braintree-utilities/main.js":6}],202:[function(require,module,exports){
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

function EventEmitter() {
  this._events = this._events || {};
  this._maxListeners = this._maxListeners || undefined;
}
module.exports = EventEmitter;

// Backwards-compat with node 0.10.x
EventEmitter.EventEmitter = EventEmitter;

EventEmitter.prototype._events = undefined;
EventEmitter.prototype._maxListeners = undefined;

// By default EventEmitters will print a warning if more than 10 listeners are
// added to it. This is a useful default which helps finding memory leaks.
EventEmitter.defaultMaxListeners = 10;

// Obviously not all Emitters should be limited to 10. This function allows
// that to be increased. Set to zero for unlimited.
EventEmitter.prototype.setMaxListeners = function(n) {
  if (!isNumber(n) || n < 0 || isNaN(n))
    throw TypeError('n must be a positive number');
  this._maxListeners = n;
  return this;
};

EventEmitter.prototype.emit = function(type) {
  var er, handler, len, args, i, listeners;

  if (!this._events)
    this._events = {};

  // If there is no 'error' event listener then throw.
  if (type === 'error') {
    if (!this._events.error ||
        (isObject(this._events.error) && !this._events.error.length)) {
      er = arguments[1];
      if (er instanceof Error) {
        throw er; // Unhandled 'error' event
      }
      throw TypeError('Uncaught, unspecified "error" event.');
    }
  }

  handler = this._events[type];

  if (isUndefined(handler))
    return false;

  if (isFunction(handler)) {
    switch (arguments.length) {
      // fast cases
      case 1:
        handler.call(this);
        break;
      case 2:
        handler.call(this, arguments[1]);
        break;
      case 3:
        handler.call(this, arguments[1], arguments[2]);
        break;
      // slower
      default:
        len = arguments.length;
        args = new Array(len - 1);
        for (i = 1; i < len; i++)
          args[i - 1] = arguments[i];
        handler.apply(this, args);
    }
  } else if (isObject(handler)) {
    len = arguments.length;
    args = new Array(len - 1);
    for (i = 1; i < len; i++)
      args[i - 1] = arguments[i];

    listeners = handler.slice();
    len = listeners.length;
    for (i = 0; i < len; i++)
      listeners[i].apply(this, args);
  }

  return true;
};

EventEmitter.prototype.addListener = function(type, listener) {
  var m;

  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events)
    this._events = {};

  // To avoid recursion in the case that type === "newListener"! Before
  // adding it to the listeners, first emit "newListener".
  if (this._events.newListener)
    this.emit('newListener', type,
              isFunction(listener.listener) ?
              listener.listener : listener);

  if (!this._events[type])
    // Optimize the case of one listener. Don't need the extra array object.
    this._events[type] = listener;
  else if (isObject(this._events[type]))
    // If we've already got an array, just append.
    this._events[type].push(listener);
  else
    // Adding the second element, need to change to array.
    this._events[type] = [this._events[type], listener];

  // Check for listener leak
  if (isObject(this._events[type]) && !this._events[type].warned) {
    var m;
    if (!isUndefined(this._maxListeners)) {
      m = this._maxListeners;
    } else {
      m = EventEmitter.defaultMaxListeners;
    }

    if (m && m > 0 && this._events[type].length > m) {
      this._events[type].warned = true;
      console.error('(node) warning: possible EventEmitter memory ' +
                    'leak detected. %d listeners added. ' +
                    'Use emitter.setMaxListeners() to increase limit.',
                    this._events[type].length);
      if (typeof console.trace === 'function') {
        // not supported in IE 10
        console.trace();
      }
    }
  }

  return this;
};

EventEmitter.prototype.on = EventEmitter.prototype.addListener;

EventEmitter.prototype.once = function(type, listener) {
  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  var fired = false;

  function g() {
    this.removeListener(type, g);

    if (!fired) {
      fired = true;
      listener.apply(this, arguments);
    }
  }

  g.listener = listener;
  this.on(type, g);

  return this;
};

// emits a 'removeListener' event iff the listener was removed
EventEmitter.prototype.removeListener = function(type, listener) {
  var list, position, length, i;

  if (!isFunction(listener))
    throw TypeError('listener must be a function');

  if (!this._events || !this._events[type])
    return this;

  list = this._events[type];
  length = list.length;
  position = -1;

  if (list === listener ||
      (isFunction(list.listener) && list.listener === listener)) {
    delete this._events[type];
    if (this._events.removeListener)
      this.emit('removeListener', type, listener);

  } else if (isObject(list)) {
    for (i = length; i-- > 0;) {
      if (list[i] === listener ||
          (list[i].listener && list[i].listener === listener)) {
        position = i;
        break;
      }
    }

    if (position < 0)
      return this;

    if (list.length === 1) {
      list.length = 0;
      delete this._events[type];
    } else {
      list.splice(position, 1);
    }

    if (this._events.removeListener)
      this.emit('removeListener', type, listener);
  }

  return this;
};

EventEmitter.prototype.removeAllListeners = function(type) {
  var key, listeners;

  if (!this._events)
    return this;

  // not listening for removeListener, no need to emit
  if (!this._events.removeListener) {
    if (arguments.length === 0)
      this._events = {};
    else if (this._events[type])
      delete this._events[type];
    return this;
  }

  // emit removeListener for all listeners on all events
  if (arguments.length === 0) {
    for (key in this._events) {
      if (key === 'removeListener') continue;
      this.removeAllListeners(key);
    }
    this.removeAllListeners('removeListener');
    this._events = {};
    return this;
  }

  listeners = this._events[type];

  if (isFunction(listeners)) {
    this.removeListener(type, listeners);
  } else {
    // LIFO order
    while (listeners.length)
      this.removeListener(type, listeners[listeners.length - 1]);
  }
  delete this._events[type];

  return this;
};

EventEmitter.prototype.listeners = function(type) {
  var ret;
  if (!this._events || !this._events[type])
    ret = [];
  else if (isFunction(this._events[type]))
    ret = [this._events[type]];
  else
    ret = this._events[type].slice();
  return ret;
};

EventEmitter.listenerCount = function(emitter, type) {
  var ret;
  if (!emitter._events || !emitter._events[type])
    ret = 0;
  else if (isFunction(emitter._events[type]))
    ret = 1;
  else
    ret = emitter._events[type].length;
  return ret;
};

function isFunction(arg) {
  return typeof arg === 'function';
}

function isNumber(arg) {
  return typeof arg === 'number';
}

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}

function isUndefined(arg) {
  return arg === void 0;
}

},{}],203:[function(require,module,exports){
'use strict';

module.exports = {
  'NONCE_RECEIVED': 'NONCE_RECEIVED',
  'ROOT_CALLBACK': 'onPaymentMethodReceived'
};

},{}],204:[function(require,module,exports){
'use strict';

var EventEmitter = require('events').EventEmitter;

module.exports = new EventEmitter();

},{"events":202}],205:[function(require,module,exports){
'use strict';

var api = require('braintree-api');
var form = require('braintree-form');
var paypal = require('braintree-paypal');
var utils = require('braintree-utilities');

function _getLegacyCallback(options) {
  if ('paypal' in options && utils.isFunction(options.paypal.onSuccess)){
    return options.paypal.onSuccess;
  } else {
    return null;
  }
}

function initialize(clientToken, options) {
  var legacyCallback = _getLegacyCallback(options);
  var formIntegration;
  var apiClient = new api.Client({
    clientToken: clientToken,
    integration: 'custom'
  });

  formIntegration = form.setup(apiClient, options);

  if (options.paypal) {
    if (!options.paypal.paymentMethodNonceInputField) {
      options.paypal.paymentMethodNonceInputField = formIntegration.paymentMethodNonce;
    }

    if (legacyCallback) {
      options.paypal.onSuccess = function (payload) {
        legacyCallback.apply(null, [payload.nonce, payload.email, payload.shippingAddress]);
      }
    }

    paypal.create(clientToken, options.paypal);
  }

  return formIntegration;
};

module.exports = { initialize: initialize };

},{"braintree-api":24,"braintree-form":135,"braintree-paypal":175,"braintree-utilities":201}],206:[function(require,module,exports){
'use strict';

var dropin = require('braintree-dropin');
var utils = require('braintree-utilities');
var EventBus = require('../event-bus');
var constants = require('../constants');

function _getLegacyCallback(options) {
  if (utils.isFunction(options.paymentMethodNonceReceived)) {
    return options.paymentMethodNonceReceived;
  } else {
    return null;
  }
}

function _hasRootCallback(options) {
  return utils.isFunction(options[constants.ROOT_CALLBACK]);
}

function initialize(clientToken, options) {
  var legacyCallback = _getLegacyCallback(options);
  var rootCallback = _hasRootCallback(options);

  if (legacyCallback || rootCallback) {
    options.paymentMethodNonceReceived = function (payload) {
      if (legacyCallback) {
        legacyCallback.apply(null, [ payload.originalEvent, payload.nonce ]);
      }

      EventBus.emit(constants.NONCE_RECEIVED, null, payload);
    };
  }

  return dropin.create(clientToken, options);
}

module.exports = { initialize: initialize };

},{"../constants":203,"../event-bus":204,"braintree-dropin":131,"braintree-utilities":201}],207:[function(require,module,exports){
'use strict';

module.exports = {
  custom: require('./custom'),
  dropin: require('./dropin'),
  paypal: require('./paypal')
};

},{"./custom":205,"./dropin":206,"./paypal":208}],208:[function(require,module,exports){
'use strict';

var paypal = require('braintree-paypal');
var utils = require('braintree-utilities');
var EventBus = require('../event-bus');
var constants = require('../constants');

function _getLegacyCallback(options) {
  if ('onSuccess' in options && utils.isFunction(options.onSuccess)) {
    return options.onSuccess;
  } else if ('paypal' in options && utils.isFunction(options.paypal.onSuccess)){
    return options.paypal.onSuccess;
  } else {
    return null;
  }
}

function _hasRootCallback(options) {
  return utils.isFunction(options[constants.ROOT_CALLBACK]);
}

function initialize(clientToken, options) {
  var legacyCallback = _getLegacyCallback(options);
  var rootCallback = _hasRootCallback(options);

  if (legacyCallback || rootCallback) {
    options.onSuccess = function (payload) {
      if (legacyCallback) {
        legacyCallback.apply(null, [payload.nonce, payload.email, payload.shippingAddress]);
      }

      EventBus.emit(constants.NONCE_RECEIVED, null, payload);
    }
  }

  return paypal.create(clientToken, options);
}

module.exports = { initialize: initialize };

},{"../constants":203,"../event-bus":204,"braintree-paypal":175,"braintree-utilities":201}],209:[function(require,module,exports){
(function (global){
'use strict';

var VERSION = '2.3.3';
var rpc = require('braintree-rpc');
var bus = new rpc.MessageBus(global);
var rpcServer = new rpc.RPCServer(bus);

module.exports = function _listen() {
  rpcServer.define('getExternalData', function (reply) {
    reply({
      sdkVersion: VERSION,
      merchantAppId: global.location.href
    });
  });
};

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"braintree-rpc":191}],210:[function(require,module,exports){
'use strict';

var VERSION = '2.3.3';
var api = require('braintree-api');
var paypal = require('braintree-paypal');
var dropin = require('braintree-dropin');
var Form = require('braintree-form');
var utils = require('braintree-utilities');
var integrations = require('./integrations');
var EventBus = require('./event-bus');
var constants = require('./constants');

function setup(clientToken, integration, options) {
  if (integration in integrations) {
    if (utils.isFunction(options[constants.ROOT_CALLBACK])) {
      EventBus.on(constants.NONCE_RECEIVED, function () {
        options[constants.ROOT_CALLBACK].apply(null, arguments);
      });
    }

    return integrations[integration].initialize(clientToken, options);
  } else {
    throw new Error(integration + ' is an unsupported integration');
  }
};

module.exports = {
  api: api,
  cse: Braintree,
  paypal: paypal,
  dropin: dropin,
  Form: Form,
  setup: setup,
  VERSION: VERSION
};

},{"./constants":203,"./event-bus":204,"./integrations":207,"braintree-api":24,"braintree-dropin":131,"braintree-form":135,"braintree-paypal":175,"braintree-utilities":201}]},{},[1])(1)
});