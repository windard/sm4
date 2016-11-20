/*! sm3-sm2-1.0.js (c) Jonllen Peng | http://www.jonllen.com/
 */
/*
 * sm3-sm2-1.0.js
 * 
 * Copyright (c) 2014 Jonllen Peng (www.jonllen.com)
 */
/**
 * @fileOverview
 * @name sm3-sm2-1.0.js
 * @author Jonllen (www.jonllen.com)
 * @version 1.0.0 (2014-06-18)
 */

if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

/**
 * class for SM2 key generation,  sm3WithSM2 signing and verifcation
 * @name KJUR.crypto.SM3withSM2
 * @class class for SM2 key generation,  SM2 signing and verifcation
 * @description
 * <p>
 * CAUTION: Most of the case, you don't need to use this class except
 * for generating an SM2 key pair. Please use {@link KJUR.crypto.Signature} class instead.
 * </p>
 * <p>
 * This class was originally developped by Stefan Thomas for Bitcoin JavaScript library.
 * Currently this class supports following named curves and their aliases.
 * <ul>
 * <li>secp256r1, NIST P-256, P-256, prime256v1 (*)</li>
 * <li>secp256k1 (*)</li>
 * <li>secp384r1, NIST P-384, P-384 (*)</li>
  * <li>sm2</li>
 * </ul>
 * </p>
 */
KJUR.crypto.SM3withSM2 = function(params) {
    var curveName = "sm2";	// curve name default
    var ecparams = null;
    var prvKeyHex = null;
    var pubKeyHex = null;

    var rng = new SecureRandom();

    var P_OVER_FOUR = null;

    this.type = "SM2";

    function implShamirsTrick(P, k, Q, l) {
	var m = Math.max(k.bitLength(), l.bitLength());
	var Z = P.add2D(Q);
	var R = P.curve.getInfinity();

	for (var i = m - 1; i >= 0; --i) {
	    R = R.twice2D();

	    R.z = BigInteger.ONE;

	    if (k.testBit(i)) {
		if (l.testBit(i)) {
		    R = R.add2D(Z);
		} else {
		    R = R.add2D(P);
		}
	    } else {
		if (l.testBit(i)) {
		    R = R.add2D(Q);
		}
	    }
	}
	
	return R;
    };

    //===========================
    // PUBLIC METHODS
    //===========================
    this.getBigRandom = function (limit) {
	return new BigInteger(limit.bitLength(), rng)
	.mod(limit.subtract(BigInteger.ONE))
	.add(BigInteger.ONE)
	;
    };

    this.setNamedCurve = function(curveName) {
	this.ecparams = KJUR.crypto.ECParameterDB.getByName(curveName);
	this.prvKeyHex = null;
	this.pubKeyHex = null;
	this.curveName = curveName;
    }

    this.setPrivateKeyHex = function(prvKeyHex) {
        this.isPrivate = true;
	this.prvKeyHex = prvKeyHex;
    }

    this.setPublicKeyHex = function(pubKeyHex) {
        this.isPublic = true;
	this.pubKeyHex = pubKeyHex;
    }

    /**
     * generate a EC key pair
     * @name generateKeyPairHex
     * @memberOf KJUR.crypto.ECDSA
     * @function
     * @return {Array} associative array of hexadecimal string of private and public key
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.ECDSA({'curve': 'sm2'});
     * var keypair = ec.generateKeyPairHex();
     * var pubhex = keypair.ecpubhex; // hexadecimal string of EC private key (=d)
     * var prvhex = keypair.ecprvhex; // hexadecimal string of EC public key
     */
    this.generateKeyPairHex = function() {
	var biN = this.ecparams['n'];
	var biPrv = this.getBigRandom(biN);
	var epPub = this.ecparams['G'].multiply(biPrv);
	var biX = epPub.getX().toBigInteger();
	var biY = epPub.getY().toBigInteger();

	var charlen = this.ecparams['keylen'] / 4;
	var hPrv = ("0000000000" + biPrv.toString(16)).slice(- charlen);
	var hX   = ("0000000000" + biX.toString(16)).slice(- charlen);
	var hY   = ("0000000000" + biY.toString(16)).slice(- charlen);
	var hPub = "04" + hX + hY;

	this.setPrivateKeyHex(hPrv);
	this.setPublicKeyHex(hPub);
	return {'ecprvhex': hPrv, 'ecpubhex': hPub};
    };

    this.signWithMessageHash = function(hashHex) {
	return this.signHex(hashHex, this.prvKeyHex);
    };

    /**
     * signing to message hash
     * @name signHex
     * @memberOf KJUR.crypto.SM3withSM2
     * @function
     * @param {String} hashHex hexadecimal string of hash value of signing message
     * @param {String} privHex hexadecimal string of EC private key
     * @return {String} hexadecimal string of ECDSA signature
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.SM3withSM2({'curve': 'sm2'});
     * var sigValue = ec.signHex(hash, prvKey);
     */
    this.signHex = function (hashHex, privHex) {
	var d = new BigInteger(privHex, 16);
	var n = this.ecparams['n'];
	var e = new BigInteger(hashHex, 16);
	
	// k BigInteger
    var k = null;
    var kp = null;
    var r = null;
    var s = null;
    var userD = d;
    
    do
    {
        do
        {
			
			var keypair = this.generateKeyPairHex();
			
			k = new BigInteger(keypair.ecprvhex, 16);
			var pubkeyHex = keypair.ecpubhex;
			
  			kp = ECPointFp.decodeFromHex(this.ecparams['curve'], pubkeyHex);

            // r
            r = e.add(kp.getX().toBigInteger());
            r = r.mod(n);
        }
        while (r.equals(BigInteger.ZERO) || r.add(k).equals(n));

        // (1 + dA)~-1
        var da_1 = userD.add(BigInteger.ONE);
        da_1 = da_1.modInverse(n);
        // s
        s = r.multiply(userD);
        s = k.subtract(s).mod(n);
        s = da_1.multiply(s).mod(n);
    }
    while (s.equals(BigInteger.ZERO));
    

	return KJUR.crypto.ECDSA.biRSSigToASN1Sig(r, s);
    };

    this.sign = function (hash, priv) {
	var d = priv;
	var n = this.ecparams['n'];
	var e = BigInteger.fromByteArrayUnsigned(hash);

	do {
	    var k = this.getBigRandom(n);
	    var G = this.ecparams['G'];
	    var Q = G.multiply(k);
	    var r = Q.getX().toBigInteger().mod(n);
	} while (r.compareTo(BigInteger.ZERO) <= 0);

	var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
	return this.serializeSig(r, s);
    };

    this.verifyWithMessageHash = function(hashHex, sigHex) {
	return this.verifyHex(hashHex, sigHex, this.pubKeyHex);
    };

    /**
     * verifying signature with message hash and public key
     * @name verifyHex
     * @memberOf KJUR.crypto.SM3withSM2
     * @function
     * @param {String} hashHex hexadecimal string of hash value of signing message
     * @param {String} sigHex hexadecimal string of signature value
     * @param {String} pubkeyHex hexadecimal string of public key
     * @return {Boolean} true if the signature is valid, otherwise false
     * @since ecdsa-modified 1.0.1
     * @example
     * var ec = KJUR.crypto.SM3withSM2({'curve': 'sm2'});
     * var result = ec.verifyHex(msgHashHex, sigHex, pubkeyHex);
     */
    this.verifyHex = function(hashHex, sigHex, pubkeyHex) {
	var r,s;

	var obj = KJUR.crypto.ECDSA.parseSigHex(sigHex);
	r = obj.r;
	s = obj.s;

	var Q;
	Q = ECPointFp.decodeFromHex(this.ecparams['curve'], pubkeyHex);
	var e = new BigInteger(hashHex, 16);

	return this.verifyRaw(e, r, s, Q);
    };

    this.verify = function (hash, sig, pubkey) {
	var r,s;
	if (Bitcoin.Util.isArray(sig)) {
	    var obj = this.parseSig(sig);
	    r = obj.r;
	    s = obj.s;
	} else if ("object" === typeof sig && sig.r && sig.s) {
	    r = sig.r;
	    s = sig.s;
	} else {
	    throw "Invalid value for signature";
	}

	var Q;
	if (pubkey instanceof ECPointFp) {
	    Q = pubkey;
	} else if (Bitcoin.Util.isArray(pubkey)) {
	    Q = ECPointFp.decodeFrom(this.ecparams['curve'], pubkey);
	} else {
	    throw "Invalid format for pubkey value, must be byte array or ECPointFp";
	}
	var e = BigInteger.fromByteArrayUnsigned(hash);

	return this.verifyRaw(e, r, s, Q);
    };

    this.verifyRaw = function (e, r, s, Q) {
	var n = this.ecparams['n'];
	var G = this.ecparams['G'];
	
	var t = r.add(s).mod(n);
    if (t.equals(BigInteger.ZERO))
        return false;
        
    var x1y1 = G.multiply(s);
    x1y1 = x1y1.add(Q.multiply(t));

    var R = e.add(x1y1.getX().toBigInteger()).mod(n);
    return r.equals(R);
    };

    /**
     * Serialize a signature into DER format.
     *
     * Takes two BigIntegers representing r and s and returns a byte array.
     */
    this.serializeSig = function (r, s) {
	var rBa = r.toByteArraySigned();
	var sBa = s.toByteArraySigned();

	var sequence = [];
	sequence.push(0x02); // INTEGER
	sequence.push(rBa.length);
	sequence = sequence.concat(rBa);

	sequence.push(0x02); // INTEGER
	sequence.push(sBa.length);
	sequence = sequence.concat(sBa);

	sequence.unshift(sequence.length);
	sequence.unshift(0x30); // SEQUENCE
	return sequence;
    };

    /**
     * Parses a byte array containing a DER-encoded signature.
     *
     * This function will return an object of the form:
     *
     * {
     *   r: BigInteger,
     *   s: BigInteger
     * }
     */
    this.parseSig = function (sig) {
	var cursor;
	if (sig[0] != 0x30)
	    throw new Error("Signature not a valid DERSequence");

	cursor = 2;
	if (sig[cursor] != 0x02)
	    throw new Error("First element in signature must be a DERInteger");;
	var rBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

	cursor += 2+sig[cursor+1];
	if (sig[cursor] != 0x02)
	    throw new Error("Second element in signature must be a DERInteger");
	var sBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

	cursor += 2+sig[cursor+1];

	//if (cursor != sig.length)
	//  throw new Error("Extra bytes in signature");

	var r = BigInteger.fromByteArrayUnsigned(rBa);
	var s = BigInteger.fromByteArrayUnsigned(sBa);

	return {r: r, s: s};
    };

    this.parseSigCompact = function (sig) {
	if (sig.length !== 65) {
	    throw "Signature has the wrong length";
	}

	// Signature is prefixed with a type byte storing three bits of
	// information.
	var i = sig[0] - 27;
	if (i < 0 || i > 7) {
	    throw "Invalid signature type";
	}

	var n = this.ecparams['n'];
	var r = BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
	var s = BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);

	return {r: r, s: s, i: i};
    };

    if (params !== undefined) {
	if (params['curve'] !== undefined) {
	    this.curveName = params['curve'];
	}
    }
    if (this.curveName === undefined) this.curveName = curveName;
    this.setNamedCurve(this.curveName);
    if (params !== undefined) {
	if (params['prv'] !== undefined) this.setPrivateKeyHex(params['prv']);
	if (params['pub'] !== undefined) this.setPublicKeyHex(params['pub']);
    }
};
