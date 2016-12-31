/*! sm4-1.0.js (c) Windard Yang | https://www.windard.com/
 */
/*
 * sm4-1.0.js
 * 
 * Copyright (c) 2014 Windard Yang (www.windard.com)
 */
/**
 * @fileOverview
 * @name sm4-1.0.js
 * @author Windard (www.windard.com)
 * @version 1.0.0 (2016-11-17)
 */

/* this is sm4 in javascript by windard , today is 2016 11-17 , 
 *I'm afraid that can I finished this project , but after all 
 *in December, everything will be done , that's prefect
 */

/*
 * garbage , rubbish programe language, should havn't big decimal number
 * can't circular bitwise left shift, can do xor well
 */

/*
 * fuck it at all , finally finished it , and there has many other works need to do
 *
 */


var SboxTable = new Array();
SboxTable[ 0] = new Array(0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05);
SboxTable[ 1] = new Array(0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99);
SboxTable[ 2] = new Array(0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62);
SboxTable[ 3] = new Array(0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6);
SboxTable[ 4] = new Array(0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8);
SboxTable[ 5] = new Array(0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35);
SboxTable[ 6] = new Array(0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87);
SboxTable[ 7] = new Array(0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e);
SboxTable[ 8] = new Array(0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1);
SboxTable[ 9] = new Array(0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3);
SboxTable[10] = new Array(0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f);
SboxTable[11] = new Array(0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51);
SboxTable[12] = new Array(0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8);
SboxTable[13] = new Array(0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0);
SboxTable[14] = new Array(0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84);
SboxTable[15] = new Array(0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48);

var CK = new Array(
0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
0x10171e25,0x2c333a41,0x484f565d,0x646b7279
);

var FK = new Array(0xa3b1bac6,0x56aa3350,0x677d9197,0xb27022dc);

// function bigxor(a, b) {
// 	if (a.toString(2).length < 33 && b.toString(2).length < 33){		
// 		return a ^ b
// 	}
// 	var abin = a.toString(2);
// 	var bbin = b.toString(2);
// 	var loggest = abin.length >= bbin.length ? abin.length : bbin.length;
// 	abin = abin.length == loggest ? abin :"0".repeat(loggest - abin.length) + abin;
// 	bbin = bbin.length == loggest ? bbin :"0".repeat(loggest - bbin.length) + bbin;
// 	var result = "";
// 	for (var i = loggest - 1; i >= 0; i--) {
// 		result = abin[i] == bbin[i] ? '0'+result : '1'+result; 
// 	};
// 	return parseInt(result, 2);
// }

function bigxor(a, b){
	return a ^ b
}

// function leftshift(a, n, size=32) {
// 	var result = new Array(size);
// 	result.fill(0);
// 	var bin = a.toString(2);
// 	bin = bin.length == size ? bin :"0".repeat(size - bin.length) + bin;
// 	for (var i = bin.length - 1; i >= 0; i--) {
// 		result[(i - n + size)%size] = bin[i];
// 	};
// 	result = result.join("");
// 	return parseInt(result, 2);
// }

function leftshift(a, n, size=32) {
	n = n % size
	return (a << n) | (a >>> (size - n))
}

function prefixInteger(str, length) {
  return Array(length+1).join("0").split("").concat(String(str).split(""))
           .slice(-length).join("");
}

// function sm4Sbox(a) {
// 	var a1 = prefixInteger(a.toString(16),8).slice(0,2);
// 	var a2 = prefixInteger(a.toString(16),8).slice(2,4);
// 	var a3 = prefixInteger(a.toString(16),8).slice(4,6);
// 	var a4 = prefixInteger(a.toString(16),8).slice(6,8);
// 	var b1 = SboxTable[parseInt(a1[0], 16)][parseInt(a1[1], 16)];
// 	var b2 = SboxTable[parseInt(a2[0], 16)][parseInt(a2[1], 16)];
// 	var b3 = SboxTable[parseInt(a3[0], 16)][parseInt(a3[1], 16)];
// 	var b4 = SboxTable[parseInt(a4[0], 16)][parseInt(a4[1], 16)];
// 	return parseInt(prefixInteger(b1.toString(16), 2) + prefixInteger(b2.toString(16), 2) + prefixInteger(b3.toString(16), 2) + prefixInteger(b4.toString(16), 2) , 16)
// }

function sm4Sbox(a) {
	var b1 = SboxTable[(a & 0xf0000000) >>> 28][(a & 0x0f000000) >>> 24]
	var b2 = SboxTable[(a & 0x00f00000) >>> 20][(a & 0x000f0000) >>> 16]
	var b3 = SboxTable[(a & 0x0000f000) >>> 12][(a & 0x00000f00) >>>  8]
	var b4 = SboxTable[(a & 0x000000f0) >>>  4][(a & 0x0000000f) >>>  0]
	return (b1 << 24) | (b2 << 16) | (b3 << 8) | (b4 << 0)
}

function GET_ULONG_BE (a) {
	a = sm4Sbox(a)
	return bigxor(bigxor(bigxor(a, leftshift(a, 2)), bigxor(leftshift(a, 10), leftshift(a, 18))), leftshift(a, 24))
}

function PUT_ULONG_BE(b) {
	b = sm4Sbox(b)
	return bigxor(b, bigxor(leftshift(b, 13), leftshift(b, 23)));
}

function sm4_getkey (MK) {
	var  K = new Array();
	var rk = new Array();
	K[0] = bigxor(MK[0], FK[0]);
	K[1] = bigxor(MK[1], FK[1]);
	K[2] = bigxor(MK[2], FK[2]);
	K[3] = bigxor(MK[3], FK[3]);

	for (var i = 0; i < 32; i++) {
		K[i+4] = bigxor(K[i], PUT_ULONG_BE(bigxor(bigxor(K[i+1], K[i+2]), bigxor(K[i+3], CK[i]))));
		rk[i] = K[i+4].toString(16);
	};
	return rk;
}

function KJUR_encrypt_sm4 (messsage, key, method="cbc") {
	var MK = key;
	var X = messsage;
	var rk = sm4_getkey(MK);
	for (var i = 0; i < 32; i++) {
		X[i+4] = bigxor(X[i], GET_ULONG_BE(bigxor(bigxor(X[i+1], X[i+2]), bigxor(X[i+3], parseInt(rk[i], 16)))))
	};
	var Y = new Array(X[35].toString(16), X[34].toString(16), X[33].toString(16), X[32].toString(16))
	return Y;
}

function KJUR_decrypt_sm4 (ciphertext, key, method="cbc") {
	var MK = key;
	var X = ciphertext;
	var frk = sm4_getkey(MK);
	var rk = new Array()
	for (var i = frk.length - 1; i >= 0; i--) {
		rk[frk.length - 1 - i] = frk[i]
	};
	for (var i = 0; i < 32; i++) {
		X[i+4] = bigxor(X[i], GET_ULONG_BE(bigxor(bigxor(X[i+1], X[i+2]), bigxor(X[i+3], parseInt(rk[i], 16)))))
	};
	var Y = new Array(X[35].toString(16), X[34].toString(16), X[33].toString(16), X[32].toString(16))
	return Y;
}


