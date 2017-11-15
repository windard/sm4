/*! utils-1.0.js (c) Windard Yang | https://www.windard.com/
 */
/*
 * utils-1.0.js
 * 
 * Copyright (c) 2014 Windard Yang (www.windard.com)
 */
/**
 * @fileOverview
 * @name utils-1.0.js
 * @author Windard (www.windard.com)
 * @version 1.0.0 (2017-11-15)
 */

function encode(s) {
    return s.replace(/[\d\D]/g, function($) {
        return ("000" + $.charCodeAt(0).toString(16)).slice(-4);
    });
}

function decode(s) {
    return s.replace(/.{4}/g, function($) {
        return String.fromCharCode(parseInt($, 16));
    });
}

function PKCS7_padding_encode(data){
    var result = new Array();
    for (var i = 0; i < data.length; i++) {
        result.push(data.charCodeAt(i))
    };
    var size = 4-result.length%4
    for (i = 0; i < size; i++) {
        result.push(size)
    };
    return result;
}

function PKCS7_padding_decode(data){
    var result="";
    var size = data[data.length-1];
    for (var i = 0; i < size ; i++) {
        data.pop();
    };
    for(i = 0;i < data.length; i++) {
        result += String.fromCharCode(data[i]);
    };
    return result;
}

function randomkey(key) {
    var result = "";
    for(var i = 0;i < key.length/2 ;i+=8 ) {
        tempnum = bigxor(parseInt(key.slice(i,i+8), 16), Math.round(Math.random()*1000000000)).toString(16)
        console.log(tempnum,tempnum.length)
        result += tempnum.length == 8 ? tempnum : "0".repeat(8 - tempnum.length) + tempnum 
    }
    return result;
}

function xorkey(key) {
    var result = new Array();
    for(var i = 0;i < key.length ;i+=8 ) {
        result.push(parseInt(key.slice(i,i+8), 16))
    }
    return result;
}

function sm4_encode_cbc(data, key) {
    var iv = new Array(0x01234567,0x89abcdef,0xfedcba98,0x76543210);
    var message = new Array();
    var result = new Array();
    key = xorkey(key);
    data = PKCS7_padding_encode(data);
    for (var x = 0 ; x < data.length/4 ; x++) {
        for (var i = 0 ; i < iv.length ; i++) {
            message.push(bigxor(iv[i], data[i+x*4]));
        };
        ciphertext = KJUR_encrypt_sm4(message, key, "cbc")
        iv = ciphertext
        result = result.concat(ciphertext);
        message = new Array();
    }
    return result;
}

function bigxor(a, b) {
    var abin = a.toString(2);
    var bbin = b.toString(2);
    var loggest = abin.length >= bbin.length ? abin.length : bbin.length;
    abin = abin.length == loggest ? abin :"0".repeat(loggest - abin.length) + abin;
    bbin = bbin.length == loggest ? bbin :"0".repeat(loggest - bbin.length) + bbin;
    var result = "";
    for (var i = loggest - 1; i >= 0; i--) {
        result = abin[i] == bbin[i] ? '0'+result : '1'+result; 
    };
    return parseInt(result, 2);
}

function sm4_decode_cbc(data, key) {
    var iv = new Array(0x01234567,0x89abcdef,0xfedcba98,0x76543210);
    var message = new Array();
    var result = new Array();
    key = xorkey(key);
    for(var x=data.length/4-1;x>=0;x--){
        if(x==0){
            iv = new Array(0x01234567,0x89abcdef,0xfedcba98,0x76543210);
        }else{
            iv = data.slice((x-1)*4,x*4)
        }
        message = KJUR_decrypt_sm4(data.slice(x*4,(x+1)*4), key);
        for(var j=message.length-1;j>=0;j--){
            result.push(bigxor(message[j], iv[j]))
        }
    }
    result.reverse();
    result = PKCS7_padding_decode(result);
    return result;
}
