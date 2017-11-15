
## 国密算法

因最近一个项目需要用到国密算法，所以在网上找了一下国密算法的相关资料。国密算法并不是特指一种算法，而是指国家密码局认定的国产密码算法。它包括 SM2,SM3,SM4 祖冲之算法等一系列算法，可以参考~~[这篇公告](http://www.oscca.gov.cn/News/201204/News_1228.htm)~~，[国家密码管理局关于发布
《祖冲之序列密码算法》等6项密码行业标准公告](http://www.sca.gov.cn/sca/xwdt/2012-03/21/content_1002392.shtml)说明。

> 建议先阅读了解一下关于现代密码的基础知识。[密码发展史之近现代密码](http://www.sca.gov.cn/sca/zxfw/2017-04/24/content_1011711.shtml)

在网上也有不少国密算法的实现，比如说 北京大学信息安全实验室 开发和维护的 [GmSSL](http://gmssl.org/) ，它是支持国密算法和标准的 openSSL 分支，其代码托管在 [https://github.com/guanzhi/GmSSL](https://github.com/guanzhi/GmSSL) 上。

### sm2

国密算法 SM2 是公钥算法，即非对称加密算法，类似于 RSA，不过 RSA 是基于大素数分解问题，SM2 是基于椭圆曲线问题。

[国家密码管理局关于发布
《SM2椭圆曲线公钥密码算法》公告](http://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002386.shtml)

### sm3

SM3 是消息摘要算法，类似于 md5 或 SHA-1 算法，不过 md5 和 SHA-1 都在 2005 年被中国山东大学的 王小云 教授破解，不建议使用。

[国家密码管理局关于发布《SM3密码杂凑算法》公告](http://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml)

### sm4

SM4 是传统的对称加密算法， 采用分组加密，类似于 DES 或 AES。

可以在~~[这篇文章](http://www.wtoutiao.com/a/844743.html)~~里看到这些算法之间的简单比较，更加深入的研究请参考论文。

网上已有 JavaScript 实现的 [SM2 算法](http://www.jonllen.com/jonllen/js/178.aspx)，其参考引用了很多 [jsrsasign](http://kjur.github.io/jsrsasign/) 的实现，这是一个用 JavaScript 做加密解密的库，实现了很多的加密解密算法。

JavaScript 本身是有很多缺陷的，数字只有 int 类型，虽然说是 64 位的，但是在做移位运算的时候它会被自动转换为 32 位，这就很尴尬，32 位的移位运算，一不小心就越界了，而且移位也只有左移，而没有循环移位。虽然说 Python 也是只有 int 型，不过它是真真的64 位，不会缺斤少两，网上也有文章详细的提到 JavaScript 的[移位操作的缺陷](http://jerryzou.com/posts/do-you-really-want-use-bit-operators-in-JavaScript/)。

JavaScript 没有循环左移，只有左移，右移和无符号位右移。JavaScript 的复数的值等于 - （值的逆 + 1），比如说 -977410425 的二进制表示为 `11000101101111011110011010000111` ，它的逆为 `00111010010000100001100101111000` ,它的值的逆加1为 `00111010010000100001100101111001` ，所以在 JavaScript 中就会表示为 `-111010010000100001100101111001`，即 `x = -(~x + 1)`

```
a=-977410425
-977410425
a.toString(2)
"-111010010000100001100101111001"
(a>>0).toString(2)
"-111010010000100001100101111001"
(a>>>0).toString(2)
"11000101101111011110011010000111"
```

关于 SM4 算法流程，国家密码局是已经公开了的，可以找到一份 PDF 文档，写的清清楚楚，明明白白，比我想象的要简单一些，这里就展示一下我自己实现的 循环左移 之类的函数，为什么一直在提循环左移呢？肯定是因为算法里面会用到的吖。

<object data="/software/sm4.pdf" height="525" type="application/pdf" width="680" internalinstanceid="7">
    <embed src="/software/sm4.pdf"><br>
</object>


[点击下载](/software/sm4.pdf)


JavaScript 版

```
function leftshift(a, n, size=32) {
    n = n % size
    return (a << n) | (a >>> (size - n))
}
```

Pyhton 版

```
def leftshift(a, n, size=32):
    n = n % size
    return (a << n) | (a >> (size - n))
```

或许也是因为这些不优雅的代码，使得代码的执行效率不高，或者说非常低，在官方文档中提供了一个 1000000 遍的加密样例，然而我的 JavaScript 10000 遍就需要近一分钟，Python 10000 遍近 10 秒，这样下来就需要一个多小时了，可是网上找到的 C语言 和 Java 实现的 SM4 对 1000000 遍加密只需要近一秒钟即可，或许跟代码质量也有关吧，但还是可怕的性能差异。

还有一个地方是 S 盒代换的部分，也改进了一下，速度略有提升，但是差距较大。

JavaScript 版

```
function sm4Sbox(a) {
    var b1 = SboxTable[(a & 0xf0000000) >>> 28][(a & 0x0f000000) >>> 24]
    var b2 = SboxTable[(a & 0x00f00000) >>> 20][(a & 0x000f0000) >>> 16]
    var b3 = SboxTable[(a & 0x0000f000) >>> 12][(a & 0x00000f00) >>>  8]
    var b4 = SboxTable[(a & 0x000000f0) >>>  4][(a & 0x0000000f) >>>  0]
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | (b4 << 0)
}
```

python 版

```
def sm4Sbox(a):
    b1 = SboxTable[(a & 0xf0000000) >> 28][(a & 0x0f000000) >> 24]
    b2 = SboxTable[(a & 0x00f00000) >> 20][(a & 0x000f0000) >> 16]
    b3 = SboxTable[(a & 0x0000f000) >> 12][(a & 0x00000f00) >>  8]
    b4 = SboxTable[(a & 0x000000f0) >>  4][(a & 0x0000000f) >>  0]
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | (b4 << 0)

```

代码都在 [https://github.com/windard/sm4](https://github.com/windard/sm4) 了，打包下载在[这里](https://github.com/windard/sm4/archive/master.zip)。

## 性能

或许是自己的代码太渣，实现的 sm4 性能不太行。

在 `/JavaScript/demo` 中有性能测试。

![performance](/JavaScript/demo/performance.jpg)
