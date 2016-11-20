
因最近一个项目需要用到国密算法，所以在网上找了一下国密算法的相关资料。国密算法并不是特指一种算法，而是指国家密码局认定的国产密码算法。它包括 SM2,SM3,SM4 祖冲之算法等一系列算法，可以参考[这篇公告](http://www.oscca.gov.cn/News/201204/News_1228.htm)说明。

在网上也有不少国密算法的实现，比如说 北京大学信息安全实验室 开发和维护的 [GmSSL](http://gmssl.org/) ，它是支持国密算法和标准的 openSSL 分支，其代码托管在 [github](https://github.com/guanzhi/GmSSL) 上。

国密算法 SM2 是公钥算法，即非对称加密算法，类似于 RSA，不过 RSA 是基于大素数分解问题，SM2 是基于椭圆曲线问题，SM3 是消息摘要算法，类似于 md5 或 SHA-1 算法，不过 md5 和 SHA-1 都在 2005 年被中国山东大学的 王小云 教授破解，不建议使用，SM4 是传统的对称加密算法， 采用分组加密，类似于 DES 或 AES ，可以在[这篇文章](http://www.wtoutiao.com/a/844743.html)里看到这些算法之间的简单比较，更加深入的研究请参考论文。

网上已有 JavaScript 实现的 [SM2 算法](http://www.jonllen.com/jonllen/js/178.aspx)，其参考引用了很多 [jsrsasign](http://kjur.github.io/jsrsasign/) 的实现，这是一个用 JavaScript 做加密解密的库，实现了很多的加密解密算法。

JavaScript 本身是有很多缺陷的，数字只有 int 类型，虽然说是 64 位的，但是在做移位运算的时候它会被自动转换为 32 位，这就很尴尬，32 位的移位运算，一不小心就越界了，而且移位也只有左移，而没有循环移位。虽然说 Python 也是只有 int 型，不过它是真真的64 位，不会缺斤少两，不会像 JavaScript 连 大整数异或 都会有问题，最后循环左移操作都是自己实现的，JavaScript 还有自己实现以下大整数异或操作，网上也有文章详细的提到 JavaScript 的[移位操作的缺陷](http://jerryzou.com/posts/do-you-really-want-use-bit-operators-in-JavaScript/)。

关于 SM4 算法流程，国家密码局是已经公开了的，可以找到一份 PDF 文档，写的清清楚楚，明明白白，比我想象的要简单一些，这里就展示一下我自己实现的 循环左移 之类的函数，为什么一直在提循环左移呢？肯定是因为算法里面会用到的吖。

<object data="/software/sm4.pdf" height="525" type="application/pdf" width="729" internalinstanceid="7">
	<embed src="/software/sm4.pdf"><br>
</object>


[点击下载](/software/sm4.pdf)


JavaScript 版

```
function leftshift(a, n, size=32) {
	var result = new Array(size);
	result.fill(0);
	var bin = a.toString(2);
	bin = bin.length == size ? bin :"0".repeat(size - bin.length) + bin;
	for (var i = bin.length - 1; i >= 0; i--) {
		result[(i - n + size)%size] = bin[i];
	};
	result = result.join("");
	return parseInt(result, 2);
}
```

Pyhton 版

```
def leftshift(a, n, size=32):
	a = list(bin(a)[2:])
	a = ["0"]*(size - len(a)) + a
	b = ['0']*32
	for i,x in enumerate(a):
		b[(i-n)%32] = a[i]
	return int("".join(b), 2)
```

对比一下就可以看到核心思想都是一样的，将数字转换为列表并填满到指定位数，然后使用模指数运算实现数字移位，不过神奇的 JavaScript 的负数的模指数还是负数。。。

然后就是 JavaScript 版的 异或操作，真是 JavaScript 为什么大整数的异或都有问题。

```
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
```

还是先转换为列表补齐然后逐位对比。这两个函数觉得都实现的好丑陋，不优雅，希望有更好的办法。

或许也是因为这些不优雅的代码，使得代码的执行效率不高，或者说非常低，在官方文档中提供了一个 1000000 遍的加密样例，然而我的 JavaScript 和 Python 跑 10000 遍就需要近一分钟，这样下来就需要一个多小时了，可是网上找到的 C语言 和 Java 实现的 SM4 对 1000000 遍加密只需要近一秒钟即可，或许跟代码质量也有关吧，但还是可怕的性能差异。

