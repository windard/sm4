// \file:sm2.h
//SM2 Algorithm
//2011-11-09
//author:goldboar
//email:goldboar@163.com
//comment:2011-11-10 sm2-sign-verify sm2-dh

//SM2_sign_setup
int SM2_sign_setup(EC_KEY *eckey, BN_CTX *ctx_in, BIGNUM **kinvp, BIGNUM **rp);

//SM2_sign_ex
int	SM2_sign_ex(int type, const unsigned char *dgst, int dlen, unsigned char 
	*sig, unsigned int *siglen, const BIGNUM *kinv, const BIGNUM *r, EC_KEY *eckey);

//SM2_sign
int	SM2_sign(int type, const unsigned char *dgst, int dlen, unsigned char 
		*sig, unsigned int *siglen, EC_KEY *eckey);

//SM2_verify
int SM2_verify(int type, const unsigned char *dgst, int dgst_len,
		const unsigned char *sigbuf, int sig_len, EC_KEY *eckey);

//SM2 DH, comupting shared point
int SM2_DH_key(const EC_GROUP * group,const EC_POINT *b_pub_key_r, const EC_POINT *b_pub_key, const BIGNUM *a_r,EC_KEY *a_eckey,
			   unsigned char *outkey,size_t keylen);
