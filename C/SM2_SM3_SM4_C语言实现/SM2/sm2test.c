#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include "sm2.h"


#pragma comment(lib,"libeay32.lib")

#define ABORT do { \
	fflush(stdout); \
	fprintf(stderr, "%s:%d: ABORT\n", __FILE__, __LINE__); \
	ERR_print_errors_fp(stderr); \
	exit(1); \
} while (0)

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

void BNPrintf(BIGNUM* bn)
{
	char *p=NULL;
	p=BN_bn2hex(bn);
	printf("%s",p);
	OPENSSL_free(p);
}


int SM2_Test_Vecotor()
{
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b;
	EC_GROUP *group;
	EC_POINT *P, *Q, *R;
	BIGNUM *x, *y, *z;
	EC_KEY	*eckey = NULL;
	unsigned char	digest[20];
	unsigned char	*signature = NULL; 
	int	sig_len;


	CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */
	
	ctx = BN_CTX_new();
	if (!ctx) ABORT;

	/* Curve SM2 (Chinese National Algorithm) */
	//http://www.oscca.gov.cn/News/201012/News_1197.htm
	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!p || !a || !b) ABORT;
	group = EC_GROUP_new(EC_GFp_mont_method()); /* applications should use EC_GROUP_new_curve_GFp
 	                                             * so that the library gets to choose the EC_METHOD */
	if (!group) ABORT;
	
	if (!BN_hex2bn(&p, "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3")) ABORT;
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
	if (!BN_hex2bn(&a, "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498")) ABORT;
	if (!BN_hex2bn(&b, "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A")) ABORT;
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;

	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	if (!P || !Q || !R) ABORT;

	x = BN_new();
	y = BN_new();
	z = BN_new();
	if (!x || !y || !z) ABORT;

	// sm2 testing P256 Vetor
	// p£º8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
	// a£º787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
	// b£º63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
	// xG 421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
	// yG 0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
	// n: 8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7

	if (!BN_hex2bn(&x, "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D")) ABORT;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx)) ABORT;
	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;
	if (!BN_hex2bn(&z, "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7")) ABORT;
	if (!EC_GROUP_set_generator(group, P, z, BN_value_one())) ABORT;
	
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nChinese sm2 algorithm test -- Generator:\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&z, "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2")) ABORT;
	if (0 != BN_cmp(y, z)) ABORT;
	
	fprintf(stdout, "verify degree ...");
	if (EC_GROUP_get_degree(group) != 256) ABORT;
	fprintf(stdout, " ok\n");
	
	fprintf(stdout, "verify group order ...");
	fflush(stdout);
	if (!EC_GROUP_get_order(group, z, ctx)) ABORT;
	if (!EC_GROUP_precompute_mult(group, ctx)) ABORT;
	if (!EC_POINT_mul(group, Q, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, Q)) ABORT;
 	fflush(stdout);
	fprintf(stdout, " ok\n");

	//testing ECDSA for SM2
	/* create new ecdsa key */
	if ((eckey = EC_KEY_new()) == NULL)
		goto builtin_err;
	if (EC_KEY_set_group(eckey, group) == 0)
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	/* create key */
	if (!EC_KEY_generate_key(eckey))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	/* check key */
	if (!EC_KEY_check_key(eckey))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	/* create signature */
	sig_len = ECDSA_size(eckey);
	fprintf(stdout,"Siglength is: %d \n",sig_len);
	if (!RAND_pseudo_bytes(digest, 20))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	if ((signature = OPENSSL_malloc(sig_len)) == NULL)
		goto builtin_err;
	if (!SM2_sign(0, digest, 20, signature, &sig_len, eckey))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	fprintf(stdout, "ECSign OK\n");
	/* verify signature */
	if (SM2_verify(0, digest, 20, signature, sig_len, eckey) != 1)
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	fprintf(stdout, "ECVerify OK\n");
	/* cleanup */
	OPENSSL_free(signature);
	signature = NULL;
	EC_KEY_free(eckey);
	eckey = NULL;
	
builtin_err:	
	
	EC_POINT_free(P);
	EC_POINT_free(Q);
	EC_POINT_free(R);
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	return 0;

}

int SM2_Test_Vecotor2()
{
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b;
	EC_GROUP *group;
	EC_POINT *P, *Q, *R;
	BIGNUM *x, *y, *z;
	EC_KEY	*eckey = NULL;
	unsigned char	*signature;
	unsigned char	digest[32] = "\xB5\x24\xF5\x52\xCD\x82\xB8\xB0\x28\x47\x6E\x00\x5C\x37\x7F\xB1\x9A\x87\xE6\xFC\x68\x2D\x48\xBB\x5D\x42\xE3\xD9\xB9\xEF\xFE\x76"; 
	int	sig_len;
	BIGNUM *kinv, *rp,*order; 
	ECDSA_SIG *ecsig = ECDSA_SIG_new();
	EC_POINT * DHPoint = NULL;
// 	unsigned char *in="123456";
// 	size_t inlen = 6;
 	size_t outlen = 256;
	unsigned char outkey[256];
	size_t keylen = 256;

	size_t i;

	CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof rnd_seed); /* or BN_generate_prime may fail */
	
	ctx = BN_CTX_new();
	if (!ctx) ABORT;

	/* Curve SM2 (Chinese National Algorithm) */
	//http://www.oscca.gov.cn/News/201012/News_1197.htm
	p = BN_new();
	a = BN_new();
	b = BN_new();
	if (!p || !a || !b) ABORT;
	group = EC_GROUP_new(EC_GFp_mont_method()); /* applications should use EC_GROUP_new_curve_GFp
 	                                             * so that the library gets to choose the EC_METHOD */
	if (!group) ABORT;
	
	if (!BN_hex2bn(&p, "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3")) ABORT;
	if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL)) ABORT;
	if (!BN_hex2bn(&a, "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498")) ABORT;
	if (!BN_hex2bn(&b, "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A")) ABORT;
	if (!EC_GROUP_set_curve_GFp(group, p, a, b, ctx)) ABORT;

	P = EC_POINT_new(group);
	Q = EC_POINT_new(group);
	R = EC_POINT_new(group);
	if (!P || !Q || !R) ABORT;

	x = BN_new();
	y = BN_new();
	z = BN_new();
	if (!x || !y || !z) ABORT;

	// sm2 testing P256 Vetor
	// p£º8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
	// a£º787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
	// b£º63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
	// xG 421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
	// yG 0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
	// n: 8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7

	if (!BN_hex2bn(&x, "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D")) ABORT;
	if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx)) ABORT;
	if (!EC_POINT_is_on_curve(group, P, ctx)) ABORT;
	if (!BN_hex2bn(&z, "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7")) ABORT;
	if (!EC_GROUP_set_generator(group, P, z, BN_value_one())) ABORT;
	
	if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nChinese sm2 algorithm test -- Generator:\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
	/* G_y value taken from the standard: */
	if (!BN_hex2bn(&z, "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2")) ABORT;
	if (0 != BN_cmp(y, z)) ABORT;
	
	fprintf(stdout, "verify degree ...");
	if (EC_GROUP_get_degree(group) != 256) ABORT;
	fprintf(stdout, " ok\n");
	
	fprintf(stdout, "verify group order ...");
	fflush(stdout);
	if (!EC_GROUP_get_order(group, z, ctx)) ABORT;
	if (!EC_GROUP_precompute_mult(group, ctx)) ABORT;
	if (!EC_POINT_mul(group, Q, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_is_at_infinity(group, Q)) ABORT;
 	fflush(stdout);
	fprintf(stdout, " ok\n");

	//testing ECDSA for SM2
	/* create new ecdsa key */
	if ((eckey = EC_KEY_new()) == NULL)
		goto builtin_err;
	if (EC_KEY_set_group(eckey, group) == 0)
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}
	/* create key */
	if (!BN_hex2bn(&z, "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263")) ABORT;
	if (!EC_POINT_mul(group,P, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting ECKey Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
	EC_KEY_set_private_key(eckey,z);
	EC_KEY_set_public_key(eckey, P);

	/* check key */
	if (!EC_KEY_check_key(eckey))
	{
		fprintf(stdout," failed\n");
		goto builtin_err;
	}

	/* create signature */
	sig_len = ECDSA_size(eckey);
 	//fprintf(stdout,"Siglength is: %d \n",sig_len);
	if ((signature = OPENSSL_malloc(sig_len)) == NULL)
		goto builtin_err;

	rp    = BN_new();
	kinv  = BN_new();
	order = BN_new();

	if (!BN_hex2bn(&z, "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F")) ABORT;
	if (!EC_POINT_mul(group, Q, z, NULL, NULL, ctx))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	if (!EC_POINT_get_affine_coordinates_GFp(group,Q, x, y, ctx))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	fprintf(stdout, "\nTesting K Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");

	EC_GROUP_get_order(group, order, ctx);
	if (!BN_nnmod(rp, x, order, ctx))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	if (!BN_copy(kinv, z ))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}

// 	for(i=0;i<32;i++)
// 		printf("%02X",digest[i]);
// 	printf("\n");

	if (!SM2_sign_ex(1, digest, 32, signature, &sig_len, kinv, rp, eckey))
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	fprintf(stdout, "ECSign OK\n");

	/* verify signature */
	if (SM2_verify(1, digest, 32, signature, sig_len, eckey) != 1)
	{
		fprintf(stdout, " failed\n");
		goto builtin_err;
	}
	fprintf(stdout, "ECVerify OK\n     r = 0x");
	d2i_ECDSA_SIG(&ecsig, &signature, sig_len);
	BNPrintf(ecsig->r);
	fprintf(stdout,"\n     s = 0x");
	BNPrintf(ecsig->s);
	fprintf(stdout,"\n");

	//testing SM2DH vector
	/* create key */
	if (!BN_hex2bn(&z, "6FCBA2EF9AE0AB902BC3BDE3FF915D44BA4CC78F88E2F8E7F8996D3B8CCEEDEE")) ABORT;
	if (!EC_POINT_mul(group,P, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting A Key Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
	EC_KEY_set_private_key(eckey,z);
	EC_KEY_set_public_key(eckey, P);

	if (!BN_hex2bn(&z, "5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53")) ABORT;
	if (!EC_POINT_mul(group,Q, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,Q, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting B Key Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
	//EC_KEY_set_private_key(eckey,z);
	//EC_KEY_set_public_key(eckey, P);

	if (!BN_hex2bn(&z, "33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80")) ABORT;
	if (!EC_POINT_mul(group,P, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,P, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting Rb Key Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");

	if (!BN_hex2bn(&z, "83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563")) ABORT;
	if (!EC_POINT_mul(group,R, z, NULL, NULL, ctx)) ABORT;
	if (!EC_POINT_get_affine_coordinates_GFp(group,R, x, y, ctx)) ABORT;
	fprintf(stdout, "\nTesting Ra Key Point\n     x = 0x");
	BNPrintf(x);
	fprintf(stdout, "\n     y = 0x");
	BNPrintf( y);
	fprintf(stdout, "\n");
    
	SM2_DH_key(group,P, Q, z,eckey,outkey,keylen);

	fprintf(stdout,"\nExchange key --KDF(Xv||Yv)--  :");
	for(i=0; i<outlen; i++)
		printf("%02X",outkey[i]);
	printf("\n");



builtin_err:	
	OPENSSL_free(signature);
	signature = NULL;
	EC_POINT_free(P);
	EC_POINT_free(Q);
	EC_POINT_free(R);
	EC_POINT_free(DHPoint);
	EC_KEY_free(eckey);
	eckey = NULL;
	EC_GROUP_free(group);
	BN_CTX_free(ctx);
	return 0;

}

int main()
{
	CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof rnd_seed); 
	
	SM2_Test_Vecotor2();
	
	
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stderr);
	
	return 0;

}