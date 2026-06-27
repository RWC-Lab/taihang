// 2-way variable base scalar multiplication

#include "fe25519.h"
#include "crypto_uint64_vec2x1.h"
#include "mont25519_batch.h"
#include "crypto_powbatch_inv25519.h"

int crypto_nP_2x1(unsigned char q[2][CRYPTO_BYTES], const unsigned char n[2][CRYPTO_BYTES], const unsigned char p[2][CRYPTO_BYTES]) {

	crypto_uint64_vec2x1 r[9] = {{0}};
	crypto_uint64_vec2x1 t[18] = {{0}};
	crypto_uint64_vec2x1 s[4] = {{0}};
	fe25519_9l e[4];
	fe25519_9l_dense a[4],c;
	fe25519 b[4],d;

	unsigned char i,j,m[2][CRYPTO_BYTES];

	for (i=0;i<2;++i) {

		for (j=0;j<CRYPTO_BYTES;++j) m[i][j] = n[i][j];
		m[i][CRYPTO_BYTES-1] = m[i][CRYPTO_BYTES-1] & 0x7f;
		m[i][CRYPTO_BYTES-1] = m[i][CRYPTO_BYTES-1] | 0x40;
		m[i][0] = m[i][0] & 0xf8;
	}		
	
	for (i=0;i<2;++i) fe25519_unpack(b+i,(const unsigned char *)(m+i));
	
	for (i=0;i<4;++i) for (j=0;j<2;++j) s[i][j] = b[j].l[i];
	
	for (i=0;i<2;++i) {
	
		fe25519_unpack(&d,(const unsigned char *)(p+i));
	  	fe25519_to_9l(e+i,&d);
	}
	
	for (i=0;i<9;++i) {r[i][0] = e[0].l[i] | (e[1].l[i] << 32);}	

	mladder_2x1(t,r,s);
		
	for (j=0;j<2;++j) {

		for (i=0;i<9;++i) {

			e[j+0].l[i] = t[i+0*9][j]; 
			e[j+2].l[i] = t[i+1*9][j];
		}
		fe25519_from_9l(b+j,e+j);
		fe25519_from_9l(b+j+2,e+j+2);
	}

	for (j=0;j<2;++j) fe25519_pack((unsigned char *)(m+j),b+j+2);

	crypto_powbatch_inv25519((unsigned char *)q,(const unsigned char *)m,2);
	
	for (j=0;j<2;++j) { 
	
		fe25519_4l_to_9l_dense(a+j,b+j);
		fe25519_unpack(b+j+2,(const unsigned char *)(q+j));
		fe25519_4l_to_9l_dense(a+j+2,b+j+2);
	}

	for (j=0;j<2;++j) {

		fe25519_mul(&c,a+j+2,a+j); 
		fe25519_9l_dense_to_4l(&d,&c);
		fe25519_pack((unsigned char *)(q+j),&d);
	}

	return 0;
}
