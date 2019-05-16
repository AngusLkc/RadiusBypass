typedef struct{
	unsigned int lo,hi;
	unsigned int a,b,c,d;
	unsigned char buffer[64];
	unsigned int block[16];
}MD5_CTX;
#define F(x,y,z)((z)^((x)&((y)^(z))))
#define G(x,y,z)((y)^((z)&((x)^(y))))
#define H(x,y,z)((x)^(y)^(z))
#define I(x,y,z)((y)^((x)|~(z)))
#define STEP(f,a,b,c,d,x,t,s)(a)+=f((b),(c),(d))+(x)+(t);(a)=(((a)<<(s))|(((a)&0xffffffff)>>(32-(s))));(a)+=(b)
#if defined(__i386__)||defined(__x86_64__)||defined(__vax__)
#define SET(n)(*(unsigned int*)&ptr[(n)*4])
#define GET(n)SET(n)
#else
#define SET(n)(ctx->block[(n)]=(unsigned int)ptr[(n)*4]|((unsigned int)ptr[(n)*4+1]<<8)|((unsigned int)ptr[(n)*4+2]<<16)|((unsigned int)ptr[(n)*4+3]<<24))
#define GET(n)(ctx->block[(n)])
#endif
void md5(unsigned char*,void*,unsigned long);
