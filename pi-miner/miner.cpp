#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "miner.h"


#define rotrFixed(x,y) (((x) >> (y)) | ((x) << (32-(y))))
#define s0(x) (rotrFixed(x,7)^rotrFixed(x,18)^(x>>3))
#define s1(x) (rotrFixed(x,17)^rotrFixed(x,19)^(x>>10))
#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) (y^((x^y)&(y^z)))
#define S0(x) (rotrFixed(x,2)^rotrFixed(x,13)^rotrFixed(x,22))
#define S1(x) (rotrFixed(x,6)^rotrFixed(x,11)^rotrFixed(x,25))
#define blk0(i) (W[i] = data[i])
#define blk2(i) (W[i&15]+=s1(W[(i-2)&15])+W[(i-7)&15]+s0(W[(i-15)&15]))
#define a(i) T[(0-i)&7]
#define b(i) T[(1-i)&7]
#define c(i) T[(2-i)&7]
#define d(i) T[(3-i)&7]
#define e(i) T[(4-i)&7]
#define f(i) T[(5-i)&7]
#define g(i) T[(6-i)&7]
#define h(i) T[(7-i)&7]
#define R(i) h(i)+=S1(e(i))+Ch(e(i),f(i),g(i))+SHA_K[i+j]+(j?blk2(i):blk0(i));d(i)+=h(i);h(i)+=S0(a(i))+Maj(a(i),b(i),c(i))

static datat avec[MAXCHIPS]; // input data for hashing: midstate[8], ms3[8], data,ntime,bits
static datat rvec[MAXCHIPS]; // returned hashing results: nonce[16], jobsel
static datat ovec[MAXCHIPS]; // perviously returned hashing results (rvec)
static hasht chipmids[MAXCHIPS]; // currently processed midstate on this chip
static datat chipdata[MAXCHIPS]; // currently processed data on this chip: data[19]
static int   chipbusy[MAXCHIPS]; // currently busy retvector slot (0-15), or temperature code
static int   chipgood[MAXCHIPS][16]; // for each slot correct answers, calculated every 15 min 
static int   chipmiss[MAXCHIPS][16]; // for each slot wrong answers, calculated every 15 min 
static int   chiphash[MAXCHIPS]; // hashing speed based on jobsel toggle
static int   chipespi[MAXCHIPS]; // spi errors, maybe each slot should be reported
static int   chipmiso[MAXCHIPS]; // miso errors
static int   chipdupl[MAXCHIPS]; // duplications
static char  chipcard[MAXCHIPS]; // card id 0-15
static char  chipfast[MAXCHIPS]; // speed set for each chip
static char  chipconf[MAXCHIPS]; // [AIFDSOXT] (bits[1:8]) auto,iclk,fast,divide,slow,oclk,fix,tmp , if ==0, no reading of data from chip
static int   chipcoor[MAXCHIPS][21][36]; // nonces found in each core
static int job=0; // number of jobs sent to chips
static int maxspeed=MAXSPEED; // max speed for autotuner
static int defspeed=DEFSPEED; // start speed for autotuner
static int minspeed=MINSPEED; // min speed for autotuner

/* SHA256 CONSTANTS */
const unsigned sha_initial_state[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
const unsigned SHA_K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void SHA256_Full(unsigned *state, unsigned *data, const unsigned *st)
{
        unsigned W[16];
        unsigned T[8];
        unsigned j;

        T[0] = state[0] = st[0]; T[1] = state[1] = st[1]; T[2] = state[2] = st[2]; T[3] = state[3] = st[3];
        T[4] = state[4] = st[4]; T[5] = state[5] = st[5]; T[6] = state[6] = st[6]; T[7] = state[7] = st[7];
        j = 0;
        for (j = 0; j < 64; j+= 16) { R(0); R(1);  R(2); R(3); R(4); R(5); R(6); R(7); R(8); R(9); R(10); R(11); R(12); R(13); R(14); R(15); }
        state[0] += T[0]; state[1] += T[1]; state[2] += T[2]; state[3] += T[3];
        state[4] += T[4]; state[5] += T[5]; state[6] += T[6]; state[7] += T[7];
}

void ms3_compute(unsigned *p)
{
        unsigned a,b,c,d,e,f,g,h, ne, na,  i;

        a = p[0]; b = p[1]; c = p[2]; d = p[3]; e = p[4]; f = p[5]; g = p[6]; h = p[7];
        for (i = 0; i < 3; i++) {
                ne = p[i+16] + SHA_K[i] + h + Ch(e,f,g) + S1(e) + d;
                na = p[i+16] + SHA_K[i] + h + Ch(e,f,g) + S1(e) + S0(a) + Maj(a,b,c);
                d = c; c = b; b = a; a = na;
                h = g; g = f; f = e; e = ne;
        }
        p[15] = a; p[14] = b; p[13] = c; p[12] = d; p[11] = e; p[10] = f; p[9] = g; p[8] = h;
}
unsigned dec_nonce(unsigned in)
{
        unsigned out;
        /* First part load */
        out = (in & 0xFF) << 24; in >>= 8;
        /* Byte reversal */
        in = (((in & 0xaaaaaaaa) >> 1) | ((in & 0x55555555) << 1));
        in = (((in & 0xcccccccc) >> 2) | ((in & 0x33333333) << 2));
        in = (((in & 0xf0f0f0f0) >> 4) | ((in & 0x0f0f0f0f) << 4));
        out |= (in >> 2)&0x3FFFFF;
        /* Extraction */
        if (in & 1) out |= (1 << 23);
        if (in & 2) out |= (1 << 22);
        out -= 0x800004;
        return out;
}
int test_nonce(unsigned tnon,hasht mids,datat data,hasht hash,uint32_t* pwdata,uint32_t* pwhash,int chip,int busy,int x,int y)
{
	static uint32_t dtmp[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0x80000000,0,0,0,0,0,0,0,0,0,0,0x280};
        unsigned int dd[16];

        memset(hash,0,sizeof(hasht));
        memset(dd,0,sizeof(dd));
        dd[0] = data[16]; dd[1] = data[17]; dd[2] = data[18]; dd[3] = tnon; dd[4] = 0x80000000; dd[15] = 0x280;
        SHA256_Full(hash, dd, mids);
        memset(dd, 0, sizeof(dd));
        memcpy(dd, hash, 4*8);
        dd[8] = 0x80000000; dd[15] = 0x100;
        SHA256_Full(hash, dd, sha_initial_state);
	if(hash[7] != 0){
		return(0);}
	memcpy(dtmp,data,sizeof(datat));
	dtmp[19]=tnon;
	memcpy(pwdata,dtmp,sizeof(dtmp));
	memcpy(pwhash,hash,sizeof(hasht));
	if(x>4){
		x-=3;}
	chipcoor[chip][x][y]++;
	chipgood[chip][busy]++;
	//printf("FOUND: %08x (%08x) mod %d chip %d [old] [%d,%d]  \r",tnon,newn,2,chip+1,x,y);
	//fp=fopen("/tmp/good.log","a");
	//fprintf(fp,"%d\t%d\t%d\t2\n",chip+1,x,y);
	//fclose(fp);
	return 1;
}

int fix_nonce(uint32_t newn,uint32_t old,hasht mids1,datat data1,hasht mids2,datat data2,int change,int chip,int job,int busy,uint32_t* pwdata,uint32_t* pwhash)
{
	//FILE *fp;
	//int mod[6]={0,-0x400000,-0x800000,0x2800000,0x2C00000,0x400000};
	//int mod[3]={0,-0x800000,-0x400000};
	hasht hash;
	uint32_t nonce=dec_nonce(newn);
	uint32_t tnon;
	uint32_t coor;
	int x;
	int y;

	if((newn & 0xff)<0x1c){ // was 0x20
		tnon=nonce-0x400000; //+mod[2];
		coor=((tnon>>29) & 0x07)|(((tnon)>>19) & 0x3F8);
		x=coor%24;
		y=coor/24;
		//should test for bad coordinate and return if bad;
		if(y<36){ // 3 out of 24 cases
			if(test_nonce(tnon,mids1,data1,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}
			if(change && test_nonce(tnon,mids2,data2,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}}}
	else{
		tnon=nonce; // mod[0]
		coor=((tnon>>29) & 0x07)|(((tnon)>>19) & 0x3F8);
		x=coor%24;
		y=coor/24;
		if(x>=17 && y<36){ // this or mod[1] , 7 out of 24 cases
			if(test_nonce(tnon,mids1,data1,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}
			if(change && test_nonce(tnon,mids2,data2,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}}
		tnon=nonce-0x800000; // +mod[1];
		coor=((tnon>>29) & 0x07)|(((tnon)>>19) & 0x3F8);
		x=coor%24;
		y=coor/24;
		if(((x>=1 && x<=4)||(x>=9 && x<=15)) && y<36){ // 11 out of 24 cases
			if(test_nonce(tnon,mids1,data1,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}
			if(change && test_nonce(tnon,mids2,data2,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}}}
	chipmiss[chip][busy]++;
#ifndef NDEBUG
	printf("ERROR: nonce %08x=>%08x (old %08x) on chip %d (job:%d,slot:%d) not mapped  \n",newn,nonce,old,chip+1,job,busy);
#endif
	//fp=fopen(".error.log","a");
	//fprintf(fp,"%d\t%d\t%08x\t%08x\n",chip,busy,newn,nonce);
	//fclose(fp);
	return 0;
}
void cpu_miner()
{	uint32_t nonce,data[32],hash1[16];
	hasht mids;
	hasht hash;
	int i;

	if(!get_work(mids,data)){
		return;}
	//if(mids[0]==0){ // remove
	//	SHA256_Full(mids,data,sha_initial_state);}
	nonce=rand();
      	for(i=0;i<1000000;i++) {
		data[16+3]= ++nonce;
		memset(hash1,0,64);
		hash1[8]=0x80000000;
		hash1[15]=0x100;
		SHA256_Full(hash1,data+16,mids);
		SHA256_Full(hash,hash1,sha_initial_state);
		if (hash[7] == 0) {
			printf("\nFOUND_NONCE: %08x\n",nonce);
			put_work(data,hash);
			return;}}
}

void spi_miner(int chips,char* chipconf,char* chipfast)
{	
	static hasht midsdo={0,0,0,0,0,0,0,0};
	static datat datado;
	uint32_t data[32];
	hasht mids={0,0,0,0,0,0,0,0};
	int c,j,wait;
        timeval start,stop;

	gettimeofday(&start,NULL);
	if(spi_need() && get_work(mids,data)){
	// prepare submission
		int card=-1,cardchip=0,good=0;
		uint32_t otime=data[17];
		uint32_t ntime=data[17];
		byte_reverse((uint8_t*)&ntime);
		for(c=0;c<chips;c++,ntime++){ // ntime roll
			if(chipcard[c]!=card){
				cardchip=0;
				card=chipcard[c];}
			else{
				cardchip++;}
			if(cardchip==15){
				good=0;
				for(j=0;j<16;j++){
					good+=chipgood[c][j];}}
			if(chipconf[c]&0x80 || (cardchip==15 && !good && (job+0)%2)){
				//printf("try temp sensor for %d [%d,%d,%d]\n",c,cardchip,good,(job+0));
				memset(avec[c],0x00,sizeof(uint32_t)*1);
				memset(avec[c]+1,0xFF,sizeof(uint32_t)*18);
				continue;}
			if(c){
				data[17]=ntime;
				byte_reverse((uint8_t*)(data+17));}
			memcpy(avec[c],mids,sizeof(hasht));
			memcpy(avec[c]+16,data+16,sizeof(uint32_t)*3);
			ms3_compute(avec[c]);} // input ready
		data[17]=otime;
		spi_put(mids,data,avec,chipconf,chipfast);} // put chip input data in spi communication buffer
	if(spi_get(mids,data,rvec,chipconf)){ // get midstate and data sent to chips and results from chips
		int non=0,err=0,spi=0,mis=0,miso=0,dup=0,card=-1,cardchip=0;
		uint32_t ntime=datado[17];
		byte_reverse((uint8_t*)&ntime);
		int miso_bad=0;
		int miso_ok=0;
		for(c=0;c<chips;c++,ntime++){ // ntime roll
			const char board[MAXBOARDS+1]="0123456789ABCDEF";
			int match=0;
			int change=0;
			int busy=chipbusy[c];
			int newbusy=chipbusy[c];
			unsigned char* buf=(unsigned char*)(rvec[c]);
			if(chipcard[c]!=card){
				cardchip=0;
				card=chipcard[c];}
			else{
				cardchip++;}
			if(!(chipconf[c]&0x80) && !rvec[c][0] && rvec[c][18]==0xFFFFFFFF && cardchip==15){ // detect temp sensor
				printf("a temp sensor: %d\n",c);
				chipconf[c]=0x80;}
			if(chipconf[c]&0x80){//test temp
				if(rvec[c][0]){
					if(rvec[c][0]==ovec[c][0]){ // this is not a temp sensor
/* kills the miner !!! */
					//	printf("not a temp sensor: %d\n",c);
					//	chipconf[c]=0x01 | 0x02 | 0x08 | 0x10; // auto adjust, iclk (conf bug), no fast clock, divide by 2, slow clock, no oclk
					//	chipfast[c]=defspeed;
					}}
				else{
					int b,n=0,noise=0;
					chipbusy[c]=0;
					for(j=4;j<19*4&&!noise;j++){
						if(chipbusy[c]){
							if(buf[j]==0xFF){
								continue;}
							else{
								noise=1;
								break;}}
						for(b=7;b>=0;b--,n++){ //LESZEK, check order !!!!
							if((buf[j]>>b)&0x1){
								if(!chipbusy[c]){
									chipbusy[c]=n;}
								continue;}
							if(chipbusy[c]){
								noise=1;}}}
					if(noise){
						chipbusy[c]=-chipbusy[c];}}}
			if(cardchip==15){
				if(buf[0]==0xFF){
					miso_bad++;}
				else{
					miso_ok++;}
				for(j=0;j<1*4;j++){
					printf("%02x",buf[j]);}
				printf("::");
				for(;j<19*4;j++){
					printf("%02x",buf[j]);}
				printf("\t%d\t%01d%c\n",chipbusy[c],card/16,board[card%16]);}
			if(chipconf[c]&0x80){//test temp
				continue;}
			if(!(chipconf[c]|0x3E)){ // prevent resetting miso
				continue;}
			for(j=1;j<16;j++){
				if(rvec[c][(busy+j)%16]!=ovec[c][(busy+j)%16]){
					newbusy=(busy+j)%16;}
				else{
					match++;}}
			if(!match){
				if(!miso){
					mis++;
					chipmiso[c]++;}
				miso=1; // remember last chips miso error state
				continue;}
			miso=0;
			if(rvec[c][17]!=0xFFFFFFFF && rvec[c][17]!=0x00000000){//log communication error
				spi++;
				chipespi[c]++;
#ifndef NDEBUG
				printf("SPI ERROR on chip %d (%08x)  \n",c+1,rvec[c][17]);
#endif
				}
			if(rvec[c][17]!=ovec[c][17]){ //job changed, need to check data for old and "datado"
				if(c){
					datado[17]=ntime;
					byte_reverse((uint8_t*)(datado+17));}
				chiphash[c]++;
				change=1;}
			for(;newbusy!=busy;busy=(busy+1)%16){ // got nonce (!)
				uint32_t pwdata[32];
				hasht pwhash;
				if(chipmids[c][0]==0 && chipdata[c][0]==0){
					continue;}
				if(rvec[c][busy]==0xFFFFFFFF || rvec[c][busy]==0x00000000){ // probably a wrong nonce
					rvec[c][busy]=ovec[c][busy];
					//spi=1;
					continue;}
				if(rvec[c][busy]==ovec[c][busy]){ // already tested
					//spi=1;
					continue;}
				for(j=0;j<16;j++){
					if(j!=busy && rvec[c][busy]==rvec[c][j]){
						chipdupl[c]++;
						dup++;
						break;}}
				if(j<16){
					continue;}
				if(fix_nonce(rvec[c][busy],ovec[c][busy],chipmids[c],chipdata[c],midsdo,datado,change,c,job,busy,pwdata,pwhash)){
					non++;
					put_work(pwdata,pwhash);}
				else{
					err++;}}
			//mis+=miso;
			//chipmiso[c]+=miso;
			chipbusy[c]=busy;
			if(change){ // set new processed data for the chip
				memcpy(chipmids[c],midsdo,sizeof(hasht));
				memcpy(chipdata[c],datado,sizeof(datat));}}
		if(miso_bad && !miso_ok){
			printf("MISO corrupted\n");
			spi_ledon();
		}
		else{
			spi_ledoff();
		}
		// data form buffer was sent to chips
		memcpy(midsdo,mids,sizeof(hasht));
		memcpy(datado,data,sizeof(datat));
		memcpy(ovec,rvec,sizeof(datat)*chips);
		gettimeofday(&stop,NULL);
		wait=1000000*(stop.tv_sec-start.tv_sec)+stop.tv_usec-start.tv_usec;
		job++;
		printf("JOB %d PROCESSED %.3f sec [nonces:%d errors:%d spi:%d miso:%d dup:%d] (queue:%d)  \n",job,(float)wait/1000000.0,non,err,spi,mis,dup,put_queue());}
	else{
		handylib::threads_sleep(100);}
}
char* chip_conf(char conf)
{
	static char str[8];
	if(conf&0x80){
		str[0]='T';
		str[1]=' ';
		str[2]=' ';
		str[3]=' ';
		str[4]=' ';
		str[5]=' ';}
	else{
		str[0]=(conf & 0x01?'A':'a'); // set auto tuning
		str[1]=(conf & 0x02?'I':'i'); // use clock from outside or slow internal clock
		str[2]=(conf & 0x04?'F':'f'); // use fast internal clock
		str[3]=(conf & 0x08?'D':'d'); // divide clock by 2
		str[4]=(conf & 0x10?'S':'s'); // use slow internal clock (requires "I") and not external clock
		str[5]=(conf & 0x20?'O':'o'); // send clock outside
		//str[6]=(conf & 0x40?'P':'p'); // program chip
	}
	return str;
}
char conf_chip(char* conf)
{
	if(conf[0]=='T'){
		return 0x80;}
	return
		(conf[0]=='A'?0x01:0x00) |
		(conf[1]=='I'?0x02:0x00) |
		(conf[2]=='F'?0x04:0x00) |
		(conf[3]=='D'?0x08:0x00) |
		(conf[4]=='S'?0x10:0x00) |
		(conf[5]=='O'?0x20:0x00) ;
		// | (conf[6]=='P'?0x40:0x00);
}
void chip_init()
{	FILE* fp=fopen(".chip.cnf","r");
	char buf[256],conf[7];
	int c,num,fast;

	if(fp==NULL){
		for(c=0;c<MAXCHIPS;c++){
			chipconf[c]=0x01 | 0x02 | 0x08 | 0x10; // auto adjust, iclk (conf bug), no fast clock, divide by 2, slow clock, no oclk
			chipfast[c]=defspeed;
			if(!defspeed){
				chipconf[c]=0x01 | 0x02 ;}}
		return;}
	for(c=0;c<MAXCHIPS && fgets(buf,256,fp)!=NULL;c++){
		if(buf[0]>57){ //hashrate line
			break;}
		sscanf(buf,"%d%*c%6c%d",&num,conf,&fast);
		if(!num){
			break;}
		if(num!=c+1){
			fprintf(stderr,"FATAL, format error in line %d:\n%s",c+1,buf);
			exit(-1);}
		chipconf[c]=conf_chip(conf);
		chipfast[c]=fast;}
		//printf("SET CHIP: %d\t%6.6s\t%d [%d,%6.6s,%d]\n",c+1,chip_conf(chipconf[c]),chipfast[c],num,conf,fast);}
	for(;c<MAXCHIPS;c++){
		chipconf[c]=0x01 | 0x02 | 0x08 | 0x10; // auto adjust, iclk (conf bug), no fast clock, divide by 2, slow clock, no oclk
		chipfast[c]=defspeed;}
}
void chip_stat(int chips)
{	static int first=0;
	static int last=0;
 	static time_t otime=0;
	time_t ntime=time(NULL);
	int speed=0;
	int nrate=0;
	int hrate=0;
	int error=0;
	int espi=0;
	int miso=0;
	int dupl=0;
	int wait=0;
	int core=0;
	int c_good=0;
	int c_bad=0;
	int c_off=0;
	int c_all=0;
	static float record=0.0;
	//extern char oldfast[MAXCHIPS]; // in spidev.cpp
	//extern char oldconf[MAXCHIPS]; // in spidev.cpp
	//extern char chipbank[MAXCHIPS+1]; // in spidev.cpp
	extern int version; // in spidev.cpp
	char chipchange[MAXCHIPS]; // 1=up,2=down,3=to0,4=shut,5=off
	struct stat sb;
	static time_t mtime;

	memset(chipchange,0,sizeof(chipchange));
	if(!otime){
		int c;
		FILE* hp=fopen(".chip-cnf","w");
		first=1;
		otime=ntime;
		if(stat(".chip.cnf",&sb)>=0){
			mtime=sb.st_mtime;}
		for(c=0;c<chips;c++){
			fprintf(hp,"%d\t%6.6s\t%d\n",c+1,chip_conf(chipconf[c]),chipfast[c]);}
		fclose(hp);
		return;}
	if(stat(".chip.cnf",&sb)>=0 && sb.st_mtime>mtime){
        	char buf[256],conf[7],newconf;
		FILE* hp=NULL;
		//FILE* hp=fopen(".hash.log","a");
		FILE* fp=fopen(".chip.cnf","r");
        	int c,num,fast;
		for(c=0;c<chips && fgets(buf,256,fp)!=NULL;c++){
			if(buf[0]>57){ //hashrate line
				break;}
			sscanf(buf,"%d%*c%6c%d",&num,conf,&fast);
			if(!num){
				break;}
			if(num!=c+1){
				printf("ERROR, format error in line %d:\n%s",c+1,buf);
				break;}
			newconf=conf_chip(conf);
			if(newconf!=chipconf[c] || fast!=chipfast[c]){
				// chip_conf return static buffer so we need to read it first before requesting new one
				printf("Set chip %d from %6.6s %d",num,chip_conf(chipconf[c]),chipfast[c]);printf(" to %6.6s %d\n",chip_conf(newconf),fast);
				//fprintf(hp,"Set chip %d from %6.6s %d",num,chip_conf(chipconf[c]),chipfast[c]);fprintf(hp," to %6.6s %d\n",chip_conf(newconf),fast);
				chipconf[c]=newconf|0x40;
				chipfast[c]=fast;}}
		fclose(fp);
		//fclose(hp);
		hp=fopen(".chip-cnf","w");
		for(c=0;c<chips;c++){
			fprintf(hp,"%d\t%6.6s\t%d\n",c+1,chip_conf(chipconf[c]),chipfast[c]);}
		fclose(hp);
		memset(chipgood,0,sizeof(chipgood));
		memset(chipmiss,0,sizeof(chipmiss));
		memset(chiphash,0,sizeof(chiphash));
		memset(chipespi,0,sizeof(chipespi));
		memset(chipmiso,0,sizeof(chipmiso));
		memset(chipdupl,0,sizeof(chipdupl));
		mtime=sb.st_mtime;
		first=1;
		last=job;
		ntime=otime;}
	wait=ntime-otime;
	if((first && !((job-last)%10) && job>last) || wait>=5*60){
		float ok,total,nr,hr;
		FILE* hp=NULL;
		FILE* fp=fopen(".stat.log","w");
		int c,j,b=0,lb=0,x,y;
		const char board[MAXBOARDS+1]="0123456789ABCDEF";
		int b_speed[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_nrate[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_hrate[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_error[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_espi[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_miso[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_dupl[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_cgood[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_cbad[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_coff[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_core[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int b_temp[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,};
		int good,miss,badc;
		hp=fopen(".chip-cnf","w");
		for(c=0;c<chips;fprintf(hp,"%d\t%6.6s\t%d\t[%01d%c:%c]\t%d\t%d\n",c+1,chip_conf(chipconf[c]),chipfast[c],b/16,board[b%16],board[(c-lb)%16],good,miss),c++){
			good=0;
			miss=0;
			if(chipconf[c]&0x80){ // temp sensor
				b_temp[b]=chipbusy[c];
				fprintf(fp,"%d\t%6.6s\t%d\t%d\t\t\t\t\t\t\t\t[%01d%c:%c]\n",c+1,chip_conf(chipconf[c]),chipfast[c],chipbusy[c],b/16,board[b%16],board[(c-lb)%16]);
				continue;}
			for(j=0;j<16;j++){
				good+=chipgood[c][j];
				miss+=chipmiss[c][j];}
			speed+=(chipconf[c]&0x10?chipfast[c]:0);
			nrate+=good;
			hrate+=chiphash[c];
			error+=miss;
			espi+=chipespi[c];
			miso+=chipmiso[c];
			dupl+=chipdupl[c];
			b=chipcard[c];
			if(chipcard[c]!=chipcard[lb]){
				lb=c;}
			b_speed[b]+=(chipconf[c]&0x10?chipfast[c]:0);
			b_nrate[b]+=good;
			b_hrate[b]+=chiphash[c];
			b_error[b]+=miss;
			b_espi[b]+=chipespi[c];
			b_miso[b]+=chipmiso[c];
			b_dupl[b]+=chipdupl[c];
			ok=(double)0xFFFFFFFF/1000000000.0*(double)good/(double)wait;
			total=(double)0xFFFFFFFF/1000000000.0*(double)chiphash[c]/(double)wait*(double)756/(double)1024;
			badc=0;
			for(x=0;x<21;x++){
				for(y=0;y<36;y++){
					if(!chipcoor[c][x][y]){ // bad core calculation
						badc++;}}}
			if(!(chipconf[c]&0x3E)){c_off++;b_coff[b]++;}
			else{ if(chipconf[c]&0x04 || badc==756){c_bad++;b_cbad[b]++;}
			else{c_good++;b_cgood[b]++;}}
			core+=756-badc;
			b_core[b]+=756-badc;
			fprintf(fp,"%d\t%6.6s\t%d\t%.3f\t%.3f\t%d\t%d\t%d\t%d\t%d\t%d\t[%01d%c:%c]\t%d\t",
				c+1,chip_conf(chipconf[c]),chipfast[c],ok,total,good,miss,chipespi[c],chipmiso[c],chipdupl[c],chiphash[c],b/16,board[b%16],board[(c-lb)%16],badc);
			for(j=0;j<16;j++){
				fprintf(fp,"%d ",chipgood[c][j]);}
			fprintf(fp,"\t");
			for(j=0;j<16;j++){
				fprintf(fp,"%d ",chipmiss[c][j]);}
			//if(chipmiso[c]>20 && !good && badc==756 && c-lb==15){ // this is most likely a temp sensor
			/*if(chiphash[c]>20 && !good && badc==756 && c-lb==15){ // this is most likely a temp sensor
				fprintf(fp,"temp-sensor");
				chipfast[c]=100;
				chipconf[c]=0x80;}*/
			if(!first && (chipconf[c] & 0x01)){
				if(ok<FIXNR){ // enable reprograming
					chipconf[c]|=0x40;
				}
				/*if(miss>=good && ok<MINNR && (chipconf[c]&0x10)) { // put chip to sleep if more errors than nonces
					chipchange[c]=3;
					fprintf(fp,"\tspeed->0\n");
					chipconf[c]=(chipconf[c] & ~0x12)|0x44;
					continue;}
				if((!chiphash[c] || good>miss) && (chipconf[c]&0x04)) { // if kick chip if completely sleeping or more nonces than errors
					chipchange[c]=1;
					fprintf(fp,"\tspeed up\n");
					chipconf[c]=(chipconf[c] & ~0x04)|0x52;
					continue;}
				if(badc == 756 && (chipconf[c]&0x04)){ // shut down chip if never returned good result
					chipchange[c]=4;
					fprintf(fp,"\tshut down\n");
					chipconf[c]&=0x01|0x40;
					continue;}*/
			}
			/*if(!first && chipconf[c]){ // change this, set fix signal
				if(good<MINGOOD || miss>MAXERROR*2 || (chipconf[c] & 0x80)){ // fix chip
					chipconf[c] = 0xc0|(chipconf[c] & 0x3F);} // toggle fix signal
				else{
					chipconf[c] &= 0x7F;}} // toggle fix signal
			if(!first && (chipconf[c] & 0x01) && (chipconf[c] != 0x01)){ // tune chips
				if(miss>good || good==0){
					if(chipfast[c]>defspeed){ // set speed to 0
						chipchange[c]=2;
						//fprintf(hp,"TUNE chip %d: slow down to %d  \n",c+1,chipfast[c]-1);
						fprintf(fp,"\tspeed down\n");
						chipfast[c]--;
						continue;}
					if(chipfast[c] && good<=chiphash[c]*0.5){ // set speed to 0
						chipchange[c]=3;
						//fprintf(hp,"TUNE chip %d: set speed to 0  \n",c+1);
						fprintf(fp,"\tspeed->0\n");
						chipfast[c]=0;
						continue;}
					if(miss>100 && !good && (chipconf[c]&0x3E)){ // chut down chip
						chipchange[c]=4;
						//fprintf(hp,"TUNE chip %d: shut down  \n",c+1);
						fprintf(fp,"\tshut down\n");
						chipconf[c]&=0x01;
						continue;}
					if((chipmiso[c]>10 && !good) || badc==756){
						chipchange[c]=5;
						//fprintf(hp,"TUNE chip %d: turn off  \n",c+1);
						fprintf(fp,"\tturn off\n");
						chipconf[c]=0;
						continue;}
					fprintf(fp,"\n");
					continue;}
				if(!miss && ok>total && chipfast[c]<maxspeed){
					chipchange[c]=1;
					//fprintf(hp,"TUNE chip %d: speed up to %d  \n",c+1,chipfast[c]+1);
					fprintf(fp,"\tspeed up\n");
					if(chipfast[c]<minspeed){
						chipfast[c]=minspeed;}
					else{
						chipfast[c]++;}
					continue;}
				if(miss>MAXERROR && chipfast[c]>minspeed && good<chiphash[c]){
					chipchange[c]=2;
					//fprintf(hp,"TUNE chip %d: slow down to %d  \n",c+1,chipfast[c]-1);
					fprintf(fp,"\tspeed down\n");
					chipfast[c]--;
					continue;}}*/
			fprintf(fp,"\n");}
		fclose(hp);
		c_all=c_good+c_bad+c_off;
		if(!c_all){
			c_all=1;}
		nr=(double)0xFFFFFFFF/1000000000.0*(double)nrate/(double)wait;
		hr=(double)0xFFFFFFFF/1000000000.0*(double)hrate/(double)wait*(double)756/(double)1024;
		fprintf(fp,"speed:%d noncerate[GH/s]:%.3f (%.3f/chip) hashrate[GH/s]:%.3f good:%d errors:%d spi-err:%d miso-err:%d duplicates:%d jobs:%d cores:%.0f%% good:%d bad:%d off:%d (best[GH/s]:%.3f) %24.24s\n",
			speed,nr,(c_good?nr/c_good:0),hr,nrate,error,espi,miso,dupl,job-last,100.0*core/(756*c_all),c_good,c_bad,c_off,record,ctime(&ntime));
		fprintf(fp,"board-%d\tspeed\tnrate\thrate\tgood\terrors\tspi-err\tmiso-er\tduplic\tgood\tbad\toff\tper chip\tgood cores\ttemp\n",version);
		lb=-1; // set last board that was changed
		for(b=0;b<MAXBOARDS;b++){
			int bchips=b_cgood[b]+b_cbad[b]+b_coff[b];
			if(bchips){
				float nr=(double)0xFFFFFFFF/1000000000.0*(double)b_nrate[b]/(double)wait;
				float hr=(double)0xFFFFFFFF/1000000000.0*(double)b_hrate[b]/(double)wait*(double)756/(double)1024;
				if(b_temp[b]>MAXTEMP){
					lb=b;
					for(c=0;c<chips;c++){
						if(chipcard[c]==b && !(chipconf[c]&0x80) && (chipconf[c]&0x03)==3){
							chipconf[c]= 0x40 | 0x01 | 0x08 | 0x10;}}}
				else if(b_temp[b]<MAXTEMP && b_temp[b]>0){
					for(c=0;c<chips;c++){
						if(chipcard[c]==b && !(chipconf[c]&0x80) && (chipconf[c]&0x03)==1){
							chipconf[c]= 0x40 | 0x01 | 0x02 | 0x08 | 0x10;}}}
				//float er=0;
				//if(hr>0){
				//	er=(hr-nr)/hr;}
				//if(!first && ((float)nr/bchips<DEFNR) && b_error[b]<MAXBERROR*b_nrate[b] && b_espi[b]<=1 && b_miso[b]<=1 && b_dupl[b]<=1){
				/*if(!first && ((float)nr/bchips<DEFNR) && er>MAXBERROR && b_espi[b]<=1 && b_miso[b]<=1 && b_dupl[b]<=1){
					for(c=0;c<chips;c++){
						if(chipcard[c]==b && (chipconf[c] & 0x01) && chipfast[c]==defspeed){
							chipfast[c]=maxspeed;}
						else if(chipcard[c]==b && (chipconf[c] & 0x01) && chipfast[c]==minspeed){
							chipfast[c]=defspeed;}}}
				if(!first && lb<0 && (b_cbad[b]>MAXBAD || ((float)nr/bchips<MINNR))){
					for(c=0;c<chips;c++){
						if(chipcard[c]==b && (chipconf[c] & 0x01) && chipfast[c]==defspeed){
							chipfast[c]=minspeed;
							lb=b;}
						else if(chipcard[c]==b && (chipconf[c] & 0x01) && chipfast[c]==maxspeed){
							chipfast[c]=defspeed;
							lb=b;}}}*/
				fprintf(fp,"%01d%c:\t%d\t%.3f\t%.3f\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t(%.3f/chip)\t%.0f%%\t%d\t%s\n",b/16,board[b%16],b_speed[b],nr,hr,
					b_nrate[b],b_error[b],b_espi[b],b_miso[b],b_dupl[b],b_cgood[b],b_cbad[b],b_coff[b],(float)nr/bchips,100.0*b_core[b]/(756*(bchips)),b_temp[b],(lb==b?"speed down":""));}}
		fclose(fp);

		// json log
		{	FILE* fp_json=fopen("stat.json","w");
			fprintf(fp_json,"{ \"stats\": \n {");
			fprintf(fp_json,"\"speed\": %d, \"noncerate\": %.3f, \"noncerateperchip\":%.3f, \"hashrate\":%.3f, \"good\":%d, \"errors\":%d, \"spi-errors\":%d, \"miso-errors\":%d, \"jobs\":%d, \"record\":%.3f\n",speed,nr,(nr/c_all),hr,nrate,error,espi,miso,job-last,record);
			fprintf(fp_json,",\"boards\": [");
			int firstboard = 0;
			for(b=0;b<MAXBOARDS;b++){
				if(b_speed[b]){
					if (firstboard > 0) fprintf(fp_json,",");
					fprintf(fp_json,"\n{ ");
					fprintf(fp_json,"\"slot\": \"%c\", \"speed\": %d, \"noncerate\":%.3f, \"hashrate\": %.3f, \"good\": %d, \"errors\": %d, \"spi-errors\": %d, \"miso-errors\":%d",board[b],b_speed[b],
						(double)0xFFFFFFFF/1000000000.0*(double)b_nrate[b]/(double)wait,
						(double)0xFFFFFFFF/1000000000.0*(double)b_hrate[b]/(double)wait*(double)756/(double)1024,
						b_nrate[b],b_error[b],b_espi[b],b_miso[b]);
					fprintf(fp_json," }\n");
					firstboard = 1;}}
			fprintf(fp_json,"\n ]");	
			fprintf(fp_json,"\n } }");
			fclose(fp_json);
		}

		if(!first){
			int c,d=0,x,y;
			FILE *hp=NULL;
			/*FILE* hp=fopen("/tmp/.hash.log","a");
			fprintf(hp,"%24.24s speed:%d nr:%.3f (%.3f) hr:%.3f good:%d err:%d spi-err:%d miso-err%d good:%d bad:%d off:%d jobs:%d (%.3f)\n",ctime(&ntime),
				speed,nr,(nr/chips),hr,nrate,error,espi,miso,c_good,c_bad,c_off,job-last,record);
			for(c=0;c<chips;c++){
				switch(chipchange[c]){
					case 1: fprintf(hp,"%d:up ",c+1); d++; break;
					case 2: fprintf(hp,"%d:down ",c+1); d++; break;
					case 3: fprintf(hp,"%d:to0 ",c+1); d++; break;
					case 4: fprintf(hp,"%d:shut ",c+1); d++; break;
					case 5: fprintf(hp,"%d:off ",c+1); d++; break;
					default: break;}}
			if(d){
				fprintf(hp,"\n");}
			fclose(hp);*/
			hp=fopen(".core.log","w");
			for(c=0;c<chips;c++){
				d=0;
				for(y=35;y>=0;y--){
					fprintf(hp,"%d\t",c+1);
					for(x=0;x<21;x++){
						if(!chipcoor[c][x][y]){
							d++;}
						fprintf(hp," %3d",chipcoor[c][x][y]);}
					fprintf(hp,"\n");}
				fprintf(hp,"%d\t%d\n\n",c+1,d);}
			fclose(hp);
			if(record<nr){
				record=nr;
				//system("/bin/cp -f .stat.log /tmp/.best.log");}}
				system("/bin/cp -f .stat.log .best.log");}}
		if(wait>=5*60){
			otime=ntime;
			memset(chipgood,0,sizeof(chipgood));
			memset(chipmiss,0,sizeof(chipmiss));
			memset(chiphash,0,sizeof(chiphash));
			memset(chipespi,0,sizeof(chipespi));
			memset(chipmiso,0,sizeof(chipmiso));
			memset(chipdupl,0,sizeof(chipdupl));
			last=job;
			first=0;}}
}
int main(int argc,char** argv)
{	int chips=0;

        if(argc>=4){
                minspeed=atoi(argv[1]);
                defspeed=atoi(argv[2]);
                maxspeed=atoi(argv[3]);}
        printf("SPEED: min:%d def:%d max:%d\n",minspeed,defspeed,maxspeed);
	get_start();
	put_start();
	chip_init();
	chips=spi_start(chipconf,chipfast,chipcard);
	printf("INIT: %d chips detected\n",chips);

	for (;;) {
		spi_miner(chips,chipconf,chipfast); // same as cpu_miner();
		chip_stat(chips);
	}

	spi_close();
	return 0;
}

