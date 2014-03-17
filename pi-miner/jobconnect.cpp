#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <json/jsonrpc.h>
#include <assert.h>
#include <signal.h>
#include "bc_bignum.h"
#include "handylib.h"
#include "miner.h"

using namespace handylib;

//echo -n 'user:pass' | base64
//const char *auth = "Basic Yml0Y29pbnJwYzo2YkIxbWR4ZWVLS2JWVVdrRFpxYWlCb3BTVm90UTYxS0pqUTRodmVSTmlORA==";
//const char *jsonurl = "http://192.168.10.253:8332/"; // pico @ home

#define MAXHOSTS 8
hosts_t hosts[MAXHOSTS]={
	        //{"Basic bW9yYXNrb19mcGdhOm1vcmFza29fZnBnYV9wYXNz","http://10.10.1.1:8332",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0},
	        //{"Basic bW9yYXNrb19mcGdhOm1vcmFza29fZnBnYV9wYXNz","http://10.10.1.1:8334",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0},
	        //{"Basic bW9yYXNrb19mcGdhOm1vcmFza29fZnBnYV9wYXNz","http://10.10.2.1:8332",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0},
	        //{"Basic bW9yYXNrb19mcGdhOm1vcmFza29fZnBnYV9wYXNz","http://10.10.2.1:8334",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0},
	        //{"Basic bW9yYXNrb19mcGdhOm1vcmFza29fZnBnYV9wYXNz","http://10.10.3.1:8332",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0},
	        //{"Basic bW9yYXNrb19mcGdhOm1vcmFza29fZnBnYV9wYXNz","http://10.10.3.1:8334",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0}
	        //{"Basic bW9yYXNrb19mcGdhOm1vcmFza29fZnBnYV9wYXNz","http://10.10.100.1:8332",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0},
	        //{"Basic bW9yYXNrb19mcGdhOm1vcmFza29fZnBnYV9wYXNz","http://10.10.100.1:8334",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0},
		//{"Basic dHl0dXMucGkxOnB1YmxpY3Bhc3M=","http://10.10.100.1:8336",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0}, 
		//{"Basic dHl0dXMucGkxOnB1YmxpY3Bhc3M=","http://10.10.100.1:8338",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0} 


//for local stratum start 
	{"Basic dHl0dXMucGkxOnB1YmxpY3Bhc3M=","http://localhost:8332",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0}, //slush
	{"Basic dHl0dXMucGkxOnB1YmxpY3Bhc3M=","http://localhost:8333",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0}, //slush
	{"Basic dHl0dXMucGkxOnB1YmxpY3Bhc3M=","http://localhost:8334",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0} //slush
//      ,{"Basic dHl0dXMuZGF2ZXRlc3QxOnB1YmxpY3Bhc3M=","http://localhost:8332",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0} //slush
//      ,{"Basic dHl0dXMuZGF2ZXRlc3QxOnB1YmxpY3Bhc3M=","http://localhost:8333",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0} //slush
//      ,{"Basic dHl0dXMuZGF2ZXRlc3QxOnB1YmxpY3Bhc3M=","http://localhost:8334",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0} //slush
//      ,{"Basic dHl0dXMuenRleDpwdWJsaWNwYXNz","http://localhost:8332",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0} //slush
//      ,{"Basic dHl0dXMuenRleDpwdWJsaWNwYXNz","http://localhost:8333",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0} //slush
//      ,{"Basic dHl0dXMuenRleDpwdWJsaWNwYXNz","http://localhost:8334",{0,0,0,0,0,0,0,0xFFFFFFFF},NULL,NULL,0,0,0} //slush

};

Thread::mutex gwmut;
Thread::mutex pwmut;

class GetworkThread : public Thread
{
	public:
	std::vector<getwork> getworks;
	unsigned char host;
	virtual void Run();
	virtual void log();
};
class PutworkThread : public Thread
{
	public:
	std::vector<putwork> putworks;
	unsigned char host;
	virtual void Run();
	virtual void log();
};

void byte_reverse(uint8_t *p)
{
	uint8_t t[4];
	t[0] = p[3];
	t[1] = p[2];
	t[2] = p[1];
	t[3] = p[0];
	p[0] = t[0];
	p[1] = t[1];
	p[2] = t[2];
	p[3] = t[3];
}
bool parse_ulong(uint32_t *dst, const char *s, unsigned int n, int rev, int brev)
{
	unsigned int i;
	char so[9]; so[8] = 0;
	if (strlen(s) < 8*n) return false;
	for (i = 0; i < n; i++) {
		memcpy(so, &s[i*8], 8);
		if (rev) {
			dst[n-1-i] = strtoul(so,0,16);
			if (brev) byte_reverse((uint8_t*)(&dst[n-1-i]));
		} else {
			dst[i] = strtoul(so,0,16);
			if (brev) byte_reverse((uint8_t*)(&dst[i]));
		}
	}
	return true;
}
void bits2bn(uint32_t *tgt, unsigned int nCompact)
{
	byte_reverse((uint8_t*)&nCompact);

	unsigned int nSize = (nCompact >> 24) & 0xFF;
	printf("nSize: %u\n", nSize);
	memset(tgt,0,32);

	if (nSize > 255) return;
	unsigned char vch[128 + nSize];

	memset(vch, 0, 4 + nSize);
	vch[3] = nSize;
	if (nSize >= 1) vch[4] = (nCompact >> 16) & 0xFF;
	if (nSize >= 2) vch[5] = (nCompact >> 8) & 0xFF;
	if (nSize >= 3) vch[6] = (nCompact >> 0) & 0xFF;

	unsigned char bnbuf[1024];
	memset(bnbuf, 0, sizeof(bnbuf));
	BIGNUM *bn = (BIGNUM*)bnbuf;

	BN_mpi2bn(vch, 4+nSize, bn);

	nSize = BN_bn2mpi(bn, NULL);
	if (nSize < 4) return;

	BN_bn2mpi(bn, vch);
	if (nSize > 4) vch[4] &= 0x7F;

	for (int i = 0, j = nSize - 1; i < 32 && j >= 4; i++, j--)
		((unsigned char*)tgt)[i] = vch[j];
}

static void connect_alarm(int signo)
{
	printf("\nCONNECT TIMEOUT\n");
}
Json::Value make_rpc_req(Json::Value query, bool logit,unsigned char host,int timeout)
{
	HTTPClient cl;
	cl.rh["Authorization"] = hosts[host].aut;
	cl.rh["Connection"] = "close";
	Json::FastWriter writer;
	cl.pr["_full_post"] = writer.write(query);
	if (logit) {
		FILE *fd = fopen(".rpc.log", "w"); // log only 1 transaction
		if (fd) {
			fprintf(fd, "COMPLETE RPC REQUEST:\n%s\nEND OF REQUEST\n", cl.pr["_full_post"].c_str());
			fclose(fd);
		}
	}
        if(timeout){
                signal(SIGALRM,connect_alarm);
                alarm(timeout);
                cl.request(hosts[host].url,true);
                alarm(0);}
        else{
                cl.request(hosts[host].url,true);}
	if (!cl.isOK()) {
		return Json::Value();
	}
	std::string ans;
	while (cl.peek() != EOF) {
		unsigned to_r = cl.rdbuf()->in_avail();
		if (to_r == 0) break;
		if (to_r > 4000) to_r = 4000;
		char tbuf[to_r+2];
		cl.read(tbuf,to_r);
		ans += std::string(tbuf, to_r);
	}
	if (logit) {
		FILE *fd = fopen(".rpc.log", "a");
		if (fd) {
			fprintf(fd, "COMPLETE RPC ANSWER:\n%s\nEND OF ANSWER\n", ans.c_str());
			fclose(fd);
		}
	}
	cl.disconnect();
	Json::Reader reader;
	Json::Value answ;
	if (!reader.parse(ans, answ)) return false;
	if (answ.type() != Json::objectValue) return false;
	answ = answ["result"];
	if (answ.type() != Json::objectValue) return false;
	return answ;
}

/* -------------------------------- getwork -----------------------------------*/
void GetworkThread::log()
{	
	unsigned int i,j;
	char filename[32];
	FILE* fp;
	sprintf(filename,".getwork-%d.log",host);
	fp=fopen(filename, "w");
	gwmut.lock();
	for(i=0;i<getworks.size();i++){
		fprintf(fp,"%u ",getworks[i].mtime);
		for(j=0;j<8;j++){
			fprintf(fp,"%08x", getworks[i].midstate[j]);}
		fprintf(fp,"\n");}
	gwmut.unlock();
	fclose(fp);
}
void GetworkThread::Run()
{
	while(!testCancel()) {
		uint32_t midstate[8]={0,0,0,0,0,0,0,0}, data[32];
		unsigned int i;
		getwork gw;
		uint32_t mtime = time(NULL);
		static uint32_t ltime=0; // last download
		Json::Value query, answ;
		PutworkThread* pwt=(PutworkThread*)hosts[host].pwt;

		if(ltime==mtime){ // limit requests to 1 per second
			threads_sleep(100);
			continue;}

		gwmut.lock();
		if(!getworks.empty()){
                        int h;
                        for(h=0;h<MAXHOSTS;h++){ // check all getwork threads if any has current job
                                GetworkThread* gwt=(GetworkThread*)hosts[h].gwt;
                                if(gwt==NULL || gwt->getworks.empty()){
                                        continue;}
                                if(gwt->getworks.back().mtime==mtime) {
                                        break;}} // this should be a GOTO, I have to start using this
                        if(h<MAXHOSTS){
                                gwmut.unlock();
                                threads_sleep(100);
                                continue;}
			/*if(getworks.back().mtime==mtime) {
				gwmut.unlock(); 
				threads_sleep(100);
				continue;}*/
			for(i=0;i<getworks.size();i++){
				if(getworks[i].mtime>mtime-MAXWORKAGE){
					break;}}
			if(i>0){
				getworks.erase(getworks.begin(),getworks.begin()+i);}}
		gwmut.unlock(); 

		if(pwt==NULL){
			threads_sleep(100);
			continue;}
		if(pwt->putworks.size()>MAXPUTWORK){
			gwmut.lock();
			getworks.clear(); // removes all jobs due to slow queue
			gwmut.unlock(); 
			printf("GETWORK: queue full for host[%d]: %s  \n",host,hosts[host].url);
			threads_sleep(1000);
			continue;}

		query["jsonrpc"] = "2.0";
		query["id"] = 1;
		query["method"] = "getwork";
		answ = make_rpc_req(query, false, host,2);
		if (answ.type() != Json::objectValue){
			threads_sleep(500);
			continue; }
		if (answ["data"].type() != Json::stringValue || !parse_ulong(data, answ["data"].asCString(), 32, 0, 1)){
			threads_sleep(500);
			continue; }
		if (answ["midstate"].type() != Json::stringValue || !parse_ulong(midstate, answ["midstate"].asCString(), 8, 0, 1)) { 
			const unsigned sha_initial_state[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
			SHA256_Full(midstate, data, sha_initial_state); }

		gwmut.lock();
		if(!getworks.empty()){
			if (memcmp( ((btc_block_t*)data)->hashPrevBlock, ((btc_block_t*)getworks.front().data)->hashPrevBlock, 32)) { // removes all jobs in last block
				//try clearing all queues
				int h;
				for(h=0;h<MAXHOSTS;h++){
					GetworkThread* gwt=(GetworkThread*)hosts[h].gwt;
                                	if(gwt==NULL){
						continue;}
					gwt->getworks.clear();}
				// clear our again just in case :-)
				getworks.clear();
				gwmut.unlock();
				pwmut.lock();
				if (answ["target"].type() != Json::stringValue || !parse_ulong(hosts[host].target, answ["target"].asCString(), 8, 0, 1)) {
					bits2bn(hosts[host].target,  ((btc_block_t*)data)->nBits );
				}
				pwmut.unlock();
				gwmut.lock(); } }
		else{
			if(hosts[host].target[7]==0xFFFFFFFF){
				gwmut.unlock();
				pwmut.lock();
				if (answ["target"].type() != Json::stringValue || !parse_ulong(hosts[host].target, answ["target"].asCString(), 8, 0, 1)) {
					bits2bn(hosts[host].target,  ((btc_block_t*)data)->nBits );
				}
				pwmut.unlock();
				gwmut.lock(); } }
		gw.mtime=mtime;
		memcpy(gw.data,data,sizeof(data));
		memcpy(gw.midstate,midstate,sizeof(midstate));
		getworks.push_back(gw);
		gwmut.unlock();
		ltime=mtime;
		//log();
		}
}

uint32_t get_work(uint32_t *midstate, uint32_t *data)
{
	getwork gw;
	uint32_t mtime;
	int h;
	static unsigned char host=0;

        gwmut.lock();
	for(h=0;h<MAXHOSTS;h++,host++){
		host=host%MAXHOSTS;
		GetworkThread* gwt=(GetworkThread*)hosts[host].gwt;
		if(gwt==NULL){
			continue;}
		if(!gwt->getworks.empty()){
			mtime=gwt->getworks.back().mtime;
			memcpy(data,gwt->getworks.back().data,sizeof(gw.data));
			memcpy(midstate,gwt->getworks.back().midstate,sizeof(gw.midstate));
			//add host signature to data
			if(((char*)data)[0]!=0){
				printf("ERROR: got incompatible data header char: %d\n",(int)(((char*)data)[0]));
				gwt->getworks.pop_back();
       				gwmut.unlock();
				return 0;}
			memcpy(data,&host,1);
			gwt->getworks.pop_back();
       			gwmut.unlock();
			hosts[host].got++;
			return mtime;}}
	gwmut.unlock();
	threads_sleep(100); //sleep here rather than in C part
	return 0;
}
void get_start()
{
	int h;
	FILE* fp=fopen(".host.cnf","r");
	static char buf[MAXHOSTS][2][256];
	char line[256];

	if(fp!=NULL){
		for(h=0;h<MAXHOSTS && fgets(line,256,fp)!=NULL;h++){
			if(sscanf(line,"%s %s",buf[h][0]+6,buf[h][1]+0)!=2){
				printf("ERROR: wrong format in line %d of .host.cnf, fatal\n%s\n",h+1,line);
				exit(-1);}
			strncpy(buf[h][0],"Basic ",6);
			hosts[h].aut=buf[h][0];
			hosts[h].url=buf[h][1];}
		fclose(fp);}
	for(h=0;h<MAXHOSTS;h++){
		if(hosts[h].url==NULL){
			continue;}
		GetworkThread *gwt = new GetworkThread();
		hosts[h].gwt=gwt;
		gwt->host=h;
		gwt->Start();}
}

/* -------------------------------- putwork -----------------------------------*/


void PutworkThread::log()
{
        unsigned int i,j;
        char filename[32];
        FILE* fp;
        sprintf(filename,".putwork-%d.log",host);
        fp=fopen(filename, "w");
        gwmut.lock();
	fprintf(fp,"%d\n",putworks.size());
        for(i=0;i<putworks.size();i++){
                for(j=16;j<20;j++){
                        fprintf(fp,"%08x", putworks[i].data[j]);}
                fprintf(fp,"\n");}
        gwmut.unlock();
        fclose(fp);
}
void PutworkThread::Run() // just send data, don't check anything (again)
{
	for(;;){
		uint32_t data[32];
		char ustr[258];
		unsigned int k;
		//FILE* fd;

		pwmut.lock();
		if(putworks.empty()){
			pwmut.unlock();
			if(testCancel()){
				break;}
			threads_sleep(100);
			continue;}
		memcpy(data,putworks.front().data, sizeof(data));
		putworks.erase(putworks.begin());
		pwmut.unlock();
	        for(k=0;k<32;k++) {
			byte_reverse((uint8_t*)(&data[k]));
			sprintf(&ustr[k*8],"%08x",data[k]);}
		ustr[256] = 0;
		//fd=fopen(".putwork.log", "a");
		//fprintf(fd,"%u %s\n",time(NULL),ustr);
		//fclose(fd);
                Json::Value query;
                query["jsonrpc"] = "2.0";
                query["id"] = 1;
                query["method"] = "getwork";
                query["params"][0] = std::string(ustr);
                Json::Value answ = make_rpc_req(query, false, host,60); // only one save
		// here we should check if the answer is ok
		hosts[host].sent++;
		//log();
		}
}
void put_work(uint32_t *data,uint32_t* hash)
{
	//FILE* fd;
	int k;
	unsigned char host;
	for(k=0;k<7;k++){ // Reverse byte order !
		byte_reverse((uint8_t*)(&hash[k]));}
	memcpy(&host,data,1);
	for(k=7;k>0;k--){
		if(hash[k]<hosts[host].target[k]){ // hash meets difficulty
			PutworkThread* pwt;
			putwork pw;
			memset(data,0,1);
			pwt=(PutworkThread*)hosts[host].pwt;
			memcpy(pw.data,data,sizeof(uint32_t)*32);
			pwmut.lock();
			pwt->putworks.push_back(pw);
			pwmut.unlock();
			hosts[host].done++;
			//fd=fopen(".putwork.log", "a");
			//fprintf(fd,"%lu %08x-%08x-%08x-%08x-%08x-%08x-%08x-%08x %d good\n",time(NULL),hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7],k);
			//fclose(fd);
			//printf("SENDING: %08x-%08x-%08x-%08x-%08x-%08x-%08x-%08x\n",hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7]);
			return;}
		if(hash[k]>hosts[host].target[k]){
			//fd=fopen(".putwork.log", "a");
			//fprintf(fd,"%lu %08x-%08x-%08x-%08x-%08x-%08x-%08x-%08x %d easy\n",time(NULL),hash[0],hash[1],hash[2],hash[3],hash[4],hash[5],hash[6],hash[7],k);
			//fclose(fd);
			return;}}
}
void put_start()
{
	int h;
	for(h=0;h<MAXHOSTS;h++){
		if(hosts[h].url==NULL){
			continue;}
		PutworkThread *pwt = new PutworkThread();
		hosts[h].pwt=pwt;
		pwt->host=h;
		pwt->Start();}
}
int put_queue()
{
	FILE* fd=fopen(".putstat.log", "w");
	int size=0,h;
	for(h=0;h<MAXHOSTS;h++){
		if(hosts[h].url==NULL){
			continue;}
		PutworkThread *pwt = (PutworkThread*)hosts[h].pwt;
		GetworkThread *gwt = (GetworkThread*)hosts[h].gwt;
		size+=pwt->putworks.size();
		fprintf(fd,"%d %d %d %d %d [%d]%s\n",pwt->putworks.size(),gwt->getworks.size(),hosts[h].got,hosts[h].done,hosts[h].sent,(int)(pwt->host),hosts[h].url);}
	fclose(fd);
	return size;
}
