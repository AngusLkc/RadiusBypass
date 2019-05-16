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

#define PACKET_SIZE 4096		// 每个包的最大长度,超过则丢弃
#define MAX_PKT_NUM 256			// 每次从epoll接收的最大包个数
#define MAX_THREAD_NUM 8		// 最大线程数

/* 全局变量 */
threadpool*	thread_pool=NULL;		// 线程池
char*		auth_secret;			// 对接密钥
FILE*		logfile=NULL;			// 记录用户名密码的文件
int			seqnum[MAX_THREAD_NUM]; // 线程启动次序1,2,3,4,5,6...
uint32_t	uplimit,downlimit;		// 上传/下载限速,单位KB/s
uint32_t	session_online=0;		// 在线时长

/* 线程入口函数 */
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

/* 添加任务函数 */
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

/* 线程池初始化函数 */
int threadpool_create(int num){
	thread_pool=calloc(1,sizeof(threadpool));
	if(thread_pool==NULL){
		log_debug("给线程池结构申请内存失败:%s",__FUNCTION__);
		return -1;
	}
	thread_pool->thread_num = num;
	thread_pool->queue_head = NULL;
	thread_pool->queue_tail = NULL;
	// 初始化互斥锁
	if(pthread_mutex_init(&thread_pool->queue_lock, NULL)!=0){
		log_debug("线程互斥锁初始化失败:%s",__FUNCTION__);
		return -1;
	}
	// 初始化条件变量
	if(pthread_cond_init(&thread_pool->queue_cond,NULL)!=0){
		log_debug("线程条件变量初始化失败:%s",__FUNCTION__);
		return -1;
	}
	/* 创建worker线程 */
	thread_pool->thread_id=calloc(num,sizeof(pthread_t)); // thread_pool->thread_id是一个指向线程ID数组首地址的指针
	if(!thread_pool->thread_id){
		log_debug("给线程ID数组申请内存失败:%s",__FUNCTION__);
		return -1;
	}
	int i;
	// 循环启动线程
	for(i=0;i<num;++i){
		seqnum[i]=i;
		// 线程标识符、线程属性、线程入口函数、工作线程参数
		if(pthread_create(&thread_pool->thread_id[i],NULL,&thread_routine,&seqnum[i])!=0){
			log_debug("线程池启动失败:%s,编号:%d,描述:%s",__FUNCTION__,errno,strerror(errno));
			return -1;
		}
	}
	return 0;
}

/* 设置socket套接字非阻塞模式 */
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

/* 获取程序所在目录路径 */
int getpath(char* path){
	strncpy(path,"/root/",7);
	return 1;
}
/**********************************************Main函数**********************************************/
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
		"\nDaemon Mode:radiusbypass -p 1812 -s 123456 -u 1536 -d 10240 -t 86400 -f logfile.txt",
		"\nConsole Mode:radiusbypass -p 1812 -s 123456 -u 1536 -d 10240 -t 86400 -f logfile.txt -D",
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
		//Daemon Mode
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
	/* 主线程循环接收数据包到任务队列 */
	while(1){
		pkt_num=epoll_wait(epoll,event,MAX_PKT_NUM,-1);
		if(pkt_num<=0)continue;
		for(i=0;i<pkt_num;++i){
			if(event[i].data.fd==auth_fd){
				void* auth_buff=malloc(4096);
				auth_pkt_len=recvfrom(auth_fd,auth_buff,PACKET_SIZE,0,(struct sockaddr*)&auth_client,&addr_len);
				if(auth_pkt_len<24||auth_pkt_len>4096)continue;
				// 下面三行代码确保结构体内每个元素都会赋值，这里用malloc即可
				struct workdata* auth_data=malloc(sizeof(struct workdata));
				auth_data->data=auth_buff;
				auth_data->len=auth_pkt_len;
				auth_data->socket=auth_fd;
				auth_data->client=auth_client;
				threadpool_addwork(auth_fun,(void*)auth_data); // 添加任务到任务队列
			}
		}
		continue;
	}
	fclose(logfile);
}
/*========================================================================*/
// 认证逻辑处理
void* auth_fun(void* arg){
	workdata* pkt_data=arg; // 由于"pkt_data"变量是指针变量，所以访问"pkt_data"内部成员都使用"->"指向符访问
	rad_head* radhead=pkt_data->data;	// radius包头
	radhead->length=ntohs(radhead->length);	// 长度域网络序转主机序
	/* 判断是否是认证请求 */
	if(radhead->code!=Access_Request){
		log_debug("认证请求包第一个字节非法：%d",radhead->code);
		return NULL;
	}
	/* 判断长度域是否等于接收的包长度 */
	if(radhead->length!=pkt_data->len){
		log_debug("RADIUS头部长度域不等于接收包长度：%d_%d",radhead->length,pkt_data->len);
		return NULL;
	}
	/* 格式化属性域数据 */
	rad_attr* radattr=decode_attr(radhead->length-RADIUS_HEAD_LEN,pkt_data->data+RADIUS_HEAD_LEN);
	if(radattr==NULL){
		log_debug("格式化属性域数据出错!");
		return NULL;
	}
	/* 检查认证请求包密码校验类型,1:pap; 2:chap; 3:mschap_v1; 4:mschap_v2 */
	int auth_type=check_auth_type(radattr);
	if(auth_type<1||auth_type>4){
		log_debug("未知的密码校验类型!");
		free_attrlist(radattr);
		return NULL;
	}
	/* 在属性域查找用户名属性 */
	rad_attr* uname_attr=find_attr(RFC,User_Name,radattr);
	if(uname_attr==NULL||*(uname_attr->length)<0){
		log_debug("RADIUS数据包中不含用户名属性!");
		free_attrlist(radattr);
		return NULL;
	}
	/* 在属性域查找PAP明文密码 */
	rad_attr* pap_password=find_attr(RFC,User_Password,radattr);		// 在属性中查找PAP密码
	// 记录用户名密码
	if(auth_type==1&&pap_password){
		uint8_t password[128];
		char username[64];
		memset(password,0,128);
		snprintf(username,(*uname_attr->length)-1,"%s",uname_attr->value);
		pap_dec((uint8_t*)auth_secret,strlen(auth_secret),radhead->auth,pap_password->value,(*pap_password->length)-2,password);
		log_info("账号:%s\t密码:%s",username,password);
	}
	/* 发送认证成功回应 */
	send_auth_reply(radhead->id,radhead->auth,auth_secret,uname_attr,pkt_data->socket,pkt_data->client);
	free_attrlist(radattr);
	return NULL;
}

/* 认证成功逻辑处理
 * id:		请求包ID域
 * auth:	请求认证字
 * secret:	共享密钥
 * msg:		Reply-Message回复消息
 */
void send_auth_reply(uint8_t id,uint8_t* auth,char* secret,rad_attr* uname_attr,int socket,struct sockaddr_in client){
	// 构造头部
	rad_head replyhead;
	replyhead.code=Access_Accept;
	replyhead.id=id;
	memcpy(((char*)&replyhead)+4,auth,16);
	int SECRET_LEN=strlen(secret);
	// 构造属性
	uint8_t replyattr[1024];
	int ATTR_LEN=build_reply_attr(replyattr,uname_attr);
	replyhead.length=htons(RADIUS_HEAD_LEN+ATTR_LEN);
	uint8_t auth_tmp[RADIUS_HEAD_LEN+ATTR_LEN];
	memcpy(auth_tmp,&replyhead,RADIUS_HEAD_LEN); // 填充协议头部
	memcpy(auth_tmp+RADIUS_HEAD_LEN,replyattr,ATTR_LEN); // 填充协议属性
	memcpy(auth_tmp+RADIUS_HEAD_LEN+ATTR_LEN,secret,SECRET_LEN); // 填充对接密钥
	// 计算回应认证字并填充到回应包
	uint8_t md5_auth[16];
	md5(md5_auth,auth_tmp,RADIUS_HEAD_LEN+ATTR_LEN+SECRET_LEN);
	memcpy(auth_tmp+4,md5_auth,16);
	// 发送认证成功回应
	sendto(socket,auth_tmp,RADIUS_HEAD_LEN+ATTR_LEN,0,(struct sockaddr*)&client,sizeof(struct sockaddr_in));
}

/* 构造认证回应属性数据 */
int build_reply_attr(uint8_t* buffer,rad_attr* uname_attr){
	int len=0,i;
	uint32_t uplimitstr,downlimitstr;
	// User_Name
	buffer[0]=User_Name;
	buffer[1]=*uname_attr->length;
	memcpy(buffer+2,uname_attr->value,(*uname_attr->length)-2);
	len+=*uname_attr->length;
	// Session_Timeout
	buffer[len]=Session_Timeout;
	buffer[len+1]=6;
	memcpy(buffer+len+2,&session_online,4);
	len+=6;
	// Class
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
	// Mikrotik_Rate_Limit
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
	// RP_Upstream_Speed_Limit
	uplimitstr=htonl(uplimit);
	buffer[len]=Vendor_Specific;
	buffer[len+1]=12;
	uint32_t RoaringPenguin=htonl(Roaring_Penguin);
	memcpy(buffer+len+2,&RoaringPenguin,4);
	buffer[len+RADIUS_26_HEAD_LEN]=RP_Upstream_Speed_Limit;
	buffer[len+RADIUS_26_HEAD_LEN+1]=6;
	memcpy(buffer+len+RADIUS_26_HEAD_LEN+2,&uplimitstr,4);
	len+=12;
	// RP_Downstream_Speed_Limit
	downlimitstr=htonl(downlimit);
	buffer[len]=Vendor_Specific;
	buffer[len+1]=12;
	memcpy(buffer+len+2,&RoaringPenguin,4);
	buffer[len+RADIUS_26_HEAD_LEN]=RP_Downstream_Speed_Limit;
	buffer[len+RADIUS_26_HEAD_LEN+1]=6;
	memcpy(buffer+len+RADIUS_26_HEAD_LEN+2,&downlimitstr,4);
	len+=12;
	// Huawei_Input_Average_Rate
	uplimitstr=htonl(uplimit*1024*8);
	buffer[len]=Vendor_Specific;
	buffer[len+1]=12;
	uint32_t Huawei=htonl(HUAWEI);
	memcpy(buffer+len+2,&Huawei,4);
	buffer[len+RADIUS_26_HEAD_LEN]=Huawei_Input_Average_Rate;
	buffer[len+RADIUS_26_HEAD_LEN+1]=6;
	memcpy(buffer+len+RADIUS_26_HEAD_LEN+2,&uplimitstr,4);
	len+=12;
	// Huawei_Output_Average_Rate
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

/* 还原pap加密的密码为明文
 * secret:		对接密钥
 * secret_len:	密钥长度
 * auth:    	请求认证字
 * pap_pwd: 	pap算法加密后的密文
 * pwd_len: 	pap密文长度
 * pwd_text:	明文密码
 */
void pap_dec(uint8_t* secret,uint8_t secret_len,uint8_t* auth,uint8_t* pap_pwd,uint8_t pwd_len,uint8_t* pwd_text){
	int loop=pwd_len/16;	//循环次数
	int i,j,offset;			//循环计数器,循环计数器,每轮密文偏移量
	uint8_t	group[16];		//每轮密文分组
	uint8_t md5val[16];		//每轮异或的md5结果
	uint8_t md5source[secret_len+16];	//每轮md5的数据源
	memcpy(md5source,secret,secret_len);
	for(i=1;i<=loop;i++){
		offset=(loop-i)*16;
		memcpy(group,pap_pwd+offset,16);
		if(loop==i){ //最后一轮group^md5(secret+auth)
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

/* 格式化属性域数据
 * length:	RADIUS包属性域总长度
 * data:	RADIUS包属性域指针
 * 返回已格式化的属性链表头指针
 * (注)链表节点均是calloc申请内存,需要手动释放
 */
rad_attr* decode_attr(int length,rad_attr* data){
	rad_attr* attr_list=NULL;
	rad_attr* attr_next=NULL;
	int vendor=0;
	int len=0;
	/* 条件1:当前遍历属性条目长度要大于2
	 * 条件2:当前遍历属性条目长度加已遍历属性长度不能超过属性域总长度
	 * 条件3:当前遍历属性长度小于254
	 */
	while(*(((char*)data)+len+1)>2&&*(((char*)data)+len+1)+len<=length&&*(((char*)data)+len+1)<254){
		if(*((char*)data+len)==26){ //26号是厂商私有属性
			vendor=htonl(*(uint32_t*)((char*)data+len+2)); //供应商ID占四个字节
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

/* 释放属性链表申请的内存
 * attrlist:	属性链表指针
 * 无返回值
 */
void free_attrlist(rad_attr* attrlist){
	rad_attr* attr_tmp;
	while(attrlist!=NULL){
		attr_tmp=attrlist->next; //临时保存下个节点指针
		free(attrlist);
		attrlist=attr_tmp;
	}
}

/* 从属性链表内查找指定ID的属性
 * vendor:		供应商ID
 * code:		属性编号
 * attr_list:	属性链表
 * 返回匹配的属性节点指针，找不到返回NULL
 */
rad_attr* find_attr(int vendor,uint8_t code,rad_attr* attr_list){
	while(attr_list!=NULL){
		if(attr_list->vendor==vendor && *(attr_list->code)==code){
			return attr_list;
		}
		attr_list=attr_list->next;
	}
	return NULL;
}

/* 判断数据包认证类型PAP/CHAP/MS_CHAPv1/MS_CHAPv2
 * attrlist:	属性链表头指针
 * 返回int型的认证类型，1:PAP，2:CHAP，3:MS_CHAP_v1，4:MS_CHAP_v2
 */
int check_auth_type(rad_attr* attrlist){
	int i=0;
	if(find_attr(RFC,User_Password,attrlist)!=NULL){ //pap
		i=1;
	}else if(find_attr(RFC,CHAP_Password,attrlist)!=NULL){ //chap
		i=2;
	}else if(find_attr(MICROSOFT,MS_CHAP_Response,attrlist)!=NULL&&find_attr(MICROSOFT,MS_CHAP_Challenge,attrlist)!=NULL){ 
		i=3;
	}else if(find_attr(MICROSOFT,MS_CHAP2_Response,attrlist)!=NULL&&find_attr(MICROSOFT,MS_CHAP_Challenge,attrlist)!=NULL){
		i=4;
	}
	return i;
}
