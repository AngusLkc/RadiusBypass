#define RADIUS_HEAD_LEN		20	/* RADIUS数据包头部长度 */
#define RADIUS_26_HEAD_LEN	6	/* RADIUS私有(26)属性头部长度 */

/* 认证请求,认证允许,认证拒绝 */
#define Access_Request		1
#define Access_Accept		2
#define Access_Reject		3

/* 厂商代码定义 */
#define RFC		        0
#define MICROSOFT	    311
#define HUAWEI          2011
#define Roaring_Penguin 10055
#define MIKROTIK        14988

/* RADIUS标准属性 */
#define User_Name			1
#define User_Password		2
#define CHAP_Password       3
#define Class               25
#define Vendor_Specific     26
#define Session_Timeout     27
#define Idle_Timeout        28

/* Microsoft私有属性 */
#define MS_CHAP_Response	1
#define MS_CHAP_Challenge	11
#define MS_CHAP_MPPE_Keys	12
#define MS_MPPE_Send_Key	16
#define MS_MPPE_Recv_Key	17
#define MS_CHAP2_Response	25
#define MS_CHAP2_Success	26

/* MikroTik私有属性 */
#define Mikrotik_Rate_Limit 8

/* Roaring-Penguin私有属性(*) */
#define RP_Upstream_Speed_Limit     1
#define RP_Downstream_Speed_Limit   2

/* Huawei私有属性 */
#define Huawei_Input_Average_Rate   2
#define Huawei_Output_Average_Rate  5

/* 用枚举实现布尔型 */
typedef enum{
	false,
	true
}bool;

/* RADIUS协议头部 */
typedef struct rad_head{
	uint8_t		code;		// 代码域
	uint8_t		id;			// ID域
	uint16_t	length;		// 长度域
	uint8_t		auth[16];	// 认证字域
}rad_head;

/* RADIUS属性三元组 */
typedef struct rad_attr{
	int			vendor;		// 属性类型rfc/private
	uint8_t*	code;		// 属性ID
	uint8_t*	length;		// 属性长度
	uint8_t*	value;		// 属性值指针
	struct rad_attr* next;	// 下个属性指针
}rad_attr;

/* 任务处理函数参数结构 */
typedef struct workdata{
    void*	data;		// 缓冲区接收的数据
    int		len;		// 从socket接收的长度
	int		socket;		// 建立连接的udp_socket
    struct sockaddr_in client; // 指向socket_client
}workdata;

/* 队列内每个任务节点结构 */
typedef struct threadwork{
    void*	(*fun)(void*);		// 任务处理函数指针
    void*	arg;				// 任务处理函数参数
    struct threadwork* next;	// 下一个任务指针
}threadwork;

/* 线程池结构 */
typedef struct threadpool{
    int				shutdown;	// 线程池关闭标志
    int				thread_num;	// 最大线程数
    pthread_t*		thread_id;	// 线程ID数组
    threadwork*		queue_head;	// 任务链表队首
    threadwork*		queue_tail;	// 任务链表队尾
    pthread_mutex_t	queue_lock;	// 任务队列互斥锁
    pthread_cond_t	queue_cond;	// 线程条件变量
}threadpool;

/* 线程入口函数 */
void* thread_routine(void*);

/* 添加任务到任务队列函数 */
int threadpool_addwork(void*(*fun)(void*),void*);

/* 初始化创建线程池函数 */
int threadpool_create(int);

/* 设置socket无阻塞模式 */
void setnonblocking(int);

/* 获取程序所在目录路径 */
int getpath(char*);

/* 认证包处理函数 */
void* auth_fun(void*);

/* 认证成功逻辑处理 */
void send_auth_reply(uint8_t,uint8_t*,char*,rad_attr*,int,struct sockaddr_in);

/* 构造认证回应属性数据 */
int build_reply_attr(uint8_t* buffer,rad_attr* uname_attr);

/* 还原pap加密的密码为明文 */
void pap_dec(uint8_t*,uint8_t,uint8_t*,uint8_t*,uint8_t,uint8_t*);

/* 格式化属性域数据 */
rad_attr* decode_attr(int length,rad_attr* data);

/* 释放属性链表申请的内存 */
void free_attrlist(rad_attr* attrlist);

/* 判断数据包认证类型PAP/CHAP/MS_CHAPv1/MS_CHAPv2 */
int check_auth_type(rad_attr* attrlist);

/* 从属性链表内查找指定ID的属性 */
rad_attr* find_attr(int,uint8_t,rad_attr*);
