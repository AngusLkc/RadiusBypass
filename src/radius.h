#define RADIUS_HEAD_LEN 20
#define RADIUS_26_HEAD_LEN 6
#define Access_Request 1
#define Access_Accept 2
#define Access_Reject 3
#define RFC 0
#define MICROSOFT 311
#define HUAWEI 2011
#define Roaring_Penguin 10055
#define MIKROTIK 14988
#define User_Name 1
#define User_Password 2
#define CHAP_Password 3
#define Class 25
#define Vendor_Specific 26
#define Session_Timeout 27
#define Idle_Timeout 28
#define MS_CHAP_Response 1
#define MS_CHAP_Challenge 11
#define MS_CHAP_MPPE_Keys 12
#define MS_MPPE_Send_Key 16
#define MS_MPPE_Recv_Key 17
#define MS_CHAP2_Response 25
#define MS_CHAP2_Success 26
#define Mikrotik_Rate_Limit 8
#define RP_Upstream_Speed_Limit 1
#define RP_Downstream_Speed_Limit 2
#define Huawei_Input_Average_Rate 2
#define Huawei_Output_Average_Rate 5
typedef enum{
    false,
    true
}bool;
typedef struct rad_head{
    uint8_t code;
    uint8_t id;
    uint16_t length;
    uint8_t auth[16];
}rad_head;
typedef struct rad_attr{
    int vendor;
    uint8_t* code;
    uint8_t* length;
    uint8_t* value;
    struct rad_attr* next;
}rad_attr;
typedef struct workdata{
    void* data;
    int len;
    int socket;
    struct sockaddr_in client;
}workdata;
typedef struct threadwork{
    void* (*fun)(void*);
    void* arg;
    struct threadwork* next;
}threadwork;
typedef struct threadpool{
    int shutdown;
    int thread_num;
    pthread_t* thread_id;
    threadwork* queue_head;
    threadwork* queue_tail;
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_cond;
}threadpool;
void* thread_routine(void*);
int threadpool_addwork(void*(*fun)(void*),void*);
int threadpool_create(int);
void setnonblocking(int);
int getpath(char*);
void* auth_fun(void*);
void send_auth_reply(uint8_t,uint8_t*,char*,rad_attr*,int,struct sockaddr_in);
int build_reply_attr(uint8_t* buffer,rad_attr* uname_attr);
void pap_dec(uint8_t*,uint8_t,uint8_t*,uint8_t*,uint8_t,uint8_t*);
rad_attr* decode_attr(int length,rad_attr* data);
void free_attrlist(rad_attr* attrlist);
int check_auth_type(rad_attr* attrlist);
rad_attr* find_attr(int,uint8_t,rad_attr*);
