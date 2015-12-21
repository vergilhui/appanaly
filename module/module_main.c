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
MODULE_AUTHOR("vergilhui");
MODULE_DESCRIPTION("Android App Behavior Record");

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

static struct nf_hook_ops out_nfho;

static int init_nfcheck(void)
{
	out_nfho.hook = nfhook;
	out_nfho.owner = THIS_MODULE;
	out_nfho.hooknum = NF_IP_LOCAL_OUT;
	out_nfho.pf = PF_INET;
	out_nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&out_nfho);
	return 0;
}

unsigned int nfhook(
	unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;

	iph = (struct iphdr *)skb_network_header(skb);
	char msg[128] = {0};
	snprintf(msg, 128,
		"{'netObject':['saddr':'%d', 'daddr':'%d', 'protocol':'%d']}\n",
		iph->saddr, iph->daddr, iph->protocol);
	kernel_send_nl_msg(strim(msg));
 	printk("network!");
}

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

int new_open(const char *file, int flag, mode_t mode)
{
	char *contact = "/data/data/com.android.providers.contacts/databases/contacts2.db";
  	char *telephony = "/data/data/com.android.providers.telephony/databases/telephony.db";
  	char *sms = "/data/data/com.android.providers.telephony/databases/mmssms.db";
  	char *apk = ".apk";
  	unsigned type = -1;
  	if ((type = (strcmp(file, contact) == 0) ? 1:0)
  		|| (type = (strcmp(file, telephony) == 0) ? 2:0)
  		|| (type = (strcmp(file, sms) == 0) ? 3:0
  		|| (strstr(s1, s2) && type = (strlen(strstr(s1, s2)) == strlen(s2) ? 4:0))
  	{
  		char msg[128] = {0};
		snprintf(msg, 128, "{'pvcObject':['path':'%s', 'type':'%d', action':'open']}\n", buf, type);
		kernel_send_nl_msg(strim(msg));
 		printk("Open privacy file! Path: %s!!!\n", file);
	}
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
	nf_unregister_hook(&out_nfho);
	printk("remove module success!");
}
