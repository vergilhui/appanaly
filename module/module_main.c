#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("vergilhui");
MODULE_DESCRIPTION("Android App Behavior Record");

//static void **sys_call_table;
#define SYS_CALL_TB 0xc000da84
#define MY_GROUP 1
#define MAX_SIZE 1024
#define SMS "AT+CMGS"
#define IMEI "AT+CGSN"
#define CALL "ATD"
#define HANGUP "ATH"
#define AWCALL "ATA"
#define AUTOAW "ATS0"
#define SHANGUP "AT+CHUP"
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

unsigned long *sys_call_table = (unsigned long *)SYS_CALL_TB;
int (*orig_write)(unsigned int fd, char *buf, unsigned int count);
int (*orig_open)(const char *file, int flag, mode_t mode);
unsigned long i_sms_len = -10;

struct task_struct *mythread = NULL;
struct sock *nl_sk = NULL;
struct sk_buff *socket_buff = NULL;

static void nl_receive_callback (struct sk_buff *skb)
{
	printk("Free sk_buff!\n");
    nlmsg_free(skb);
}

static void kernel_send_nl_msg(const char *msg)
{
    struct nlmsghdr *nlsk_mh;
    //struct sk_buff *socket_buff;
    
    socket_buff = nlmsg_new(MAX_SIZE, GFP_KERNEL);
    if (!socket_buff)
    	printk("socket_buff NULL\n");

    nlsk_mh = nlmsg_put(socket_buff, 0, 0, NLMSG_DONE, MAX_SIZE, 0);
    if (!nlsk_mh)
    	printk("nlsk_mh NULL\n");

    NETLINK_CB(socket_buff).pid = 0;
    NETLINK_CB(socket_buff).dst_group = MY_GROUP;

    if (!msg)
    	printk("msg NULL \n");
    strcpy(nlmsg_data(nlsk_mh), msg);

    nlmsg_multicast(nl_sk, socket_buff, 0, MY_GROUP, GFP_KERNEL);

    return;
}

/*unsigned int nfhook(
	unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	char inetmsg[128] = {0};
	//struct udphdr *udph;
	//struct tcphdr *tcph;
	__be32 sip, dip;

	if (skb)
	{
		iph = ip_hdr(skb);
		if (iph	&& (iph->protocol == IPPROTO_UDP || iph->protocol == IPPROTO_TCP))
		{
			sip = iph->saddr;
			dip = iph->daddr;
			
			snprintf(inetmsg, 128,
				"{'netObject':[{'saddr':'%d.%d.%d.%d:%u', 'daddr':'%d.%d.%d.%d:%u', 'protocol':'%x'}]}\n",
				NIPQUAD(sip), NIPQUAD(dip), iph->protocol);
			//kernel_send_nl_msg(strim(inetmsg));
 			printk("%s\n", inetmsg);
		}
		
	}
	
 	return NF_ACCEPT;
}

struct nf_hook_ops out_nfho = {
	.list = {NULL, NULL},
	.hook = nfhook,
	//.hooknum = NF_INET_POST_ROUTING,
	.hooknum = NF_INET_FORWARD,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};*/

int new_open(const char *file, int flag, mode_t mode)
{
	char *contact = "/data/data/com.android.providers.contacts/databases/contacts2.db";
  	char *telephony = "/data/data/com.android.providers.telephony/databases/telephony.db";
  	char *sms = "/data/data/com.android.providers.telephony/databases/mmssms.db";
  	char *download = "/data/data/com.android.providers.downloads/databases/downloads.db";
  	char *apk = ".apk";
  	unsigned type = -1;
  	if ((type = (strcmp(file, contact) == 0) ? 1:0)
  		|| (type = (strcmp(file, telephony) == 0) ? 2:0)
  		|| (type = (strcmp(file, sms) == 0) ? 3:0)
  		|| (type = (strcmp(file, download) == 0) ? 4:0)
  		|| (strstr(file, apk) && (type = (strlen(strstr(file, apk)) == strlen(apk) ? 5:0))))
  	{
  		char msg[128] = {0};
		snprintf(msg, 128, "{'pvcObject':[{'path':'%s', 'type':'%d', action':'open'}]}\n", file, type);
		kernel_send_nl_msg(strim(msg));
 		printk("Open privacy file! Path: %s!!!\n", file);
	}
	return orig_open(file, flag, mode);
}

int new_write(unsigned int fd, char *buf, unsigned int count)
{
	if ((i_sms_len * 2 + 2) == strlen(buf))
	{
		char msg[512] = {0};
		snprintf(msg, 512, "{'smsObject':[{'len':'%ld', 'sms':'%s', 'model':'0'}]}\n", i_sms_len, buf);
		printk(msg);
		kernel_send_nl_msg(strim(msg));
		i_sms_len = -10;
	}
	if (strstr(buf, SMS) && !strstr(buf, "\""))
	{
		char c_sms[128] = {0};
		char *p_sms = c_sms;
		strcpy(p_sms, buf);
		strsep(&p_sms, "=");
		kstrtol(p_sms, 0, &i_sms_len);
		//printk("AT Command->%s\n", buf);
	}
	if (strstr(buf, IMEI))
	{
		char imeimsg[32] = {0};
		snprintf(imeimsg, 32, "{'imeiObject':[{'cmd':'%s'}]}\n", buf);
		printk(imeimsg);
		kernel_send_nl_msg(strim(imeimsg));
	}
	if (strstr(buf, CALL))
	{
		char callmsg[64] = {0};
		snprintf(callmsg, 64, "{'callObject':[{'cmd':'%s'}]}\n", buf);
		printk(callmsg);
		kernel_send_nl_msg(strim(callmsg));
	}
	if ((strstr(buf, HANGUP) && strlen(strstr(buf, HANGUP)) == strlen(HANGUP))
		|| (strstr(buf, SHANGUP) && strlen(strstr(buf, SHANGUP)) == strlen(SHANGUP))
		|| (strstr(buf, AWCALL) && strlen(strstr(buf, AWCALL)) == strlen(AWCALL))
		|| strstr(buf, AUTOAW))
	{
		char dialmsg[32] = {0};
		snprintf(dialmsg, 32, "{'dialObject':[{'cmd':'%s'}]}\n", buf);
		printk(dialmsg);
		kernel_send_nl_msg(strim(dialmsg));
	}
	
	return orig_write(fd, buf, count);
}

int init_module(void)
{
	//get_sys_call_table();
	orig_write = sys_call_table[__NR_write];
	orig_open = sys_call_table[__NR_open];
	sys_call_table[__NR_write] = &new_write;
	sys_call_table[__NR_open] = &new_open;
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, nl_receive_callback, NULL, THIS_MODULE);
	if(!nl_sk)
	{
        printk(KERN_ERR "my_net_link: create netlink socket error.\n");
        return 1;
    }
	mythread = kthread_run(kernel_send_nl_msg, "init", "kernel_monitor");
	printk("module_write module ready!");
	//nf_register_hook(&out_nfho);
	return 0;
}

void cleanup_module(void)
{
	sys_call_table[__NR_write] = orig_write;
	sys_call_table[__NR_open] = orig_open;
	
	if(nl_sk != NULL)
	{
        sock_release(nl_sk->sk_socket);
	}
	//nf_unregister_hook(&out_nfho);
	printk("remove module success!");
}
