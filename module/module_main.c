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
#include <linux/slab.h>
#include <linux/semaphore.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include "protocol.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("vergilhui");
MODULE_DESCRIPTION("Android App Behavior Record");

//static void **sys_call_table;
#define SYS_CALL_TB 0xc000da84
#define MAX_SIZE 1024
#define SMS "AT+CMGS"
#define IMEI "AT+CGSN"
#define CALL "ATD"
#define HANGUP "ATH"
#define AWCALL "ATA"
#define AUTOAW "ATS0"
#define SHANGUP "AT+CHUP"
#define PTCP_WATCH_PORT 80

DEFINE_SEMAPHORE(receive_sem);

unsigned long *sys_call_table = (unsigned long *)SYS_CALL_TB;
int (*orig_write)(unsigned int fd, char *buf, unsigned int count);
int (*orig_open)(const char *file, int flag, mode_t mode);
unsigned long i_sms_len = -10;
struct sock *nl_sk = NULL;

struct
{
  __u32 pid;
  rwlock_t lock;
}user_proc;

static void kernel_receive(struct sk_buff *skb)
{
    if(down_trylock(&receive_sem))
        return;
    if (skb)
    {
    	struct nlmsghdr *nlh = NULL;
		if(skb->len >= sizeof(struct nlmsghdr))
        {
            nlh = (struct nlmsghdr *)skb->data;
            if((nlh->nlmsg_len >= sizeof(struct nlmsghdr))
                 	&& (skb->len >= nlh->nlmsg_len))
            {
		    	if(nlh->nlmsg_type == IMP2_U_PID)
		      	{
					write_lock_bh(&user_proc.pid);
					user_proc.pid = nlh->nlmsg_pid;
					write_unlock_bh(&user_proc.pid);
		      	}
		    	else if(nlh->nlmsg_type == IMP2_CLOSE)
		      	{
					write_lock_bh(&user_proc.pid);
					if(nlh->nlmsg_pid == user_proc.pid)
			  			user_proc.pid = 0;
					write_unlock_bh(&user_proc.pid);
		      	}
		  	}
	    }
	}
	up(&receive_sem);
}

static int kernel_send_nl_msg(const char *msg)
{
	int ret;
    struct nlmsghdr *nlsk_mh;
    struct sk_buff *socket_buff;
    
    socket_buff = nlmsg_new(MAX_SIZE, GFP_KERNEL);
    if (!socket_buff)
    	printk("socket_buff NULL\n");

    nlsk_mh = nlmsg_put(socket_buff, 0, 0, IMP2_K_MSG, MAX_SIZE, 0);
    if (!nlsk_mh)
    	printk("nlsk_mh NULL\n");

    NETLINK_CB(socket_buff).dst_group = 0;

    if (!msg)
    	printk("msg NULL \n");
    strcpy(nlmsg_data(nlsk_mh), msg);

    read_lock_bh(&user_proc.lock);
    printk("send msg to user space! user pid: %d", user_proc.pid);
    ret = netlink_unicast(nl_sk, socket_buff, user_proc.pid, MSG_DONTWAIT);
    read_unlock_bh(&user_proc.lock);

    return ret;

    nlmsg_failure:
    	if (socket_buff)
    		kfree_skb(socket_buff);
    	return -1;
}

unsigned int nfhook(
	unsigned int hooknum,
	struct sk_buff *skb,
	const struct net_device *in,
	const struct net_device *out,
	int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	struct tcphdr *tcph;
	char *inetmsg = kmalloc(128, GFP_KERNEL);

    if (!skb)
    	return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph)
    	return NF_ACCEPT;
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);
	if (tcph->source != PTCP_WATCH_PORT)
        return NF_ACCEPT;
	
	memset(inetmsg, 0, sizeof(char)*128);
		
	snprintf(inetmsg, 128,
		"{\"netObject\":{\"saddr\":\"%pI4\",\"daddr\":\"%pI4\", \"data\":\"%s\", \"protocol\":\"TCP\"}}\n",
		iph->saddr, iph->daddr, skb->data);

	read_lock_bh(&user_proc.lock);
	if(user_proc.pid != 0)
	{
	  	read_unlock_bh(&user_proc.lock);
	  	kernel_send_nl_msg(inetmsg);
	}
    else
		read_unlock_bh(&user_proc.lock);
	kfree(inetmsg);
	
 	return NF_ACCEPT;
}

struct nf_hook_ops out_nfho =
{
	.list = {NULL, NULL},
	.hook = nfhook,
	.hooknum = NF_INET_PRE_ROUTING,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

int new_open(const char *file, int flag, mode_t mode)
{
	char *contact = "/data/data/com.android.providers.contacts/databases/contacts2.db";
  	char *telephony = "/data/data/com.android.providers.telephony/databases/telephony.db";
  	char *sms = "/data/data/com.android.providers.telephony/databases/mmssms.db";
  	char *download = "/data/data/com.android.providers.downloads/databases/downloads.db";
  	char *systempath = "/system/bin";
  	char *apk = ".apk";
  	unsigned type = -1;
  	if ((type = (strcmp(file, contact) == 0) ? 1:0)
  		|| (type = (strcmp(file, telephony) == 0) ? 2:0)
  		|| (type = (strcmp(file, sms) == 0) ? 3:0)
  		|| (type = (strcmp(file, download) == 0) ? 4:0)
  		|| (type = (strcmp(file, systempath) == 0) ? 5:0)
  		|| (strstr(file, apk) && (type = (strlen(strstr(file, apk)) == strlen(apk) ? 6:0))))
  	{
  		char* msg = kmalloc(128, GFP_KERNEL);
  		memset(msg, 0, sizeof(char)*128);
		snprintf(msg, 128, "{\"pvcObject\":{\"path\":\"%s\", \"type\":\"%d\", \"action\":\"open\"}}\n", file, type);
		read_lock_bh(&user_proc.lock);
        if(user_proc.pid != 0)
		{
	  		read_unlock_bh(&user_proc.lock);
	  		kernel_send_nl_msg(msg);
		}
      	else
			read_unlock_bh(&user_proc.lock);
 		printk("Open privacy file! Path: %s!!!\n", file);
 		kfree(msg);
	}
	return orig_open(file, flag, mode);
}

int new_write(unsigned int fd, char *buf, unsigned int count)
{
	if ((i_sms_len * 2 + 2) == strlen(buf))
	{
		char *msg = kmalloc(512, GFP_KERNEL);
		if(!msg){
	        printk(KERN_ERR "appaly: alloc_msg Error./n");
	        return orig_write(fd, buf, count);
    	}
		memset(msg, 0, sizeof(char)*512);
		snprintf(msg, 512, "{\"smsObject\":{\"len\":\"%ld\", \"sms\":\"%s\"}}\n", i_sms_len, buf);
		printk(msg);
		read_lock_bh(&user_proc.lock);
        if(user_proc.pid != 0)
		{
	  		read_unlock_bh(&user_proc.lock);
	  		kernel_send_nl_msg(msg);
		}
      	else
			read_unlock_bh(&user_proc.lock);
		i_sms_len = -10;
		kfree(msg);
	}
	if (strstr(buf, SMS) && !strstr(buf, "\""))
	{
		char c_sms[128] = {0};
		char *p_sms = c_sms;
		strcpy(p_sms, buf);
		strsep(&p_sms, "=");
		kstrtol(p_sms, 0, &i_sms_len);
	}
	if (strstr(buf, IMEI))
	{
		char *imeimsg = kmalloc(64, GFP_KERNEL);
		memset(imeimsg, 0, sizeof(char)*64);
		snprintf(imeimsg, 32, "{\"imeiObject\":{\"cmd\":\"%s\"}}\n", buf);
		printk(imeimsg);
		read_lock_bh(&user_proc.lock);
        if(user_proc.pid != 0)
		{
	  		read_unlock_bh(&user_proc.lock);
	  		kernel_send_nl_msg(imeimsg);
		}
      	else
			read_unlock_bh(&user_proc.lock);
		kfree(imeimsg);
	}
	if (strstr(buf, CALL))
	{
		char *callmsg = kmalloc(64, GFP_KERNEL);
		memset(callmsg, 0, sizeof(char)*64);
		snprintf(callmsg, 64, "{\"callObject\":{\"cmd\":\"%s\"}}\n", buf);
		printk(callmsg);
		read_lock_bh(&user_proc.lock);
        if(user_proc.pid != 0)
		{
	  		read_unlock_bh(&user_proc.lock);
	  		kernel_send_nl_msg(callmsg);
		}
      	else
			read_unlock_bh(&user_proc.lock);
		kfree(callmsg);
	}
	if ((strstr(buf, HANGUP) && strlen(strstr(buf, HANGUP)) == strlen(HANGUP))
		|| (strstr(buf, SHANGUP) && strlen(strstr(buf, SHANGUP)) == strlen(SHANGUP))
		|| (strstr(buf, AWCALL) && strlen(strstr(buf, AWCALL)) == strlen(AWCALL))
		|| strstr(buf, AUTOAW))
	{
		char *dialmsg = kmalloc(64, GFP_KERNEL);
		memset(dialmsg, 0, sizeof(char)*64);
		snprintf(dialmsg, 32, "{\"dialObject\":{\"cmd\":\"%s\"}}\n", buf);
		printk(dialmsg);
		read_lock_bh(&user_proc.lock);
        if(user_proc.pid != 0)
		{
	  		read_unlock_bh(&user_proc.lock);
	  		kernel_send_nl_msg(dialmsg);
		}
      	else
			read_unlock_bh(&user_proc.lock);
		kfree(dialmsg);
	}
	
	return orig_write(fd, buf, count);
}

int init_module(void)
{
	rwlock_init(&user_proc.lock);
	orig_write = sys_call_table[__NR_write];
	orig_open = sys_call_table[__NR_open];
	sys_call_table[__NR_write] = &new_write;
	sys_call_table[__NR_open] = &new_open;
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0, kernel_receive, NULL, THIS_MODULE);
	if (!nl_sk)
	{
		printk("nl_sk is NULL!");
	}
	printk("module_write module ready!");
	nf_register_hook(&out_nfho);
	return 0;
}

void cleanup_module(void)
{
	sys_call_table[__NR_write] = orig_write;
	sys_call_table[__NR_open] = orig_open;

	if(nl_sk)
    {
      sock_release(nl_sk->sk_socket);
    }
	
	nf_unregister_hook(&out_nfho);
	printk("remove module success!");
}
