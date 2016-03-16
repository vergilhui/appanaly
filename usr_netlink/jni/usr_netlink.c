#include <unistd.h>
#include <stdio.h>
#include <linux/types.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <signal.h>
#include <android/log.h>
#include "protocol.h"

#define LOG_TAG "AppanalyTag"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define MAX_SIZE 1024

struct msg_to_kernel
{
  struct nlmsghdr *hdr;
};

static int skfd;

static void sig_int(int signo)
{
  struct sockaddr_nl ksockaddr;
  struct nlmsghdr *msg;

  memset(&ksockaddr, 0, sizeof(ksockaddr));
  ksockaddr.nl_family = AF_NETLINK;
  ksockaddr.nl_pid    = 0;
  ksockaddr.nl_groups = 0;

  if (NULL == (msg=(struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_SIZE))))
  {
    perror("alloc mem failed!");
    exit(0);
  }
  memset(msg, 0, MAX_SIZE);
  msg->nlmsg_len = NLMSG_SPACE(MAX_SIZE);
  msg->nlmsg_flags = 0;
  msg->nlmsg_type = IMP2_CLOSE;
  msg->nlmsg_pid = getpid();

  strcpy(NLMSG_DATA(msg), "send user pid!");

  printf("send pid to kernel");
  sendto(skfd, msg, msg->nlmsg_len, 0, (struct sockaddr *)(&ksockaddr),
         sizeof(ksockaddr));

  close(skfd);
  free(msg);
  exit(0);
}

int main(void)
{
  struct sockaddr_nl ksockaddr;
  int klen;
  struct nlmsghdr *msg = NULL;
  int sendlen = 0;
  int rcvlen = 0;

  skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
  if(skfd < 0)
  {
    printf("can not create a netlink socket\n");
    exit(0);
  }
  printf("send msg to kernel!\n");
  signal(SIGINT, sig_int);

  memset(&ksockaddr, 0, sizeof(ksockaddr));
  ksockaddr.nl_family = AF_NETLINK;
  ksockaddr.nl_pid = 0;
  ksockaddr.nl_groups = 0;

  if (NULL == (msg=(struct nlmsghdr*)malloc(NLMSG_SPACE(MAX_SIZE))))
  {
    perror("alloc mem failed!");
    return 1;
  }
  memset(msg, 0, MAX_SIZE);
  msg->nlmsg_len = NLMSG_SPACE(MAX_SIZE);
  msg->nlmsg_flags = 0;
  msg->nlmsg_type = IMP2_U_PID;
  msg->nlmsg_pid = getpid();

  strcpy(NLMSG_DATA(msg), "send user pid!");

  printf("send msg to kernel!\n");
  sendto(skfd, msg, msg->nlmsg_len, 0,
     (struct sockaddr*)&ksockaddr, sizeof(ksockaddr));
  printf("receive msg from kernel!\n");
  while(1)
  {
    memset(msg, 0, MAX_SIZE);
    klen = sizeof(struct sockaddr_nl);
    rcvlen = recvfrom(skfd, msg, NLMSG_LENGTH(MAX_SIZE),
          0, (struct sockaddr*)&ksockaddr, &klen);

    LOGI("%s", NLMSG_DATA(msg));
    printf("message: %s, ", NLMSG_DATA(msg));
  }

  return 0;
}
