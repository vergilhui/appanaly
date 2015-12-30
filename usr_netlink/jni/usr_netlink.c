#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <errno.h>
#include <android/log.h>

#define NETLINK_TEST 17
#define MY_GROUP 1
#define MAX_SIZE 1024
#define LOG_TAG "AppanalyTag"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

int main(int argc, char* argv[])
{
    int sock_fd, retval;
    struct sockaddr_nl user_sockaddr;
    struct nlmsghdr *nl_msghdr;
    struct msghdr msghdr;
    struct iovec iov;
    char error_msg[256] = {0};
    char *kernel_msg;

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (sock_fd == -1)
    {
        sprintf(error_msg, "error getting socket: %s", strerror(errno));
        LOGI("%s", error_msg);
	    printf("error getting socket: %s", error_msg);
        return -1;
    }
    memset(&user_sockaddr, 0, sizeof(user_sockaddr));

    user_sockaddr.nl_family = PF_NETLINK;
    user_sockaddr.nl_pid = getpid();
    user_sockaddr.nl_groups = MY_GROUP;

    retval = bind(sock_fd, (struct sockaddr*)&user_sockaddr, sizeof(user_sockaddr));
    if(retval < 0)
    {
        sprintf(error_msg, "bind failed: %s", strerror(errno));
        LOGI("%s", error_msg);
        printf("bind failed: %s", error_msg);
        close(sock_fd);
        return -1;
    }

    while (1)
    {
        nl_msghdr = (struct nlmsghdr*) malloc(NLMSG_SPACE(MAX_SIZE));
	    if(!nl_msghdr)
        {
            LOGI("%s", "malloc nlmsghdr error!\n");
            printf("malloc nlmsghdr error!\n");
            close(sock_fd);
            return -1;
        }
        memset(nl_msghdr, 0, NLMSG_SPACE(MAX_SIZE));
        iov.iov_base = (void*) nl_msghdr;
        iov.iov_len = NLMSG_SPACE(MAX_SIZE);

    	memset(&msghdr, 0, sizeof(msghdr));
        //msghdr.msg_name = (void*) &user_sockaddr;
    	//msghdr.msg_namelen = sizeof(user_sockaddr);
    	msghdr.msg_iov = &iov;
    	msghdr.msg_iovlen = 1;
    	recvmsg(sock_fd, &msghdr, 0);
        kernel_msg = (char*)NLMSG_DATA(nl_msghdr);
        LOGI("%s", kernel_msg);
    	printf("%s\n", kernel_msg);
        
    }
    free(kernel_msg);
    close(sock_fd);

    return 0;
}
