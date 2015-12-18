#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <errno.h>

#define NETLINK_TEST 17
#define MY_GROUP 1
#define MAX_SIZE 1024

int main(int argc, char* argv[])
{
    int sock_fd, retval;
    struct sockaddr_nl user_sockaddr;
    struct nlmsghdr *nl_msghdr;
    struct msghdr msghdr;
    struct iovec iov;
    char* kernel_msg;

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if (sock_fd == -1){
	printf("error getting socket: %s", strerror(errno));
    	return -1;
    }
    memset(&user_sockaddr, 0, sizeof(user_sockaddr));

    user_sockaddr.nl_family = PF_NETLINK;
    user_sockaddr.nl_pid = getpid();
    user_sockaddr.nl_groups = MY_GROUP;

    retval = bind(sock_fd, (struct sockaddr*)&user_sockaddr, sizeof(user_sockaddr));
    if(retval < 0){
        printf("bind failed: %s", strerror(errno));
        close(sock_fd);
        return -1;
    }

    while (1)
    {
        nl_msghdr = (struct nlmsghdr*) malloc(NLMSG_SPACE(MAX_SIZE));
	if(!nl_msghdr){
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
	printf("%s\n", NLMSG_DATA(nl_msghdr));
    }
    close(sock_fd);

    return 0;
}
