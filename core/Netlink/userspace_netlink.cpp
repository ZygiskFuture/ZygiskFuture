#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>

// 自定义协议类型（需与内核模块一致）
#define NETLINK_MY_PROTO 31  // 通常 > 15 以避免冲突
#define MAX_PAYLOAD 1024     // 最大消息负载

struct nl_msg {
    struct nlmsghdr hdr;
    char data[MAX_PAYLOAD];
};

int main() {
    int sock_fd;
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int ret;

    // 1. 创建 Netlink 套接字
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_MY_PROTO);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    // 2. 绑定源地址（用户态）
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();  // 使用进程ID作为地址
    src_addr.nl_groups = 0;      // 单播

    if (bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    // 3. 准备目标地址（内核态）
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;       // 0 表示内核
    dest_addr.nl_groups = 0;    // 单播

    // 4. 创建 Netlink 消息头
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    if (!nlh) {
        perror("malloc");
        close(sock_fd);
        return -1;
    }

    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_LENGTH(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();   // 发送方ID
    nlh->nlmsg_flags = 0;        // 普通消息

    // 5. 填充消息内容（示例）
    char *payload = "Hello Kernel from User!";
    strncpy(NLMSG_DATA(nlh), payload, strlen(payload) + 1);

    // 6. 设置 I/O 向量
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;

    // 7. 设置消息结构
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 8. 发送消息到内核
    printf("Sending message: %s\n", (char *)NLMSG_DATA(nlh));
    ret = sendmsg(sock_fd, &msg, 0);
    if (ret < 0) {
        perror("sendmsg");
        free(nlh);
        close(sock_fd);
        return -1;
    }

    // 9. 接收内核响应
    printf("Waiting for kernel reply...\n");
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    ret = recvmsg(sock_fd, &msg, 0);
    if (ret < 0) {
        perror("recvmsg");
    } else {
        // 解析接收到的消息
        char *reply = NLMSG_DATA(nlh);
        printf("Received reply: %s\n", reply);
    }

    // 10. 清理资源
    free(nlh);
    close(sock_fd);
    return 0;
}