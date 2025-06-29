#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

// 必须与用户态相同的协议号
#define NETLINK_MY_PROTO 31
#define MODULE_NAME "netlink_kern"
#define MAX_PAYLOAD 1024

static struct sock *nl_sock = NULL;

// 自定义消息结构（需与用户态一致）
struct kernel_nl_msg {
    struct nlmsghdr hdr;
    char data[MAX_PAYLOAD];
};

// 消息处理回调函数
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    struct kernel_nl_msg *msg;
    pid_t user_pid;
    int len;
    char *reply = "Hello User from Kernel!";

    // 获取Netlink消息头
    nlh = nlmsg_hdr(skb);
    len = nlmsg_len(nlh);
    
    if (len < sizeof(*nlh) || len < sizeof(struct kernel_nl_msg)) {
        pr_err("%s: Invalid message length\n", MODULE_NAME);
        return;
    }

    // 获取消息内容
    msg = nlmsg_data(nlh);
    user_pid = nlh->nlmsg_pid;  // 保存用户进程PID用于回复
    
    // 打印接收到的消息
    pr_info("%s: Received from user[%d]: %s\n", 
            MODULE_NAME, user_pid, msg->data);

    // 准备回复消息
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh_out;
    int msg_size = strlen(reply) + 1;
    int total_size = nlmsg_total_size(msg_size);

    // 分配发送缓冲区
    skb_out = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb_out) {
        pr_err("%s: Failed to allocate skb\n", MODULE_NAME);
        return;
    }

    // 设置消息头
    nlh_out = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; // 单播
    
    // 填充消息内容
    strncpy(nlmsg_data(nlh_out), reply, msg_size);

    // 发送回复
    int res = nlmsg_unicast(nl_sock, skb_out, user_pid);
    if (res < 0) {
        pr_err("%s: Error sending reply: %d\n", MODULE_NAME, res);
        kfree_skb(skb_out);
    } else {
        pr_info("%s: Reply sent to user[%d]\n", MODULE_NAME, user_pid);
    }
}

// Netlink配置
static struct netlink_kernel_cfg nl_cfg = {
    .input = nl_recv_msg,  // 消息处理回调
};

// 模块初始化
static int __init nl_init(void)
{
    pr_info("%s: Initializing module\n", MODULE_NAME);
    
    // 创建Netlink套接字
    nl_sock = netlink_kernel_create(&init_net, NETLINK_MY_PROTO, &nl_cfg);
    if (!nl_sock) {
        pr_err("%s: Failed to create netlink socket\n", MODULE_NAME);
        return -ENOMEM;
    }
    
    pr_info("%s: Netlink socket created (proto=%d)\n", 
            MODULE_NAME, NETLINK_MY_PROTO);
    return 0;
}

// 模块退出
static void __exit nl_exit(void)
{
    pr_info("%s: Exiting module\n", MODULE_NAME);
    
    if (nl_sock) {
        netlink_kernel_release(nl_sock);
        nl_sock = NULL;
    }
}

module_init(nl_init);
module_exit(nl_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netlink Kernel Module Example");