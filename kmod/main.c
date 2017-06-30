#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <linux/ctype.h>

#define NETLINK_TEST 17

/* The netlink socket. */
static struct sock *test_nl_sock;

static void dump_nlmsg(struct nlmsghdr *nlh)
{
	int i, j, len;
	unsigned char *data = NLMSG_DATA(nlh);
	int col = 16;
	int datalen = NLMSG_PAYLOAD(nlh, 0);

	printk(KERN_DEBUG "===============DEBUG START===============\n");
	printk(KERN_DEBUG "nlmsghdr info (%d):\n", NLMSG_HDRLEN);
	printk(KERN_DEBUG
		"  nlmsg_len\t= %d\n" "  nlmsg_type\t= %d\n"
		"  nlmsg_flags\t= %d\n" "  nlmsg_seq\t= %d\n" "  nlmsg_pid\t= %d\n",
		nlh->nlmsg_len, nlh->nlmsg_type,
		nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);

	printk(KERN_DEBUG "nlmsgdata info (%d):\n", datalen);

	for (i = 0; i < datalen; i += col) {
		len = (datalen - i < col) ? (datalen - i) : col;

		printk("  ");
		for (j = 0; j < col; j++) {
			if (j < len)
				printk("%02x ", data[i + j]);
			else
				printk("   ");

		}
		printk("\t");
		for (j = 0; j < len; j++) {
			if (j < len)
				if (isprint(data[i + j]))
					printk("%c", data[i + j]);
				else
					printk(".");
			else
				printk(" ");
		}
		printk("\n");
	}
	printk(KERN_DEBUG "===============DEBUG END===============\n");
}

static int send_msg_to_user(struct sk_buff *in_skb, int pid)
{
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	const char *str = "I am message from kernel!";
	int len = strlen(str) + 1;

	skb = nlmsg_new(len, GFP_KERNEL);
	if (!skb) {
		printk(KERN_ERR "nlmsg_new: couldn't alloc a sk_buff\n");
		return -ENOMEM;
	}

	nlh = nlmsg_put(skb, 0, 7438, 0, len, 0);
	if (!nlh) {
		printk(KERN_ERR "nlmsg_put: couldn't put nlmsghdr\n");
		kfree_skb(skb);
		return -EMSGSIZE;
	}
	memcpy(NLMSG_DATA(nlh), str, len);

	/* debug info */
	dump_nlmsg(nlh);

	return nlmsg_unicast(test_nl_sock, skb, pid);
}

static int netlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	printk(KERN_INFO "receive from userspace: %s", (char *) NLMSG_DATA(nlh));

	return send_msg_to_user(skb, nlh->nlmsg_pid);
}

/* Receive messages from netlink socket. */
static void test_nl_rcv_skb(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int err;

	while (skb->len >= nlmsg_total_size(0)) {
		int msglen;

		nlh = nlmsg_hdr(skb);
		err = 0;

		/* debug info */
		dump_nlmsg(nlh);

		if (nlh->nlmsg_len < NLMSG_HDRLEN || skb->len < nlh->nlmsg_len) {
			return;
		}

		err = netlink_rcv_msg(skb, nlh);
		if (err) {
			netlink_ack(skb, nlh, err);
		}

		msglen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (msglen > skb->len) {
			msglen = skb->len;
		}
		skb_pull(skb, msglen);
	}
}

static int __init test_nl_init(void)
{
	test_nl_sock = netlink_kernel_create(&init_net, NETLINK_TEST, 0,
					test_nl_rcv_skb, NULL, THIS_MODULE);
	if (!test_nl_sock) {
		printk(KERN_ERR "netlink_kernel_create: couldn't create a netlink sock\n");
		return -ENOMEM;
	}

	printk(KERN_INFO "test netlink module init successful\n");

	return 0;
}

static void __exit test_nl_exit(void)
{
	netlink_kernel_release(test_nl_sock);

	printk(KERN_INFO "test netlink module exit successful\n");
}

module_init(test_nl_init);
module_exit(test_nl_exit);

MODULE_AUTHOR("houjian");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("netlink test module");
