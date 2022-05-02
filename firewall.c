#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

static struct nf_hook_ops netfilter_ops;

/* This function to be called by hook. */
static unsigned int main_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    //struct udphdr *udp_header;
	int dstPort;
	struct tcphdr *hdr;
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);    

    if (ip_header->protocol == IPPROTO_ICMP) {
       // udp_header = (struct udphdr *)skb_transport_header(skb);
        printk(KERN_INFO "Drop icmp packet.\n");

        return NF_DROP;
    }

	if (ip_header->protocol == IPPROTO_TCP) {
		hdr = (struct tcphdr *) skb_transport_header(skb);
		dstPort = ntohs(hdr->dest);
		if((dstPort==443) || (dstPort==80)) /*drop https and http*/ {
			printk("Drop HTTPS/HTTP packet\n");
			return NF_DROP;
		}
	}
    return NF_ACCEPT;
}

static int __init my_firewall_init(void)
{
	struct net *n;

	printk("Init MY MODULE\n");
	netfilter_ops.hook              =       main_hook;
	netfilter_ops.pf                =       PF_INET;
	netfilter_ops.hooknum           =       NF_INET_POST_ROUTING;
	netfilter_ops.priority          =       NF_IP_PRI_FIRST;

	for_each_net(n)
	{
		printk("Registering for %d\n",n->ifindex);
        nf_register_net_hook(n, &netfilter_ops);
	}

	return 0;
}

static void __exit my_firewall_exit(void)
{
	struct net *net;
	printk("Exit MY MODULE\n");
	for_each_net(net) {
		nf_unregister_net_hook(net, &netfilter_ops);
	}
}

module_init(my_firewall_init);
module_exit(my_firewall_exit);



MODULE_LICENSE("GPL");
MODULE_AUTHOR("S Ganguly");
MODULE_DESCRIPTION("A simple firewall.");
MODULE_VERSION("0.0");



