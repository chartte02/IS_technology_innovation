//#define __KERNEL__
//#define MODULE

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/udp.h>

#define MATCH		1
#define NMATCH	0

int enable_flag = 0;

struct nf_hook_ops myhook;

unsigned int controlled_protocol = 0;
unsigned short controlled_srcport = 0;
unsigned short controlled_dstport = 0;
unsigned int controlled_saddr = 0;
unsigned int controlled_daddr = 0;

struct sk_buff *tmpskb;
struct iphdr *piphdr;

int port_check(unsigned short srcport, unsigned short dstport){
	if ((controlled_srcport == 0 ) && ( controlled_dstport == 0 ))
		return MATCH;
	if ((controlled_srcport != 0 ) && ( controlled_dstport == 0 ))
	{
		if (controlled_srcport == srcport)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_srcport == 0 ) && ( controlled_dstport != 0 ))
	{
		if (controlled_dstport == dstport)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_srcport != 0 ) && ( controlled_dstport != 0 ))
	{
		if ((controlled_srcport == srcport) && (controlled_dstport == dstport))
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}


int ipaddr_check(unsigned int saddr, unsigned int daddr){
	if ((controlled_saddr == 0 ) && ( controlled_daddr == 0 ))
		return MATCH;
	if ((controlled_saddr != 0 ) && ( controlled_daddr == 0 ))
	{
		if (controlled_saddr == saddr)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr == 0 ) && ( controlled_daddr != 0 ))
	{
		if (controlled_daddr == daddr)
			return MATCH;
		else
			return NMATCH;
	}
	if ((controlled_saddr != 0 ) && ( controlled_daddr != 0 ))
	{
		if ((controlled_saddr == saddr) && (controlled_daddr == daddr))
			return MATCH;
		else
			return NMATCH;
	}
	return NMATCH;
}

int icmp_check(void){
	struct icmphdr *picmphdr;
	//printk("<0>This is an ICMP packet.\n");
   	picmphdr = (struct icmphdr *)(tmpskb->data +(piphdr->ihl*4));

	if (picmphdr->type == 0){
		if (ipaddr_check(piphdr->daddr,piphdr->saddr) == MATCH){
			printk("An ICMP packet is denied! \n");
			return NF_DROP;
		}
	}
	if (picmphdr->type == 8){
		if (ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH){
			printk("An ICMP packet is denied! \n");
			return NF_DROP;
		}
	}
    	return NF_ACCEPT;
}

int tcp_check(void){
	struct tcphdr *ptcphdr;
	//printk("<0>This is an tcp packet.\n");
   	ptcphdr = (struct tcphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(ptcphdr->source,ptcphdr->dest) == MATCH)){
	 	printk("A TCP packet is denied! \n");
		return NF_DROP;
	}
	else
      		return NF_ACCEPT;
}

int udp_check(void){
	struct udphdr *pudphdr;
	//printk("<0>This is an udp packet.\n");
   	pudphdr = (struct udphdr *)(tmpskb->data +(piphdr->ihl*4));
	if ((ipaddr_check(piphdr->saddr,piphdr->daddr) == MATCH) && (port_check(pudphdr->source,pudphdr->dest) == MATCH)){
	 	printk("A UDP packet is denied! \n");
		return NF_DROP;
	}
	else
      		return NF_ACCEPT;
}


unsigned int hook_func(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){

	if (enable_flag == 0)
		return NF_ACCEPT;
   	tmpskb = skb;
	piphdr = ip_hdr(tmpskb);

	if(piphdr->protocol != controlled_protocol)
      		return NF_ACCEPT;

	if (piphdr->protocol  == 1)  //ICMP packet
		return icmp_check();
	else if (piphdr->protocol  == 6) //TCP packet
		return tcp_check();
	else if (piphdr->protocol  == 17) //UDP packet
		return udp_check();
	else
	{
		printk("Unkonwn type's packet! \n");
		return NF_ACCEPT;
	}
}

static ssize_t write_controlinfo(struct file * fd, const char __user *buf, size_t len, loff_t *ppos)
{
	char controlinfo[128];
	char *pchar;

	pchar = controlinfo;

	if (len == 0){
		enable_flag = 0;
		return len;
	}

	if (copy_from_user(controlinfo, buf, len) != 0){
		printk("Can't get the control rule! \n");
		printk("Something may be wrong, please check it! \n");
		return 0;
	}
	controlled_protocol = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_saddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_daddr = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_srcport = *(( int *) pchar);
	pchar = pchar + 4;
	controlled_dstport = *(( int *) pchar);

	enable_flag = 1;
	printk("input info: p = %d, x = %d y = %d m = %d n = %d \n", controlled_protocol,controlled_saddr,controlled_daddr,controlled_srcport,controlled_dstport);
	return len;
}


struct file_operations fops = {
	.owner=THIS_MODULE,
	.write=write_controlinfo,
};


static int __init initmodule(void)
{
	int ret;
	printk("Init Module\n");
	myhook.hook=hook_func;
	myhook.hooknum=NF_INET_POST_ROUTING;
	myhook.pf=PF_INET;
	myhook.priority=NF_IP_PRI_FIRST;

	nf_register_net_hook(&init_net,&myhook);

	ret = register_chrdev(124, "/dev/controlinfo", &fops);
	if (ret != 0)
		printk("Can't register device file! \n");

   	return 0;
}

static void __exit cleanupmodule(void)
{
	nf_unregister_net_hook(&init_net,&myhook);

	unregister_chrdev(124, "/dev/controlinfo");
    printk("CleanUp\n");
}

module_init(initmodule);
module_exit(cleanupmodule);
MODULE_LICENSE("GPL");
