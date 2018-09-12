// +build linux
// +build cgo

package shared

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gorilla/websocket"

	"github.com/lxc/lxd/shared/api"
	"github.com/lxc/lxd/shared/logger"
)

/*
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct netns_ifaddrs {
	struct netns_ifaddrs *ifa_next;

	// Can - but shouldn't be - NULL.
	char *ifa_name;

	// This field is not present struct ifaddrs
	int ifa_ifindex;

	unsigned ifa_flags;

	// This field is not present struct ifaddrs
	int ifa_mtu;

	// This field is not present struct ifaddrs
	int ifa_prefixlen;

	struct sockaddr *ifa_addr;
	struct sockaddr *ifa_netmask;
	union {
		struct sockaddr *ifu_broadaddr;
		struct sockaddr *ifu_dstaddr;
	} ifa_ifu;

	// If you don't know what this is for don't touch it.
	void *ifa_data;
};

#define __ifa_broadaddr ifa_ifu.ifu_broadaddr
#define __ifa_dstaddr ifa_ifu.ifu_dstaddr

#ifdef IFLA_IF_NETNSID
#ifndef IFLA_TARGET_NETNSID
#define IFLA_TARGET_NETNSID = IFLA_IF_NETNSID
#endif
#else
#define IFLA_IF_NETNSID 46
#define IFLA_TARGET_NETNSID 46
#endif

#ifndef IFA_TARGET_NETNSID
#define IFA_TARGET_NETNSID 10
#endif

#define IFADDRS_HASH_SIZE 64

#define __NETLINK_ALIGN(len) (((len) + 3) & ~3)

#define __NLMSG_OK(nlh, end) \
	((char *)(end) - (char *)(nlh) >= sizeof(struct nlmsghdr))

#define __NLMSG_NEXT(nlh) \
	(struct nlmsghdr *)((char *)(nlh) + __NETLINK_ALIGN((nlh)->nlmsg_len))

#define __NLMSG_DATA(nlh) ((void *)((char *)(nlh) + sizeof(struct nlmsghdr)))

#define __NLMSG_DATAEND(nlh) ((char *)(nlh) + (nlh)->nlmsg_len)

#define __NLMSG_RTA(nlh, len)                               \
	((void *)((char *)(nlh) + sizeof(struct nlmsghdr) + \
		  __NETLINK_ALIGN(len)))

#define __RTA_DATALEN(rta) ((rta)->rta_len - sizeof(struct rtattr))

#define __RTA_NEXT(rta) \
	(struct rtattr *)((char *)(rta) + __NETLINK_ALIGN((rta)->rta_len))

#define __RTA_OK(nlh, end) \
	((char *)(end) - (char *)(rta) >= sizeof(struct rtattr))

#define __NLMSG_RTAOK(rta, nlh) __RTA_OK(rta, __NLMSG_DATAEND(nlh))

#define __IN6_IS_ADDR_LINKLOCAL(a) \
	((((uint8_t *)(a))[0]) == 0xfe && (((uint8_t *)(a))[1] & 0xc0) == 0x80)

#define __IN6_IS_ADDR_MC_LINKLOCAL(a) \
	(IN6_IS_ADDR_MULTICAST(a) && ((((uint8_t *)(a))[1] & 0xf) == 0x2))

#define __RTA_DATA(rta) ((void *)((char *)(rta) + sizeof(struct rtattr)))

// getifaddrs() reports hardware addresses with PF_PACKET that implies
// struct sockaddr_ll.  But e.g. Infiniband socket address length is
// longer than sockaddr_ll.ssl_addr[8] can hold. Use this hack struct
// to extend ssl_addr - callers should be able to still use it.
struct sockaddr_ll_hack {
	unsigned short sll_family, sll_protocol;
	int sll_ifindex;
	unsigned short sll_hatype;
	unsigned char sll_pkttype, sll_halen;
	unsigned char sll_addr[24];
};

union sockany {
	struct sockaddr sa;
	struct sockaddr_ll_hack ll;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

struct ifaddrs_storage {
	struct netns_ifaddrs ifa;
	struct ifaddrs_storage *hash_next;
	union sockany addr, netmask, ifu;
	unsigned int index;
	char name[IFNAMSIZ + 1];
};

struct ifaddrs_ctx {
	struct ifaddrs_storage *first;
	struct ifaddrs_storage *last;
	struct ifaddrs_storage *hash[IFADDRS_HASH_SIZE];
};

void netns_freeifaddrs(struct netns_ifaddrs *ifp)
{
	struct netns_ifaddrs *n;

	while (ifp) {
		n = ifp->ifa_next;
		free(ifp);
		ifp = n;
	}
}

static void copy_addr(struct sockaddr **r, int af, union sockany *sa,
		      void *addr, size_t addrlen, int ifindex)
{
	uint8_t *dst;
	size_t len;

	switch (af) {
	case AF_INET:
		dst = (uint8_t *)&sa->v4.sin_addr;
		len = 4;
		break;
	case AF_INET6:
		dst = (uint8_t *)&sa->v6.sin6_addr;
		len = 16;
		if (__IN6_IS_ADDR_LINKLOCAL(addr) ||
		    __IN6_IS_ADDR_MC_LINKLOCAL(addr))
			sa->v6.sin6_scope_id = ifindex;
		break;
	default:
		return;
	}

	if (addrlen < len)
		return;

	sa->sa.sa_family = af;

	memcpy(dst, addr, len);

	*r = &sa->sa;
}

static void gen_netmask(struct sockaddr **r, int af, union sockany *sa,
			int prefixlen)
{
	uint8_t addr[16] = {0};
	int i;

	if ((size_t)prefixlen > 8 * sizeof(addr))
		prefixlen = 8 * sizeof(addr);

	i = prefixlen / 8;

	memset(addr, 0xff, i);

	if ((size_t)i < sizeof(addr))
		addr[i++] = 0xff << (8 - (prefixlen % 8));

	copy_addr(r, af, sa, addr, sizeof(addr), 0);
}

static void copy_lladdr(struct sockaddr **r, union sockany *sa, void *addr,
			size_t addrlen, int ifindex, unsigned short hatype)
{
	if (addrlen > sizeof(sa->ll.sll_addr))
		return;

	sa->ll.sll_family = AF_PACKET;
	sa->ll.sll_ifindex = ifindex;
	sa->ll.sll_hatype = hatype;
	sa->ll.sll_halen = addrlen;

	memcpy(sa->ll.sll_addr, addr, addrlen);

	*r = &sa->sa;
}

static int nl_msg_to_ifaddr(void *pctx, struct nlmsghdr *h)
{
	struct ifaddrs_storage *ifs, *ifs0;
	struct rtattr *rta;
	int stats_len = 0;
	struct ifinfomsg *ifi = __NLMSG_DATA(h);
	struct ifaddrmsg *ifa = __NLMSG_DATA(h);
	struct ifaddrs_ctx *ctx = pctx;

	if (h->nlmsg_type == RTM_NEWLINK) {
		for (rta = __NLMSG_RTA(h, sizeof(*ifi)); __NLMSG_RTAOK(rta, h);
		     rta = __RTA_NEXT(rta)) {
			if (rta->rta_type != IFLA_STATS)
				continue;

			stats_len = __RTA_DATALEN(rta);
			break;
		}
	} else {
		for (ifs0 = ctx->hash[ifa->ifa_index % IFADDRS_HASH_SIZE]; ifs0;
		     ifs0 = ifs0->hash_next)
			if (ifs0->index == ifa->ifa_index)
				break;
		if (!ifs0)
			return 0;
	}

	ifs = calloc(1, sizeof(struct ifaddrs_storage) + stats_len);
	if (!ifs) {
		errno = ENOMEM;
		return -1;
	}

	if (h->nlmsg_type == RTM_NEWLINK) {
		ifs->index = ifi->ifi_index;
		ifs->ifa.ifa_ifindex = ifi->ifi_index;
		ifs->ifa.ifa_flags = ifi->ifi_flags;

		for (rta = __NLMSG_RTA(h, sizeof(*ifi)); __NLMSG_RTAOK(rta, h);
		     rta = __RTA_NEXT(rta)) {
			switch (rta->rta_type) {
			case IFLA_IFNAME:
				if (__RTA_DATALEN(rta) < sizeof(ifs->name)) {
					memcpy(ifs->name, __RTA_DATA(rta),
					       __RTA_DATALEN(rta));
					ifs->ifa.ifa_name = ifs->name;
				}
				break;
			case IFLA_ADDRESS:
				copy_lladdr(&ifs->ifa.ifa_addr, &ifs->addr,
					    __RTA_DATA(rta), __RTA_DATALEN(rta),
					    ifi->ifi_index, ifi->ifi_type);
				break;
			case IFLA_BROADCAST:
				copy_lladdr(&ifs->ifa.__ifa_broadaddr, &ifs->ifu,
					    __RTA_DATA(rta), __RTA_DATALEN(rta),
					    ifi->ifi_index, ifi->ifi_type);
				break;
			case IFLA_STATS:
				ifs->ifa.ifa_data = (void *)(ifs + 1);
				memcpy(ifs->ifa.ifa_data, __RTA_DATA(rta),
				       __RTA_DATALEN(rta));
				break;
			case IFLA_MTU:
				memcpy(&ifs->ifa.ifa_mtu, __RTA_DATA(rta),
				       sizeof(int));
				printf("%d\n", ifs->ifa.ifa_mtu);
				break;
			}
		}

		if (ifs->ifa.ifa_name) {
			unsigned int bucket = ifs->index % IFADDRS_HASH_SIZE;
			ifs->hash_next = ctx->hash[bucket];
			ctx->hash[bucket] = ifs;
		}
	} else {
		ifs->ifa.ifa_name = ifs0->ifa.ifa_name;
		ifs->ifa.ifa_mtu = ifs0->ifa.ifa_mtu;
		ifs->ifa.ifa_ifindex = ifs0->ifa.ifa_ifindex;
		ifs->ifa.ifa_flags = ifs0->ifa.ifa_flags;

		for (rta = __NLMSG_RTA(h, sizeof(*ifa)); __NLMSG_RTAOK(rta, h);
		     rta = __RTA_NEXT(rta)) {
			switch (rta->rta_type) {
			case IFA_ADDRESS:
				// If ifa_addr is already set we, received an
				// IFA_LOCAL before so treat this as destination
				// address.
				if (ifs->ifa.ifa_addr)
					copy_addr(&ifs->ifa.__ifa_dstaddr,
						  ifa->ifa_family, &ifs->ifu,
						  __RTA_DATA(rta),
						  __RTA_DATALEN(rta),
						  ifa->ifa_index);
				else
					copy_addr(&ifs->ifa.ifa_addr,
						  ifa->ifa_family, &ifs->addr,
						  __RTA_DATA(rta),
						  __RTA_DATALEN(rta),
						  ifa->ifa_index);
				break;
			case IFA_BROADCAST:
				copy_addr(&ifs->ifa.__ifa_broadaddr,
					  ifa->ifa_family, &ifs->ifu,
					  __RTA_DATA(rta), __RTA_DATALEN(rta),
					  ifa->ifa_index);
				break;
			case IFA_LOCAL:
				// If ifa_addr is set and we get IFA_LOCAL,
				// assume we have a point-to-point network. Move
				// address to correct field.
				if (ifs->ifa.ifa_addr) {
					ifs->ifu = ifs->addr;
					ifs->ifa.__ifa_dstaddr = &ifs->ifu.sa;

					memset(&ifs->addr, 0, sizeof(ifs->addr));
				}

				copy_addr(&ifs->ifa.ifa_addr, ifa->ifa_family,
					  &ifs->addr, __RTA_DATA(rta),
					  __RTA_DATALEN(rta), ifa->ifa_index);
				break;
			case IFA_LABEL:
				if (__RTA_DATALEN(rta) < sizeof(ifs->name)) {
					memcpy(ifs->name, __RTA_DATA(rta),
					       __RTA_DATALEN(rta));
					ifs->ifa.ifa_name = ifs->name;
				}
				break;
			}
		}

		if (ifs->ifa.ifa_addr) {
			gen_netmask(&ifs->ifa.ifa_netmask, ifa->ifa_family,
				    &ifs->netmask, ifa->ifa_prefixlen);
			ifs->ifa.ifa_prefixlen = ifa->ifa_prefixlen;
		}
	}

	if (ifs->ifa.ifa_name) {
		if (!ctx->first)
			ctx->first = ifs;

		if (ctx->last)
			ctx->last->ifa.ifa_next = &ifs->ifa;

		ctx->last = ifs;
	} else {
		free(ifs);
	}

	return 0;
}

#define NLMSG_TAIL(nmsg)                      \
	((struct rtattr *)(((void *)(nmsg)) + \
			   __NETLINK_ALIGN((nmsg)->nlmsg_len)))

int addattr(struct nlmsghdr *n, size_t maxlen, int type, const void *data,
	    size_t alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return -1;

	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return 0;
}

extern int __netlink_send(int fd, struct nlmsghdr *nlmsghdr)
{
	int ret;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
	    .iov_base = nlmsghdr,
	    .iov_len = nlmsghdr->nlmsg_len,
	};
	struct msghdr msg = {
	    .msg_name = &nladdr,
	    .msg_namelen = sizeof(nladdr),
	    .msg_iov = &iov,
	    .msg_iovlen = 1,
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	ret = sendmsg(fd, &msg, MSG_NOSIGNAL);
	if (ret < 0)
		return -1;

	return ret;
}

static int __netlink_recv(int fd, unsigned int seq, int type, int af,
			  __s32 netns_id,
			  int (*cb)(void *ctx, struct nlmsghdr *h), void *ctx)
{
	char getlink_buf[__NETLINK_ALIGN(sizeof(struct nlmsghdr)) +
			 __NETLINK_ALIGN(sizeof(struct ifinfomsg)) +
			 __NETLINK_ALIGN(1024)];
	char getaddr_buf[__NETLINK_ALIGN(sizeof(struct nlmsghdr)) +
			 __NETLINK_ALIGN(sizeof(struct ifaddrmsg)) +
			 __NETLINK_ALIGN(1024)];
	char *buf;
	struct nlmsghdr *hdr;
	struct ifinfomsg *ifi_msg;
	struct ifaddrmsg *ifa_msg;
	union {
		uint8_t buf[8192];
		struct {
			struct nlmsghdr nlh;
			struct rtgenmsg g;
		} req;
		struct nlmsghdr reply;
	} u;
	int r, property, ret;

	if (type == RTM_GETLINK)
		buf = getlink_buf;
	else if (type == RTM_GETADDR)
		buf = getaddr_buf;
	else
		return -1;

	memset(buf, 0, sizeof(*buf));
	hdr = (struct nlmsghdr *)buf;
	if (type == RTM_GETLINK)
		ifi_msg = (struct ifinfomsg *)__NLMSG_DATA(hdr);
	else
		ifa_msg = (struct ifaddrmsg *)__NLMSG_DATA(hdr);

	if (type == RTM_GETLINK)
		hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*ifi_msg));
	else
		hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*ifa_msg));

	hdr->nlmsg_type = type;
	hdr->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	hdr->nlmsg_pid = 0;
	hdr->nlmsg_seq = seq;
	if (type == RTM_GETLINK)
		ifi_msg->ifi_family = af;
	else
		ifa_msg->ifa_family = af;

	errno = EINVAL;
	if (type == RTM_GETLINK)
		property = IFLA_TARGET_NETNSID;
	else if (type == RTM_GETADDR)
		property = IFA_TARGET_NETNSID;
	else
		return -1;

	if (netns_id >= 0)
		addattr(hdr, 1024, property, &netns_id, sizeof(netns_id));

	r = __netlink_send(fd, hdr);
	if (r < 0)
		return -1;

	for (;;) {
		r = recv(fd, u.buf, sizeof(u.buf), MSG_DONTWAIT);
		if (r <= 0)
			return -1;

		for (hdr = &u.reply; __NLMSG_OK(hdr, (void *)&u.buf[r]);
		     hdr = __NLMSG_NEXT(hdr)) {
			if (hdr->nlmsg_type == NLMSG_DONE)
				return 0;

			if (hdr->nlmsg_type == NLMSG_ERROR) {
				errno = EINVAL;
				return -1;
			}

			ret = cb(ctx, hdr);
			if (ret)
				return ret;
		}
	}
}

static int __rtnl_enumerate(int link_af, int addr_af, __s32 netns_id,
			    int (*cb)(void *ctx, struct nlmsghdr *h), void *ctx)
{
	int fd, r, saved_errno;

	fd = socket(PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	r = __netlink_recv(fd, 1, RTM_GETLINK, link_af, netns_id, cb, ctx);
	if (!r)
		r = __netlink_recv(fd, 2, RTM_GETADDR, netns_id, addr_af, cb,
				   ctx);

	saved_errno = errno;
	close(fd);
	errno = saved_errno;

	return r;
}

int netns_getifaddrs(struct netns_ifaddrs **ifap, __s32 netns_id)
{
	int r, saved_errno;
	struct ifaddrs_ctx _ctx;
	struct ifaddrs_ctx *ctx = &_ctx;

	memset(ctx, 0, sizeof *ctx);

	r = __rtnl_enumerate(AF_UNSPEC, AF_UNSPEC, netns_id, nl_msg_to_ifaddr,
			     ctx);
	saved_errno = errno;
	if (r < 0)
		netns_freeifaddrs(&ctx->first->ifa);
	else
		*ifap = &ctx->first->ifa;
	errno = saved_errno;

	return r;
}

// Dumper helpers
static void print_ip(const char *name, struct netns_ifaddrs *ifaddrs_ptr, void *addr_ptr)
{
	if (addr_ptr) {
		// This constant is defined in <netinet/in.h>
		char address[INET6_ADDRSTRLEN];
		inet_ntop(ifaddrs_ptr->ifa_addr->sa_family, addr_ptr, address,
			  sizeof(address));
		printf("%s: %s\n", name, address);
	} else {
		printf("No %s\n", name);
	}
}

// Get a pointer to the address structure from a sockaddr.
static void *get_addr_ptr(struct sockaddr *sockaddr_ptr)
{
	if (sockaddr_ptr->sa_family == AF_INET)
		return &((struct sockaddr_in *)sockaddr_ptr)->sin_addr;

	if (sockaddr_ptr->sa_family == AF_INET6)
		return &((struct sockaddr_in6 *)sockaddr_ptr)->sin6_addr;

	return NULL;
}

static char *get_packet_address(struct sockaddr *sockaddr_ptr, char *buf, size_t buflen)
{
	char *slider = buf;
	unsigned char *m = ((struct sockaddr_ll *)sockaddr_ptr)->sll_addr;
	unsigned char n = ((struct sockaddr_ll *)sockaddr_ptr)->sll_halen;

	for (unsigned char i = 0; i < n; i++) {
		int ret;

		ret = snprintf(slider, buflen, "%02x%s", m[i], (i + 1) < n ? ":" : "");
		if (ret < 0 || (size_t)ret >= buflen)
			return NULL;

		buflen -= ret;
		slider = (slider + ret);
	}

	return buf;
}

// Print the internet address.
static void print_internet_address(struct netns_ifaddrs *ifaddrs_ptr)
{
	void *addr_ptr;
	if (!ifaddrs_ptr->ifa_addr)
		return;
	addr_ptr = get_addr_ptr(ifaddrs_ptr->ifa_addr);
	print_ip("internet address", ifaddrs_ptr, addr_ptr);
}

// Print the netmask.
static void print_netmask(struct netns_ifaddrs *ifaddrs_ptr)
{
	void *addr_ptr;
	if (!ifaddrs_ptr->ifa_netmask)
		return;
	addr_ptr = get_addr_ptr(ifaddrs_ptr->ifa_netmask);
	print_ip("netmask", ifaddrs_ptr, addr_ptr);
	printf("%d\n", ifaddrs_ptr->ifa_prefixlen);
}

static void print_internet_interface(struct netns_ifaddrs *ifaddrs_ptr)
{
	print_internet_address(ifaddrs_ptr);
	print_netmask(ifaddrs_ptr);
	if (ifaddrs_ptr->__ifa_dstaddr) {
		void *addr_ptr = get_addr_ptr(ifaddrs_ptr->__ifa_dstaddr);
		print_ip("destination", ifaddrs_ptr, addr_ptr);
	}
	if (ifaddrs_ptr->__ifa_broadaddr) {
		void *addr_ptr = get_addr_ptr(ifaddrs_ptr->__ifa_broadaddr);
		print_ip("broadcast", ifaddrs_ptr, addr_ptr);
	}
}

void print_ifaddrs(struct netns_ifaddrs *ifaddrs_ptr)
{
	struct netns_ifaddrs *ifa_next;

	printf("Name: %s\n"
	       "ifindex: %d\n"
	       "mtu: %d\n"
	       "flags: %x\n",
	       ifaddrs_ptr->ifa_name,
	       ifaddrs_ptr->ifa_ifindex,
	       ifaddrs_ptr->ifa_mtu,
	       ifaddrs_ptr->ifa_flags);
	if (ifaddrs_ptr->ifa_addr->sa_family == AF_INET) {
		printf("AF_INET\n");
		print_internet_interface(ifaddrs_ptr);
		printf("\n");
	} else if (ifaddrs_ptr->ifa_addr->sa_family == AF_INET6) {
		printf("AF_INET6\n");
		print_internet_interface(ifaddrs_ptr);
		printf("\n");
	}

	ifa_next = ifaddrs_ptr->ifa_next;
	if (!ifa_next)
		return;

	print_ifaddrs(ifa_next);
}

extern int netlink_open(int protocol)
{
	int fd, ret;
	socklen_t socklen;
	struct sockaddr_nl local;
	int sndbuf = 32768;
	int rcvbuf = 32768;
	int err = -1;

	fd = socket(AF_NETLINK, SOCK_RAW, protocol);
	if (fd < 0)
		return -1;

	ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	if (ret < 0)
		goto out;

	ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	if (ret < 0)
		goto out;

	ret = bind(fd, (struct sockaddr *)&local, sizeof(local));
	if (ret < 0)
		goto out;

	socklen = sizeof(local);
	ret = getsockname(fd, (struct sockaddr *)&local, &socklen);
	if (ret < 0)
		goto out;

	errno = -EINVAL;
	if (socklen != sizeof(local))
		goto out;

	errno = -EINVAL;
	if (local.nl_family != AF_NETLINK)
		goto out;

	return 0;

out:
	close(fd);
	return err;
}

static int netlink_recv(int fd, struct nlmsghdr *nlmsghdr)
{
	int ret;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
	    .iov_base = nlmsghdr,
	    .iov_len = nlmsghdr->nlmsg_len,
	};

	struct msghdr msg = {
	    .msg_name = &nladdr,
	    .msg_namelen = sizeof(nladdr),
	    .msg_iov = &iov,
	    .msg_iovlen = 1,
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

again:
	ret = recvmsg(fd, &msg, 0);
	if (ret < 0) {
		if (errno == EINTR)
			goto again;

		return -1;
	}

	if (!ret)
		return 0;

	if (msg.msg_flags & MSG_TRUNC && (ret == nlmsghdr->nlmsg_len)) {
		errno = EMSGSIZE;
		ret = -1;
	}

	return ret;
}

enum {
	__LXC_NETNSA_NONE,
#define __LXC_NETNSA_NSID_NOT_ASSIGNED -1
	__LXC_NETNSA_NSID,
	__LXC_NETNSA_PID,
	__LXC_NETNSA_FD,
	__LXC_NETNSA_MAX,
};

static int netlink_transaction(int fd, struct nlmsghdr *request,
			       struct nlmsghdr *answer)
{
	int ret;

	ret = __netlink_send(fd, request);
	if (ret < 0)
		return -1;

	ret = netlink_recv(fd, answer);
	if (ret < 0)
		return -1;

	ret = 0;
	if (answer->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(answer);
		errno = -err->error;
		if (err->error < 0)
			ret = -1;
	}

	return ret;
}

static int parse_rtattr_flags(struct rtattr *tb[], int max, struct rtattr *rta,
			      int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}

	return 0;
}

static int parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
	return parse_rtattr_flags(tb, max, rta, len, 0);
}

static inline __s32 rta_getattr_s32(const struct rtattr *rta)
{
	return *(__s32 *)RTA_DATA(rta);
}

#ifndef NETNS_RTA
#define NETNS_RTA(r) \
	((struct rtattr *)(((char *)(r)) + NLMSG_ALIGN(sizeof(struct rtgenmsg))))
#endif

__s32 netns_get_nsid(int netns_fd)
{
	int fd, ret;
	ssize_t len;
	char buf[NLMSG_ALIGN(sizeof(struct nlmsghdr)) +
		 NLMSG_ALIGN(sizeof(struct rtgenmsg)) + NLMSG_ALIGN(1024)];
	struct rtattr *tb[__LXC_NETNSA_MAX + 1];
	struct nlmsghdr *hdr;
	struct rtgenmsg *msg;
	int saved_errno;

	fd = netlink_open(NETLINK_ROUTE);
	if (fd < 0)
		return -1;

	memset(buf, 0, sizeof(buf));
	hdr = (struct nlmsghdr *)buf;
	msg = (struct rtgenmsg *)NLMSG_DATA(hdr);

	hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*msg));
	hdr->nlmsg_type = RTM_GETNSID;
	hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	hdr->nlmsg_pid = 0;
	hdr->nlmsg_seq = RTM_GETNSID;
	msg->rtgen_family = AF_UNSPEC;

	addattr(hdr, 1024, __LXC_NETNSA_FD, &netns_fd, sizeof(__s32));

	ret = netlink_transaction(fd, hdr, hdr);
	saved_errno = errno;
	close(fd);
	errno = saved_errno;
	if (ret < 0)
		return -1;

	msg = NLMSG_DATA(hdr);
	len = hdr->nlmsg_len - NLMSG_SPACE(sizeof(*msg));
	if (len < 0)
		return -1;

	parse_rtattr(tb, __LXC_NETNSA_MAX, NETNS_RTA(msg), len);
	if (tb[__LXC_NETNSA_NSID]) {
		return rta_getattr_s32(tb[__LXC_NETNSA_NSID]);
	}

	return -1;
}
*/
import "C"

func NetnsGetifaddrs(initPID int32) (map[string]api.NetworkState, error) {
	var ifaddrs *C.struct_netns_ifaddrs
	var netnsID C.__s32

	if initPID > 0 {
		f, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", initPID))
		if err != nil {
			return nil, err
		}
		defer f.Close()

		netnsID = C.netns_get_nsid(C.__s32(f.Fd()))
		if netnsID < 0 {
			return nil, fmt.Errorf("Failed to retrieve network namespace id")
		}
	} else {
		netnsID = -1
	}

	ret := C.netns_getifaddrs(&ifaddrs, netnsID)
	if ret < 0 {
		return nil, fmt.Errorf("Failed to retrieve network interfaces and addresses")
	}
	defer C.netns_freeifaddrs(ifaddrs)

	// We're using the interface name as key here but we should really
	// switch to the ifindex at some point to handle ip aliasing correctly.
	networks := map[string]api.NetworkState{}

	for addr := ifaddrs; addr != nil; addr = addr.ifa_next {
		var address [C.INET6_ADDRSTRLEN]C.char
		addNetwork, networkExists := networks[C.GoString(addr.ifa_name)]
		if !networkExists {
			addNetwork = api.NetworkState{
				Addresses: []api.NetworkStateAddress{},
				Counters:  api.NetworkStateCounters{},
			}
		}

		if addr.ifa_addr.sa_family == C.AF_INET || addr.ifa_addr.sa_family == C.AF_INET6 {
			netState := "down"
			netType := "unknown"

			if (addr.ifa_flags & C.IFF_BROADCAST) > 0 {
				netType = "broadcast"
			}

			if (addr.ifa_flags & C.IFF_LOOPBACK) > 0 {
				netType = "loopback"
			}

			if (addr.ifa_flags & C.IFF_POINTOPOINT) > 0 {
				netType = "point-to-point"
			}

			if (addr.ifa_flags & C.IFF_UP) > 0 {
				netState = "up"
			}

			family := "inet"
			if addr.ifa_addr.sa_family == C.AF_INET6 {
				family = "inet6"
			}

			addr_ptr := C.get_addr_ptr(addr.ifa_addr)
			if addr_ptr == nil {
				return nil, fmt.Errorf("Failed to retrieve valid address pointer")
			}

			address_str := C.inet_ntop(C.int(addr.ifa_addr.sa_family), addr_ptr, &address[0], C.INET6_ADDRSTRLEN)
			if address_str == nil {
				return nil, fmt.Errorf("Failed to retrieve address string")
			}

			if addNetwork.Addresses == nil {
				addNetwork.Addresses = []api.NetworkStateAddress{}
			}

			goAddrString := C.GoString(address_str)
			scope := "global"
			if strings.HasPrefix(goAddrString, "127") {
				scope = "local"
			}

			if goAddrString == "::1" {
				scope = "local"
			}

			if strings.HasPrefix(goAddrString, "169.254") {
				scope = "link"
			}

			if strings.HasPrefix(goAddrString, "fe80:") {
				scope = "link"
			}

			address := api.NetworkStateAddress{}
			address.Family = family
			address.Address = goAddrString
			address.Netmask = fmt.Sprintf("%d", int(addr.ifa_prefixlen))
			address.Scope = scope

			addNetwork.Addresses = append(addNetwork.Addresses, address)
			addNetwork.State = netState
			addNetwork.Type = netType
			addNetwork.Mtu = int(addr.ifa_mtu)
		} else if addr.ifa_addr.sa_family == C.AF_PACKET {
			var buf [1024]C.char

			hwaddr := C.get_packet_address(addr.ifa_addr, &buf[0], 1024)
			if hwaddr == nil {
				return nil, fmt.Errorf("Failed to retrieve hardware address")
			}

			addNetwork.Hwaddr = C.GoString(hwaddr)

			stats := (*C.struct_rtnl_link_stats)(addr.ifa_data)
			if stats != nil {
				addNetwork.Counters.BytesReceived = int64(stats.rx_bytes)
				addNetwork.Counters.BytesSent = int64(stats.tx_bytes)
				addNetwork.Counters.PacketsReceived = int64(stats.rx_packets)
				addNetwork.Counters.PacketsSent = int64(stats.tx_packets)
			}
		}
		ifName := C.GoString(addr.ifa_name)

		networks[ifName] = addNetwork
	}

	return networks, nil
}

func WebsocketExecMirror(conn *websocket.Conn, w io.WriteCloser, r io.ReadCloser, exited chan bool, fd int) (chan bool, chan bool) {
	readDone := make(chan bool, 1)
	writeDone := make(chan bool, 1)

	go defaultWriter(conn, w, writeDone)

	go func(conn *websocket.Conn, r io.ReadCloser) {
		in := ExecReaderToChannel(r, -1, exited, fd)
		for {
			buf, ok := <-in
			if !ok {
				r.Close()
				logger.Debugf("sending write barrier")
				conn.WriteMessage(websocket.TextMessage, []byte{})
				readDone <- true
				return
			}
			w, err := conn.NextWriter(websocket.BinaryMessage)
			if err != nil {
				logger.Debugf("Got error getting next writer %s", err)
				break
			}

			_, err = w.Write(buf)
			w.Close()
			if err != nil {
				logger.Debugf("Got err writing %s", err)
				break
			}
		}
		closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
		conn.WriteMessage(websocket.CloseMessage, closeMsg)
		readDone <- true
		r.Close()
	}(conn, r)

	return readDone, writeDone
}
