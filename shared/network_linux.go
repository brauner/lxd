// +build linux
// +build cgo

package shared

import (
	"fmt"
	"io"

	"github.com/gorilla/websocket"

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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/types.h>
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

	if (netns_id != -EINVAL)
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
	void *addr_ptr = 0;
	if (sockaddr_ptr->sa_family == AF_INET)
		addr_ptr = &((struct sockaddr_in *)sockaddr_ptr)->sin_addr;
	else if (sockaddr_ptr->sa_family == AF_INET6)
		addr_ptr = &((struct sockaddr_in6 *)sockaddr_ptr)->sin6_addr;
	return addr_ptr;
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
*/
import "C"

func NetnsGetifaddrs(netnsID int32) error {
	var ifaddrs *C.struct_netns_ifaddrs

	ret := C.netns_getifaddrs(&ifaddrs, C.__s32(netnsID))
	if ret < 0 {
		return fmt.Errorf("Failed to retrieve interfaces and addresses")
	}

	C.print_ifaddrs(ifaddrs)
	C.netns_freeifaddrs(ifaddrs)

	return nil
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
