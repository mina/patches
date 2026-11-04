/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * Implementation for a "virtual network device" module to
 * inject packets into the kernel and read packets leaving the kernel.
 */

#include "netdev.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef linux
#include <endian.h>
#include <linux/if_packet.h>
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <net/if_tun.h>
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#include "assert.h"
#include "ethernet.h"
#include "ip.h"
#include "ipv6.h"
#include "logging.h"
#include "net_utils.h"
#include "packet.h"
#include "packet_parser.h"
#include "packet_socket.h"
#include "tcp.h"
#include "tun.h"
#include "wrap.h"

/* Internal private state for the netdev for purely local tests. */
struct local_netdev {
	struct netdev netdev;		/* "inherit" from netdev */

	char *name;		/* malloc-ed copy of interface name (owned) */
	int tun_fd;		/* tun (or AF_PACKET tx) fd for injecting packets */
	int control_fd;		/* fd for configuration of tun interface */
	int index;		/* interface index from if_nametoindex */
	bool is_nsim;		/* using linked netdevsim pair instead of tun */
	struct ether_addr local_mac;
	struct ether_addr remote_mac;
	struct packet_socket *psock;	/* for sniffing packets (owned) */
};

#ifdef linux
static int nsim_created_ids[2] = { -1, -1 };
static bool nsim_atexit_registered;

static int nsim_write_sysfs(const char *path, const char *val)
{
	ssize_t n, len = strlen(val);
	int fd, saved_errno;

	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -errno;
	n = write(fd, val, len);
	saved_errno = errno;
	close(fd);
	return (n == len) ? 0 : -(saved_errno ? saved_errno : EIO);
}

static void cleanup_nsim_devices(void)
{
	char buf[32];
	int i;

	for (i = 1; i >= 0; i--) {
		if (nsim_created_ids[i] >= 0) {
			snprintf(buf, sizeof(buf), "%d", nsim_created_ids[i]);
			nsim_write_sysfs("/sys/bus/netdevsim/del_device", buf);
			nsim_created_ids[i] = -1;
		}
	}
}

static bool should_use_nsim(void)
{
	const char *env = getenv("PACKETDRILL_NSIM");

	if (env)
		return env[0] != '\0' && strcmp(env, "0") != 0;
	return access("/sys/bus/netdevsim/new_device", W_OK) == 0;
}

static int nsim_alloc_pair(unsigned int *out_id)
{
	unsigned int base = 10000 + ((unsigned int)getpid() % 20000) * 2;
	unsigned int attempt;

	for (attempt = 0; attempt < 20000; attempt++) {
		unsigned int id = 10000 + ((base - 10000 + attempt * 2) % 40000);
		char buf0[32], buf1[32], del0[32];

		snprintf(buf0, sizeof(buf0), "%u 1", id);
		if (nsim_write_sysfs("/sys/bus/netdevsim/new_device", buf0) < 0)
			continue;

		snprintf(buf1, sizeof(buf1), "%u 1", id + 1);
		if (nsim_write_sysfs("/sys/bus/netdevsim/new_device", buf1) < 0) {
			snprintf(del0, sizeof(del0), "%u", id);
			nsim_write_sysfs("/sys/bus/netdevsim/del_device", del0);
			continue;
		}

		nsim_created_ids[0] = id;
		nsim_created_ids[1] = id + 1;
		if (!nsim_atexit_registered) {
			atexit(cleanup_nsim_devices);
			nsim_atexit_registered = true;
		}
		*out_id = id;
		return 0;
	}
	return -ENOSPC;
}
#endif

struct netdev_ops local_netdev_ops;

/* "Downcast" an abstract netdev to our local flavor. */
static inline struct local_netdev *to_local_netdev(struct netdev *netdev)
{
	return (struct local_netdev *)netdev;
}

/* Clean up any old tun device state that might be lying around from
 * previous tests. NetBSD the kernel does not automatically tear down
 * unreferenced tun devices and routes referencing those routes.
 */
static void cleanup_old_device(struct config *config,
				struct local_netdev *netdev)
{
#if defined(__NetBSD__)
	char *cleanup_command = NULL;
	int result;

	asprintf(&cleanup_command,
		 "/sbin/ifconfig %s down delete > /dev/null 2>&1",
		 TUN_DEV);
	DEBUGP("running: '%s'\n", cleanup_command);
	result = system(cleanup_command);
	DEBUGP("result: %d\n", result);
	free(cleanup_command);
#endif  /* defined(__NetBSD__) */
}

/* Check that the remote IP is actually remote. It must be to ensure
 * that test packets will pass into our tun device.
 */
static void check_remote_address(struct config *config,
				 struct local_netdev *netdev)
{
	if (is_ip_local(&config->live_remote_ip)) {
		die("error: live_remote_ip %s is not remote\n",
		    config->live_remote_ip_string);
	}
}

/* Make sure config->live_local_ip is not configured on any devices.
 * This is only used for anyip tests.
 */
static void check_local_anyip(struct config *config)
{
	if (is_ip_local(&config->live_local_ip)) {
		die("error: live_local_ip %s is not remote for anyip\n",
		    config->live_local_ip_string);
	}
}

/* Create a tun (or linked netdevsim) device for the lifetime of this test. */
static void create_device(struct config *config, struct local_netdev *netdev)
{
#ifdef linux
	if (should_use_nsim()) {
		struct sockaddr_ll sll = { 0 };
		struct ifreq ifr;
		int one = 1;
		int peer_if;
		char *cmd;

		netdev->is_nsim = true;
		netdev->name = strdup("tun0");
		netdev->control_fd = wrap_socket(config->ip_version,
						 SOCK_DGRAM);

		if (if_nametoindex("tun0") == 0) {
			unsigned int id;

			if (nsim_alloc_pair(&id) < 0)
				die("unable to allocate netdevsim pair\n");

			asprintf(&cmd,
				 "set -e; "
				 "d0=$(ls /sys/bus/netdevsim/devices/netdevsim%u/net | head -n1); "
				 "d1=$(ls /sys/bus/netdevsim/devices/netdevsim%u/net | head -n1); "
				 "ip link set \"$d0\" name tun0; "
				 "ip link set \"$d1\" name nsim1; "
				 "exec 3</sys/class/net/tun0/ifindex; "
				 "exec 4</sys/class/net/nsim1/ifindex; "
				 "exec 5</proc/self/ns/net; "
				 "read i0 <&3; read i1 <&4; "
				 "echo \"5:$i0 5:$i1\" > /sys/bus/netdevsim/link_device; "
				 "sysctl -qw net.ipv6.conf.tun0.accept_dad=0 "
				 "net.ipv6.conf.nsim1.disable_ipv6=1; "
				 "ethtool -C tun0 rx-usecs 0 2>/dev/null || true; "
				 "ethtool -C nsim1 rx-usecs 0 2>/dev/null || true; "
				 "tc qdisc replace dev nsim1 root pfifo 2>/dev/null || true; "
				 "if [ -n \"$PACKETDRILL_NSIM_HDS\" ]; then "
				 "ethtool -G tun0 tcp-data-split enabled 2>/dev/null || true; "
				 "fi; "
				 "ip link set nsim1 up",
				 id, id + 1);
		} else {
			asprintf(&cmd,
				 "ip addr flush dev tun0; "
				 "ip route flush dev tun0 2>/dev/null || true; "
				 "ip -6 route flush dev tun0 2>/dev/null || true; "
				 "sysctl -qw net.ipv6.conf.tun0.accept_dad=0 "
				 "net.ipv6.conf.nsim1.disable_ipv6=1; "
				 "tc qdisc replace dev nsim1 root pfifo 2>/dev/null || true; "
				 "ip link set nsim1 up");
		}
		if (system(cmd) != 0)
			die("error setting up netdevsim: %s\n", cmd);
		free(cmd);

		netdev->index = if_nametoindex("tun0");
		peer_if = if_nametoindex("nsim1");
		if (!netdev->index || !peer_if)
			die_perror("if_nametoindex tun0/nsim1");

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, "tun0", IFNAMSIZ - 1);
		if (ioctl(netdev->control_fd, SIOCGIFHWADDR, &ifr) < 0)
			die_perror("SIOCGIFHWADDR tun0");
		memcpy(&netdev->local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, "nsim1", IFNAMSIZ - 1);
		if (ioctl(netdev->control_fd, SIOCGIFHWADDR, &ifr) < 0)
			die_perror("SIOCGIFHWADDR nsim1");
		memcpy(&netdev->remote_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

		netdev->tun_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (netdev->tun_fd < 0)
			die_perror("socket PF_PACKET nsim1");
		if (setsockopt(netdev->tun_fd, SOL_PACKET, PACKET_VNET_HDR,
			       &one, sizeof(one)) < 0)
			die_perror("setsockopt PACKET_VNET_HDR");
		sll.sll_family = AF_PACKET;
		sll.sll_ifindex = peer_if;
		sll.sll_protocol = htons(ETH_P_ALL);
		if (bind(netdev->tun_fd, (struct sockaddr *)&sll,
			 sizeof(sll)) < 0)
			die_perror("bind PF_PACKET nsim1");

		if (config->speed != TUN_DRIVER_SPEED_CUR) {
			asprintf(&cmd,
				 "ethtool -s tun0 speed %u duplex full autoneg off; "
				 "ethtool -s nsim1 speed %u duplex full autoneg off",
				 config->speed, config->speed);
			if (system(cmd) < 0)
				die("Error executing %s\n", cmd);
			free(cmd);
		}
		if (config->mtu != TUN_DRIVER_DEFAULT_MTU) {
			asprintf(&cmd, "ip link set tun0 mtu %d; "
				 "ip link set nsim1 mtu %d",
				 config->mtu, config->mtu);
			if (system(cmd) < 0)
				die("Error executing %s\n", cmd);
			free(cmd);
		}
		return;
	}
#endif
	/* Open the tun device, which "clones" it for our purposes. */
	int tun_fd;
#ifdef linux
	int nb = 0;

loop:
	if (++nb > 10)
		die_perror("open tun device");
#endif
	tun_fd = open(TUN_PATH, O_RDWR);
	if (tun_fd < 0)
		die_perror("open tun device");

	netdev->tun_fd = tun_fd;

#ifdef linux
	/* Create the device. Since we do not specify a device name, the
	 * kernel will try to allocate the "next" device of the specified
	 * type. This device will disappear when we are done.
	 */
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
	int status = ioctl(netdev->tun_fd, TUNSETIFF, (void *)&ifr);
	if (status < 0)
		die_perror("TUNSETIFF");

	/* Our tests rely on using tun0.
	 * We might change this in the future, by passing a variable filled
	 * with tunnel name. In the mean time, wait a bit that tun0 gets free.
	 */
	if (strcmp(ifr.ifr_name, "tun0")) {
		close(tun_fd);
		usleep(100000);
		goto loop;
	}
	netdev->name = strdup(ifr.ifr_name);
#endif

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	const int mode = IFF_BROADCAST | IFF_MULTICAST;
	if (ioctl(netdev->tun_fd, TUNSIFMODE, &mode, sizeof(mode)) < 0)
		die_perror("TUNSIFMODE");

	netdev->name = strdup(TUN_DEV);
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#if defined(__FreeBSD__) ||  defined(__NetBSD__)
	/* On FreeBSD and NetBSD we need to explicitly ask to be able
	 * to prepend the address family when injecting tun packets.
	 * OpenBSD presumes we are doing this, even without the ioctl.
	 */
	const int header = 1;
	if (ioctl(netdev->tun_fd, TUNSIFHEAD, &header, sizeof(header)) < 0)
		die_perror("TUNSIFHEAD");
#endif /* defined(__FreeBSD__) ||  defined(__NetBSD__) */

	DEBUGP("tun name: '%s'\n", netdev->name);

	netdev->index = if_nametoindex(netdev->name);
	if (netdev->index == 0)
		die_perror("if_nametoindex");

	DEBUGP("tun index: '%d'\n", netdev->index);

	if (config->speed != TUN_DRIVER_SPEED_CUR) {
		char *command;
		asprintf(&command, "ethtool -s %s speed %u autoneg off",
			 netdev->name, config->speed);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);

		/* Need to bring interface down and up so the interface speed
		 * will be copied to the link_speed field. This field is
		 * used by TCP's cwnd bound. */
		asprintf(&command, "ifconfig %s down; sleep 1; ifconfig %s up; "
			      "sleep 1", netdev->name, netdev->name);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);
	}

	if (config->mtu != TUN_DRIVER_DEFAULT_MTU) {
		char *command;
		asprintf(&command, "ifconfig %s mtu %d",
			 netdev->name, config->mtu);
		if (system(command) < 0)
			die("Error executing %s\n", command);
		free(command);
	}

	/* Open a socket we can use to configure the tun interface. */
	netdev->control_fd = wrap_socket(config->ip_version, SOCK_DGRAM);
}

/* Set the offload flags to be like a typical ethernet device */
static void set_device_offload_flags(struct local_netdev *netdev)
{
#ifdef linux
	if (netdev->is_nsim)
		return;
	const u32 offload =
	    TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN;
	if (ioctl(netdev->tun_fd, TUNSETOFFLOAD, offload) != 0)
		die_perror("TUNSETOFFLOAD");
#endif
}

/* Bring up the device */
static void bring_up_device(struct local_netdev *netdev)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, netdev->name, IFNAMSIZ);
	if (ioctl(netdev->control_fd, SIOCGIFFLAGS, &ifr) < 0)
		die_perror("SIOCGIFFLAGS");
	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(netdev->control_fd, SIOCSIFFLAGS, &ifr) < 0)
		die_perror("SIOCSIFFLAGS");
}

/* Route traffic destined for our remote IP through this device.
 * In anyip environment, we don't use the gateway IP.
 */
static void route_traffic_to_device(struct config *config,
				    struct local_netdev *netdev)
{
	char *route_command = NULL;
#ifdef linux
	asprintf(&route_command,
		 "ip -%d route del %s > /dev/null 2>&1 ; "
		 "ip -%d route add %s dev %s %s%s > /dev/null 2>&1",
		 (config->wire_protocol == AF_INET) ? 4 : 6,
		 config->live_remote_prefix_string,
		 (config->wire_protocol == AF_INET) ? 4 : 6,
		 config->live_remote_prefix_string,
		 netdev->name,
		 config->is_anyip ? "" : "via ",
		 config->is_anyip ? "" :
		 config->live_gateway_ip_string);
#endif
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	if (config->wire_protocol == AF_INET) {
		asprintf(&route_command,
			 "route delete %s > /dev/null 2>&1 ; "
			 "route add %s %s > /dev/null",
			 config->live_remote_prefix_string,
			 config->live_remote_prefix_string,
			 config->live_gateway_ip_string);
	} else if (config->wire_protocol == AF_INET6) {
		asprintf(&route_command,
			 "route delete -inet6 %s > /dev/null 2>&1 ; "
#if defined(__FreeBSD__)
			 "route add -inet6 %s -interface tun0 %s > /dev/null",
#elif defined(__OpenBSD__) || defined(__NetBSD__)
			 "route add -inet6 %s %s > /dev/null",
#endif
			 config->live_remote_prefix_string,
			 config->live_remote_prefix_string,
			 config->live_gateway_ip_string);
	} else {
		assert(!"bad wire protocol");
	}
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */
	int result = system(route_command);
	if ((result == -1) || (WEXITSTATUS(result) != 0)) {
		if (netdev->is_nsim && !config->is_anyip) {
			free(route_command);
			asprintf(&route_command,
				 "ip -%d route replace %s dev %s; "
				 "ip -%d route replace %s dev %s via %s",
				 (config->wire_protocol == AF_INET) ? 4 : 6,
				 config->live_gateway_ip_string,
				 netdev->name,
				 (config->wire_protocol == AF_INET) ? 4 : 6,
				 config->live_remote_prefix_string,
				 netdev->name,
				 config->live_gateway_ip_string);
			result = system(route_command);
		}
		if ((result == -1) || (WEXITSTATUS(result) != 0))
			die("error executing route command '%s'\n",
			    route_command);
	}
	free(route_command);
#ifdef linux
	if (netdev->is_nsim) {
		char mac[32];
		const u8 *m = (const u8 *)&netdev->remote_mac;

		snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
			 m[0], m[1], m[2], m[3], m[4], m[5]);
		asprintf(&route_command,
			 "ip -%d neigh replace %s lladdr %s dev %s nud permanent; "
			 "ip -%d neigh replace %s lladdr %s dev %s nud permanent",
			 (config->wire_protocol == AF_INET) ? 4 : 6,
			 config->live_gateway_ip_string, mac, netdev->name,
			 (config->wire_protocol == AF_INET) ? 4 : 6,
			 config->live_remote_ip_string, mac, netdev->name);
		system(route_command);
		free(route_command);
	}
#endif
}

struct netdev *local_netdev_new(struct config *config)
{
	struct local_netdev *netdev = calloc(1, sizeof(struct local_netdev));

	netdev->netdev.ops = &local_netdev_ops;

	cleanup_old_device(config, netdev);

	check_remote_address(config, netdev);
	create_device(config, netdev);
	set_device_offload_flags(netdev);
	bring_up_device(netdev);

	if (config->is_anyip)
		check_local_anyip(config);
	else
		net_setup_dev_address(netdev->name,
				      &config->live_local_ip,
				      config->live_prefix_len);

	route_traffic_to_device(config, netdev);
	netdev->psock = packet_socket_new(netdev->name);

	return (struct netdev *)netdev;
}

static void local_netdev_free(struct netdev *a_netdev)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);

	if (netdev->psock)
		packet_socket_free(netdev->psock);
	if (netdev->tun_fd >= 0)
		close(netdev->tun_fd);
	if (netdev->control_fd >= 0)
		close(netdev->control_fd);
	if (netdev->name != NULL)
		free(netdev->name);
	memset(netdev, 0, sizeof(*netdev));  /* paranoia to help catch bugs */
	free(netdev);
}

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
/* According to `man 4 tun` on OpenBSD: "Each packet read or written
 * is prefixed with a tunnel header consisting of a 4-byte network
 * byte order integer containing the address family in the case of
 * layer 3 tunneling." Similarly, on FreeBSD and NetBSD one must use
 * ioctl(TUNSIFHEAD) and prepend an address family, in order to be
 * able to send IPv6 packets (otherwise FreeBSD and NetBSD assume the
 * packets are IPv4).
 */
static void bsd_tun_write(struct local_netdev *netdev,
			  struct packet *packet)
{
	int address_family = htonl(packet_address_family(packet));
	struct iovec vector[2] = {
		{ &address_family, sizeof(address_family) },
		{ packet_start(packet), packet->ip_bytes }
	};

	if (writev(netdev->tun_fd, vector, ARRAY_SIZE(vector)) < 0)
		die_perror("BSD tun write()");
}
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#ifdef linux
#include <linux/virtio_net.h>

static void linux_tun_write(struct local_netdev *netdev,
			    struct packet *packet)
{
	struct virtio_net_hdr gso = { 0 };
	struct ether_header ether;

	if (packet->tcp && packet->mss) {
		if (packet->ipv4)
			gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		else
			gso.gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		gso.gso_size = htole16(packet->mss);
	}
	if (netdev->is_nsim) {
		int af = packet_address_family(packet);
		size_t total_len = sizeof(ether) + packet->ip_bytes;
		size_t hdr_len = total_len < 3760 ? total_len : 3760;
		struct iovec vec[3] = {
			{ &gso, sizeof(gso) },
			{ &ether, sizeof(ether) },
			{ packet_start(packet), packet->ip_bytes }
		};

		/* Match tun_alloc_skb() linear headroom (3776 - 16 = 3760) so
		 * skb->truesize matches tun across nonlinear GSO/OOO tests.
		 */
		gso.hdr_len = htole16(hdr_len);
		ether_copy(ether.ether_dhost, &netdev->local_mac);
		ether_copy(ether.ether_shost, &netdev->remote_mac);
		ether.ether_type = htons(ether_type_for_family(af));
		if (writev(netdev->tun_fd, vec, ARRAY_SIZE(vec)) < 0)
			die_perror("Linux nsim writev()");
		return;
	}

	struct iovec vector[2] = {
		{ &gso, sizeof(gso) },
		{ packet_start(packet), packet->ip_bytes }
	};
	if (writev(netdev->tun_fd, vector, ARRAY_SIZE(vector)) < 0)
		die_perror("Linux tun write()");
}
#endif  /* linux */

static int local_netdev_send(struct netdev *a_netdev,
			     struct packet *packet)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);

	assert(packet->ip_bytes > 0);
	/* We do IPv4 and IPv6 */
	assert(packet->ipv4 || packet->ipv6);
	/* We only do TCP and ICMP */
	assert(packet->tcp || packet->udp || packet->icmpv4 || packet->icmpv6);

	DEBUGP("local_netdev_send\n");

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
	bsd_tun_write(netdev, packet);
#endif /* defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) */

#ifdef linux
	linux_tun_write(netdev, packet);
#endif  /* linux */

	return STATUS_OK;
}

/* Read the given number of packets out of the tun device. We read
 * these packets so that the kernel can exercise its normal code paths
 * for packet transmit completion, since this code path may feed back
 * to TCP behavior; e.g., see the Linux patch "tcp: avoid retransmits
 * of TCP packets hanging in host queues".  We don't need to actually
 * need the packet contents, but on Linux we need to read at least 1
 * byte of packet data to consume the packet.
 * After we added IFF_VNET_HDR attribute to the linux tun device,
 * we expect to receive a virtio_net_hdr at the beginning.
 */
static void local_netdev_read_queue(struct local_netdev *netdev,
				    int num_packets)
{
#ifdef linux
	char buf[sizeof(struct virtio_net_hdr) + 1];
#else
	char buf[1];
#endif
	int i = 0, in_bytes = 0;

	for (i = 0; i < num_packets; ++i) {
		in_bytes = read(netdev->tun_fd, buf, sizeof(buf));
		assert(in_bytes <= (int)sizeof(buf));

		if (in_bytes < 0) {
			if (errno == EINTR)
				continue;
			else
				die_perror("tun read()");
		}
       }
}

static int local_netdev_receive(struct netdev *a_netdev, s32 timeout_secs,
				struct packet **packet, char **error)
{
	struct local_netdev *netdev = to_local_netdev(a_netdev);
	int status = STATUS_ERR;
	int num_packets = 0;

	DEBUGP("local_netdev_receive\n");

	status = netdev_receive_loop(netdev->psock,
				     netdev->is_nsim ? PACKET_LAYER_2_ETHERNET :
						       PACKET_LAYER_3_IP,
				     DIRECTION_OUTBOUND, timeout_secs, packet,
				     &num_packets, error);
	if (status == STATUS_TIMEOUT)
		return STATUS_TIMEOUT;
	if (!netdev->is_nsim)
		local_netdev_read_queue(netdev, num_packets);
	return status;
}

int netdev_receive_loop(struct packet_socket *psock,
			enum packet_layer_t layer,
			enum direction_t direction,
			s32 timeout_secs,
			struct packet **packet,
			int *num_packets,
			char **error)
{
	assert(*packet == NULL);	/* should be no packet yet */

	*num_packets = 0;
	while (1) {
		int in_bytes = 0;
		enum packet_parse_result_t result;

		*packet = packet_new(PACKET_READ_BYTES);

		/* Sniff the next outbound packet from the kernel under test. */
		int rcv_status = packet_socket_receive(
			psock, direction, timeout_secs, *packet, &in_bytes);

		if (rcv_status == STATUS_TIMEOUT) {
			/* Set an error message indicating what occurred. */
			asprintf(error, "Timed out waiting for packet");
			return STATUS_TIMEOUT;
		}
		if (rcv_status) {
			packet_free(*packet);
			*packet = NULL;
			continue;
		}

		++*num_packets;
		result = parse_packet(*packet, in_bytes, layer, error);

		if (result == PACKET_OK)
			return STATUS_OK;

		packet_free(*packet);
		*packet = NULL;

		if (result == PACKET_BAD)
			return STATUS_ERR;

		DEBUGP("parse_result:%d; error parsing packet: %s\n",
		       result, *error);
	}

	assert(!"should not be reached");
	return STATUS_ERR;	/* not reached */
}

struct netdev_ops local_netdev_ops = {
	.free = local_netdev_free,
	.send = local_netdev_send,
	.receive = local_netdev_receive,
};
