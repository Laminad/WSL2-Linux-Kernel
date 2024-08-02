// SPDX-License-Identifier: GPL-2.0-or-later
/* Local endpoint object management
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/net.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/hashtable.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/af_rxrpc.h>
#include "ar-internal.h"

static void rxrpc_local_rcu(struct rcu_head *);

/*
 * Handle an ICMP/ICMP6 error turning up at the tunnel.  Push it through the
 * usual mechanism so that it gets parsed and presented through the UDP
 * socket's error_report().
 */
static void rxrpc_encap_err_rcv(struct sock *sk, struct sk_buff *skb, int err,
				__be16 port, u32 info, u8 *payload)
{
	if (ip_hdr(skb)->version == IPVERSION)
		return ip_icmp_error(sk, skb, err, port, info, payload);
	if (IS_ENABLED(CONFIG_AF_RXRPC_IPV6))
		return ipv6_icmp_error(sk, skb, err, port, info, payload);
}

/*
 * Set or clear the Don't Fragment flag on a socket.
 */
void rxrpc_local_dont_fragment(const struct rxrpc_local *local, bool set)
{
	if (set)
		ip_sock_set_mtu_discover(local->socket->sk, IP_PMTUDISC_DO);
	else
		ip_sock_set_mtu_discover(local->socket->sk, IP_PMTUDISC_DONT);
}

/*
 * Compare a local to an address.  Return -ve, 0 or +ve to indicate less than,
 * same or greater than.
 *
 * We explicitly don't compare the RxRPC service ID as we want to reject
 * conflicting uses by differing services.  Further, we don't want to share
 * addresses with different options (IPv6), so we don't compare those bits
 * either.
 */
static long rxrpc_local_cmp_key(const struct rxrpc_local *local,
				const struct sockaddr_rxrpc *srx)
{
	long diff;

	diff = ((local->srx.transport_type - srx->transport_type) ?:
		(local->srx.transport_len - srx->transport_len) ?:
		(local->srx.transport.family - srx->transport.family));
	if (diff != 0)
		return diff;

	switch (srx->transport.family) {
	case AF_INET:
		/* If the choice of UDP port is left up to the transport, then
		 * the endpoint record doesn't match.
		 */
		return ((u16 __force)local->srx.transport.sin.sin_port -
			(u16 __force)srx->transport.sin.sin_port) ?:
			memcmp(&local->srx.transport.sin.sin_addr,
			       &srx->transport.sin.sin_addr,
			       sizeof(struct in_addr));
#ifdef CONFIG_AF_RXRPC_IPV6
	case AF_INET6:
		/* If the choice of UDP6 port is left up to the transport, then
		 * the endpoint record doesn't match.
		 */
		return ((u16 __force)local->srx.transport.sin6.sin6_port -
			(u16 __force)srx->transport.sin6.sin6_port) ?:
			memcmp(&local->srx.transport.sin6.sin6_addr,
			       &srx->transport.sin6.sin6_addr,
			       sizeof(struct in6_addr));
#endif
	default:
		BUG();
	}
}

static void rxrpc_client_conn_reap_timeout(struct timer_list *timer)
{
	struct rxrpc_local *local =
		container_of(timer, struct rxrpc_local, client_conn_reap_timer);

	if (!local->kill_all_client_conns &&
	    test_and_set_bit(RXRPC_CLIENT_CONN_REAP_TIMER, &local->client_conn_flags))
		rxrpc_wake_up_io_thread(local);
}

/*
 * Allocate a new local endpoint.
 */
static struct rxrpc_local *rxrpc_alloc_local(struct net *net,
					     const struct sockaddr_rxrpc *srx)
{
	struct rxrpc_local *local;
	u32 tmp;

	local = kzalloc(sizeof(struct rxrpc_local), GFP_KERNEL);
	if (local) {
<<<<<<< HEAD
		refcount_set(&local->ref, 1);
		atomic_set(&local->active_users, 1);
		local->net = net;
		local->rxnet = rxrpc_net(net);
		INIT_HLIST_NODE(&local->link);
		init_completion(&local->io_thread_ready);
#ifdef CONFIG_AF_RXRPC_INJECT_RX_DELAY
		skb_queue_head_init(&local->rx_delay_queue);
#endif
		skb_queue_head_init(&local->rx_queue);
		INIT_LIST_HEAD(&local->conn_attend_q);
		INIT_LIST_HEAD(&local->call_attend_q);

		local->client_bundles = RB_ROOT;
		spin_lock_init(&local->client_bundles_lock);
		local->kill_all_client_conns = false;
		INIT_LIST_HEAD(&local->idle_client_conns);
		timer_setup(&local->client_conn_reap_timer,
			    rxrpc_client_conn_reap_timeout, 0);

=======
		atomic_set(&local->usage, 1);
		atomic_set(&local->active_users, 1);
		local->rxnet = rxnet;
		INIT_LIST_HEAD(&local->link);
		INIT_WORK(&local->processor, rxrpc_local_processor);
		init_rwsem(&local->defrag_sem);
		skb_queue_head_init(&local->reject_queue);
		skb_queue_head_init(&local->event_queue);
		local->client_conns = RB_ROOT;
		spin_lock_init(&local->client_conns_lock);
>>>>>>> master
		spin_lock_init(&local->lock);
		rwlock_init(&local->services_lock);
		local->debug_id = atomic_inc_return(&rxrpc_debug_id);
		memcpy(&local->srx, srx, sizeof(*srx));
		local->srx.srx_service = 0;
<<<<<<< HEAD
		idr_init(&local->conn_ids);
		get_random_bytes(&tmp, sizeof(tmp));
		tmp &= 0x3fffffff;
		if (tmp == 0)
			tmp = 1;
		idr_set_cursor(&local->conn_ids, tmp);
		INIT_LIST_HEAD(&local->new_client_calls);
		spin_lock_init(&local->client_call_lock);

		trace_rxrpc_local(local->debug_id, rxrpc_local_new, 1, 1);
=======
		trace_rxrpc_local(local->debug_id, rxrpc_local_new, 1, NULL);
>>>>>>> master
	}

	_leave(" = %p", local);
	return local;
}

/*
 * create the local socket
 * - must be called with rxrpc_local_mutex locked
 */
static int rxrpc_open_socket(struct rxrpc_local *local, struct net *net)
{
	struct udp_tunnel_sock_cfg tuncfg = {NULL};
	struct sockaddr_rxrpc *srx = &local->srx;
	struct udp_port_cfg udp_conf = {0};
	struct task_struct *io_thread;
	struct sock *usk;
	int ret;

	_enter("%p{%d,%d}",
	       local, srx->transport_type, srx->transport.family);

	udp_conf.family = srx->transport.family;
	udp_conf.use_udp_checksums = true;
	if (udp_conf.family == AF_INET) {
		udp_conf.local_ip = srx->transport.sin.sin_addr;
		udp_conf.local_udp_port = srx->transport.sin.sin_port;
#if IS_ENABLED(CONFIG_AF_RXRPC_IPV6)
	} else {
		udp_conf.local_ip6 = srx->transport.sin6.sin6_addr;
		udp_conf.local_udp_port = srx->transport.sin6.sin6_port;
		udp_conf.use_udp6_tx_checksums = true;
		udp_conf.use_udp6_rx_checksums = true;
#endif
	}
	ret = udp_sock_create(net, &udp_conf, &local->socket);
	if (ret < 0) {
		_leave(" = %d [socket]", ret);
		return ret;
	}

	tuncfg.encap_type = UDP_ENCAP_RXRPC;
	tuncfg.encap_rcv = rxrpc_encap_rcv;
	tuncfg.encap_err_rcv = rxrpc_encap_err_rcv;
	tuncfg.sk_user_data = local;
	setup_udp_tunnel_sock(net, local->socket, &tuncfg);

	/* set the socket up */
	usk = local->socket->sk;
	usk->sk_error_report = rxrpc_error_report;

	switch (srx->transport.family) {
	case AF_INET6:
		/* we want to receive ICMPv6 errors */
		ip6_sock_set_recverr(usk);

		/* Fall through and set IPv4 options too otherwise we don't get
		 * errors from IPv4 packets sent through the IPv6 socket.
		 */
		fallthrough;
	case AF_INET:
		/* we want to receive ICMP errors */
		ip_sock_set_recverr(usk);

		/* we want to set the don't fragment bit */
		rxrpc_local_dont_fragment(local, true);

		/* We want receive timestamps. */
		sock_enable_timestamps(usk);
		break;

	default:
		BUG();
	}

	io_thread = kthread_run(rxrpc_io_thread, local,
				"krxrpcio/%u", ntohs(udp_conf.local_udp_port));
	if (IS_ERR(io_thread)) {
		ret = PTR_ERR(io_thread);
		goto error_sock;
	}

	wait_for_completion(&local->io_thread_ready);
	local->io_thread = io_thread;
	_leave(" = 0");
	return 0;

error_sock:
	kernel_sock_shutdown(local->socket, SHUT_RDWR);
	local->socket->sk->sk_user_data = NULL;
	sock_release(local->socket);
	local->socket = NULL;
	return ret;
}

/*
 * Look up or create a new local endpoint using the specified local address.
 */
struct rxrpc_local *rxrpc_lookup_local(struct net *net,
				       const struct sockaddr_rxrpc *srx)
{
	struct rxrpc_local *local;
	struct rxrpc_net *rxnet = rxrpc_net(net);
	struct hlist_node *cursor;
	long diff;
	int ret;

	_enter("{%d,%d,%pISp}",
	       srx->transport_type, srx->transport.family, &srx->transport);

	mutex_lock(&rxnet->local_mutex);

	hlist_for_each(cursor, &rxnet->local_endpoints) {
		local = hlist_entry(cursor, struct rxrpc_local, link);

		diff = rxrpc_local_cmp_key(local, srx);
		if (diff != 0)
			continue;

		/* Services aren't allowed to share transport sockets, so
		 * reject that here.  It is possible that the object is dying -
		 * but it may also still have the local transport address that
		 * we want bound.
		 */
		if (srx->srx_service) {
			local = NULL;
			goto addr_in_use;
		}

		/* Found a match.  We want to replace a dying object.
		 * Attempting to bind the transport socket may still fail if
		 * we're attempting to use a local address that the dying
		 * object is still using.
		 */
<<<<<<< HEAD
		if (!rxrpc_use_local(local, rxrpc_local_use_lookup))
=======
		if (!rxrpc_use_local(local))
>>>>>>> master
			break;

		goto found;
	}

	local = rxrpc_alloc_local(net, srx);
	if (!local)
		goto nomem;

	ret = rxrpc_open_socket(local, net);
	if (ret < 0)
		goto sock_error;

<<<<<<< HEAD
	if (cursor) {
		hlist_replace_rcu(cursor, &local->link);
		cursor->pprev = NULL;
	} else {
		hlist_add_head_rcu(&local->link, &rxnet->local_endpoints);
	}
=======
	if (cursor != &rxnet->local_endpoints)
		list_replace_init(cursor, &local->link);
	else
		list_add_tail(&local->link, cursor);
	age = "new";
>>>>>>> master

found:
	mutex_unlock(&rxnet->local_mutex);
	_leave(" = %p", local);
	return local;

nomem:
	ret = -ENOMEM;
sock_error:
	mutex_unlock(&rxnet->local_mutex);
	if (local)
		call_rcu(&local->rcu, rxrpc_local_rcu);
	_leave(" = %d", ret);
	return ERR_PTR(ret);

addr_in_use:
	mutex_unlock(&rxnet->local_mutex);
	_leave(" = -EADDRINUSE");
	return ERR_PTR(-EADDRINUSE);
}

/*
 * Get a ref on a local endpoint.
 */
struct rxrpc_local *rxrpc_get_local(struct rxrpc_local *local,
				    enum rxrpc_local_trace why)
{
	int r, u;

<<<<<<< HEAD
	u = atomic_read(&local->active_users);
	__refcount_inc(&local->ref, &r);
	trace_rxrpc_local(local->debug_id, why, r + 1, u);
=======
	n = atomic_inc_return(&local->usage);
	trace_rxrpc_local(local->debug_id, rxrpc_local_got, n, here);
>>>>>>> master
	return local;
}

/*
 * Get a ref on a local endpoint unless its usage has already reached 0.
 */
struct rxrpc_local *rxrpc_get_local_maybe(struct rxrpc_local *local,
					  enum rxrpc_local_trace why)
{
	int r, u;

<<<<<<< HEAD
	if (local && __refcount_inc_not_zero(&local->ref, &r)) {
		u = atomic_read(&local->active_users);
		trace_rxrpc_local(local->debug_id, why, r + 1, u);
		return local;
=======
	if (local) {
		int n = atomic_fetch_add_unless(&local->usage, 1, 0);
		if (n > 0)
			trace_rxrpc_local(local->debug_id, rxrpc_local_got,
					  n + 1, here);
		else
			local = NULL;
>>>>>>> master
	}

<<<<<<< HEAD
	return NULL;
=======
/*
 * Queue a local endpoint and pass the caller's reference to the work item.
 */
void rxrpc_queue_local(struct rxrpc_local *local)
{
	const void *here = __builtin_return_address(0);
	unsigned int debug_id = local->debug_id;
	int n = atomic_read(&local->usage);

	if (rxrpc_queue_work(&local->processor))
		trace_rxrpc_local(debug_id, rxrpc_local_queued, n, here);
	else
		rxrpc_put_local(local);
>>>>>>> master
}

/*
 * Drop a ref on a local endpoint.
 */
void rxrpc_put_local(struct rxrpc_local *local, enum rxrpc_local_trace why)
{
	unsigned int debug_id;
	bool dead;
	int r, u;

	if (local) {
<<<<<<< HEAD
		debug_id = local->debug_id;

		u = atomic_read(&local->active_users);
		dead = __refcount_dec_and_test(&local->ref, &r);
		trace_rxrpc_local(debug_id, why, r, u);

		if (dead)
=======
		n = atomic_dec_return(&local->usage);
		trace_rxrpc_local(local->debug_id, rxrpc_local_put, n, here);

		if (n == 0)
>>>>>>> master
			call_rcu(&local->rcu, rxrpc_local_rcu);
	}
}

/*
 * Start using a local endpoint.
 */
<<<<<<< HEAD
struct rxrpc_local *rxrpc_use_local(struct rxrpc_local *local,
				    enum rxrpc_local_trace why)
{
	local = rxrpc_get_local_maybe(local, rxrpc_local_get_for_use);
	if (!local)
		return NULL;

	if (!__rxrpc_use_local(local, why)) {
		rxrpc_put_local(local, rxrpc_local_put_for_use);
=======
struct rxrpc_local *rxrpc_use_local(struct rxrpc_local *local)
{
	unsigned int au;

	local = rxrpc_get_local_maybe(local);
	if (!local)
		return NULL;

	au = atomic_fetch_add_unless(&local->active_users, 1, 0);
	if (au == 0) {
		rxrpc_put_local(local);
>>>>>>> master
		return NULL;
	}

	return local;
}

/*
 * Cease using a local endpoint.  Once the number of active users reaches 0, we
<<<<<<< HEAD
 * start the closure of the transport in the I/O thread..
 */
void rxrpc_unuse_local(struct rxrpc_local *local, enum rxrpc_local_trace why)
{
	unsigned int debug_id;
	int r, u;

	if (local) {
		debug_id = local->debug_id;
		r = refcount_read(&local->ref);
		u = atomic_dec_return(&local->active_users);
		trace_rxrpc_local(debug_id, why, r, u);
		if (u == 0)
			kthread_stop(local->io_thread);
=======
 * start the closure of the transport in the work processor.
 */
void rxrpc_unuse_local(struct rxrpc_local *local)
{
	unsigned int au;

	if (local) {
		au = atomic_dec_return(&local->active_users);
		if (au == 0)
			rxrpc_queue_local(local);
		else
			rxrpc_put_local(local);
>>>>>>> master
	}
}

/*
 * Destroy a local endpoint's socket and then hand the record to RCU to dispose
 * of.
 *
 * Closing the socket cannot be done from bottom half context or RCU callback
 * context because it might sleep.
 */
void rxrpc_destroy_local(struct rxrpc_local *local)
{
	struct socket *socket = local->socket;
	struct rxrpc_net *rxnet = local->rxnet;

	_enter("%d", local->debug_id);

<<<<<<< HEAD
	local->dead = true;

=======
>>>>>>> master
	mutex_lock(&rxnet->local_mutex);
	hlist_del_init_rcu(&local->link);
	mutex_unlock(&rxnet->local_mutex);

	rxrpc_clean_up_local_conns(local);
	rxrpc_service_connection_reaper(&rxnet->service_conn_reaper);
	ASSERT(!local->service);

	if (socket) {
		local->socket = NULL;
		kernel_sock_shutdown(socket, SHUT_RDWR);
		socket->sk->sk_user_data = NULL;
		sock_release(socket);
	}

	/* At this point, there should be no more packets coming in to the
	 * local endpoint.
	 */
<<<<<<< HEAD
#ifdef CONFIG_AF_RXRPC_INJECT_RX_DELAY
	rxrpc_purge_queue(&local->rx_delay_queue);
#endif
	rxrpc_purge_queue(&local->rx_queue);
	rxrpc_purge_client_connections(local);
=======
	rxrpc_purge_queue(&local->reject_queue);
	rxrpc_purge_queue(&local->event_queue);
}

/*
 * Process events on an endpoint.  The work item carries a ref which
 * we must release.
 */
static void rxrpc_local_processor(struct work_struct *work)
{
	struct rxrpc_local *local =
		container_of(work, struct rxrpc_local, processor);
	bool again;

	trace_rxrpc_local(local->debug_id, rxrpc_local_processing,
			  atomic_read(&local->usage), NULL);

	do {
		again = false;
		if (atomic_read(&local->active_users) == 0) {
			rxrpc_local_destroyer(local);
			break;
		}

		if (!skb_queue_empty(&local->reject_queue)) {
			rxrpc_reject_packets(local);
			again = true;
		}

		if (!skb_queue_empty(&local->event_queue)) {
			rxrpc_process_local_events(local);
			again = true;
		}
	} while (again);

	rxrpc_put_local(local);
>>>>>>> master
}

/*
 * Destroy a local endpoint after the RCU grace period expires.
 */
static void rxrpc_local_rcu(struct rcu_head *rcu)
{
	struct rxrpc_local *local = container_of(rcu, struct rxrpc_local, rcu);

	rxrpc_see_local(local, rxrpc_local_free);
	kfree(local);
}

/*
 * Verify the local endpoint list is empty by this point.
 */
void rxrpc_destroy_all_locals(struct rxrpc_net *rxnet)
{
	struct rxrpc_local *local;

	_enter("");

	flush_workqueue(rxrpc_workqueue);

	if (!hlist_empty(&rxnet->local_endpoints)) {
		mutex_lock(&rxnet->local_mutex);
		hlist_for_each_entry(local, &rxnet->local_endpoints, link) {
			pr_err("AF_RXRPC: Leaked local %p {%d}\n",
			       local, refcount_read(&local->ref));
		}
		mutex_unlock(&rxnet->local_mutex);
		BUG();
	}
}
