/*
 *   Copyright (c) 2013-2014 Fred Klassen <tcpreplay at appneta dot com> - AppNeta
 *   Copyright (c) 2014 Alexey Indeev <aindeev at appneta dot com> - AppNeta
 *
 *   The Tcpreplay Suite of tools is free software: you can redistribute it
 *   and/or modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, either version 3 of the
 *   License, or with the authors permission any later version.
 *
 *   The Tcpreplay Suite is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with the Tcpreplay Suite.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/quick_tx.h>

static inline int quick_tx_clear_skb_list(struct quick_tx_skb *list) {
	int num_freed = 0;
	struct quick_tx_skb *qtx_skb, *tmp;
	list_for_each_entry_safe(qtx_skb, tmp, &list->list, list) {
		num_freed++;
		list_del_init(&qtx_skb->list);
		kmem_cache_free(qtx_skbuff_head_cache, qtx_skb);
	}
	return num_freed;
}

static inline int quick_tx_free_skb(struct quick_tx_dev *dev, bool free_skb)
{
	struct quick_tx_skb *qtx_skb;
	int freed = 0;

	if (!list_empty(&dev->skb_wait_list.list)) {
		qtx_skb = list_entry(dev->skb_wait_list.list.next, struct quick_tx_skb, list);
		while (qtx_skb != &dev->skb_wait_list) {
			if (atomic_read(&qtx_skb->skb.users) == 1) {
				u16 *dma_block_index = (u16*)(qtx_skb->skb.cb + (sizeof(qtx_skb->skb.cb) - sizeof(u16)));
				atomic_dec(&dev->shared_data->dma_blocks[*dma_block_index].users);

				list_del_init(&qtx_skb->list);

				if (free_skb) {
					freed++;
					kmem_cache_free(qtx_skbuff_head_cache, qtx_skb);
				} else {
					list_add(&qtx_skb->list, &dev->skb_freed_list.list);
				}

				qtx_skb = list_entry(dev->skb_wait_list.list.next, struct quick_tx_skb, list);
			} else {
				break;
			}
		}
		if (free_skb) {
			freed += quick_tx_clear_skb_list(&dev->skb_freed_list);
		}

		dev->num_skb_freed += freed;
	}
	return freed;
}

static inline int quick_tx_send_skb(struct quick_tx_skb *qtx_skb, struct quick_tx_dev *dev, int budget, bool all)
{
	netdev_tx_t status = NETDEV_TX_BUSY;
	struct net_device* netdev = dev->netdev;
	const struct net_device_ops *ops = netdev->netdev_ops;
	unsigned long flags;
	struct netdev_queue *txq;
	int done = 0;

	if (!netif_device_present(netdev) || !netif_running(netdev)) {
		qtx_error("Device cannot currently transmit, it is not running.");
		qtx_error("Force stopping transmit..");
		return NETDEV_NOT_RUNNING;
	}

	txq = netdev_get_tx_queue(netdev, 0);

next_skb:
	if (done < budget || all)
		done++;

	/* if no skb provided try to get one from list */
	if (!qtx_skb && !list_empty(&dev->skb_queued_list.list)) {
		qtx_skb = list_entry(dev->skb_queued_list.list.next, struct quick_tx_skb, list);
	}

	/* No more actual items, just the head */
	if (!qtx_skb || qtx_skb == &dev->skb_queued_list) {
		static int qtx_s = 0;
		if (qtx_s % 100 == 0)
			quick_tx_free_skb(dev, false);
		qtx_s++;

		return NETDEV_TX_OK;
	}

	local_irq_save(flags);
	__netif_tx_lock(txq, smp_processor_id());

	if (!netif_xmit_frozen_or_stopped(txq)) {
		if (atomic_read(&qtx_skb->skb.users) != 2)
			atomic_set(&qtx_skb->skb.users, 2);
#if 1
		status = ops->ndo_start_xmit(&qtx_skb->skb, netdev);
#else
		status = NETDEV_TX_OK;
		atomic_dec(&qtx_skb->skb.users);
#endif

		__netif_tx_unlock(txq);
		local_irq_restore(flags);


		if (likely(status == NETDEV_TX_OK)) {
			dev->num_tx_ok_packets++;
			dev->num_tx_ok_bytes += qtx_skb->skb.len;

			list_del_init(&qtx_skb->list);
			list_add_tail(&qtx_skb->list, &dev->skb_wait_list.list);

			/* Set skb to NULL so we dont send it again */
			qtx_skb = NULL;

			goto next_skb;
		} else {
			if (status == NETDEV_TX_BUSY) {
				dev->num_tx_busy++;
			} else if (status == NETDEV_TX_LOCKED) {
				dev->num_tx_locked++;
			}
		}
	} else {
		__netif_tx_unlock(txq);
		local_irq_restore(flags);

		dev->num_tq_frozen_or_stopped++;
	}

	if (done < budget || all)
		goto next_skb;
	else if (&qtx_skb->list != &dev->skb_queued_list.list.next)
		list_add(&qtx_skb->list, &dev->skb_queued_list.list);

//	else if (skb_queue_len(&dev->skb_queued_list) > MAX_SKB_LIST_SIZE) {
//		quick_tx_free_skb(dev, false);
//		schedule_timeout_interruptible(1);
//		goto next_skb;
//	}

	return status;
}

static inline struct quick_tx_skb* quick_tx_alloc_skb_fill(struct quick_tx_dev * dev, unsigned int data_size, gfp_t gfp_mask,
			    int flags, int node, u8 *data, unsigned int full_size)
{
	struct skb_shared_info *shinfo;
	struct quick_tx_skb *qtx_skb;
	struct sk_buff *skb;

	if (!list_empty(&dev->skb_freed_list.list)) {
		qtx_skb = list_entry(dev->skb_freed_list.list.next, struct quick_tx_skb, list);
		list_del_init(&qtx_skb->list);
	} else {
		dev->num_skb_alloced++;
		qtx_skb = kmem_cache_alloc_node(qtx_skbuff_head_cache, gfp_mask & ~__GFP_DMA, node);
		INIT_LIST_HEAD(&qtx_skb->list);
	}

	if (!qtx_skb)
		return NULL;

	skb = &qtx_skb->skb;

	prefetchw(skb);
	prefetchw(data + full_size);

	memset(skb, 0, offsetof(struct sk_buff, tail));

	skb->truesize = SKB_TRUESIZE(SKB_DATA_ALIGN(data_size));
	atomic_set(&skb->users, 1);
	skb->head = data;
	skb->data = data;
	skb_reset_tail_pointer(skb);
	skb->end = skb->tail + data_size;
#ifdef NET_SKBUFF_DATA_USES_OFFSET
	skb->mac_header = ~0U;
	skb->transport_header = ~0U;
#endif

	skb_reserve(skb, NET_SKB_PAD);
	skb_put(skb, data_size - NET_SKB_PAD);

	/* make sure we initialize shinfo sequentially */
	shinfo = skb_shinfo(skb);
	memset(shinfo, 0, offsetof(struct skb_shared_info, dataref));
	atomic_set(&shinfo->dataref, 1);
	kmemcheck_annotate_variable(shinfo->destructor_arg);

out:
	return qtx_skb;
}

void quick_tx_worker(struct work_struct *work)
{
	struct quick_tx_dev *dev = container_of(work, struct quick_tx_dev, tx_work);
	struct quick_tx_skb *qtx_skb;
	struct sk_buff *skb;
	struct quick_tx_shared_data *data = dev->shared_data;
	struct quick_tx_packet_entry* entry = data->lookup_table + data->lookup_consumer_index;
	struct quick_tx_dma_block_entry* dma_block;
	u32 full_size = 0;
	int ret;

	qtx_error("Starting quick_tx_worker");

	dev->shared_data->lookup_flag = 0;
	wait_event(dev->consumer_q, dev->shared_data->lookup_flag == 1);
	dev->time_start_tx = ktime_get_real();

	while (true) {

		rmb();
		if (entry->length > 0 && entry->consumed == 0) {
			/* Calculate full size of the space required to packet */
			full_size = SKB_DATA_ALIGN(SKB_DATA_ALIGN(NET_SKB_PAD + entry->length) + sizeof(struct skb_shared_info));

			/* Get the DMA block our packet is in */
			dma_block = &data->dma_blocks[entry->dma_block_index];
			atomic_inc(&dma_block->users);

			/* Write memory barrier so that users++ gets executed beforehand */
			wmb();

			/* Fill up skb with data at the DMA block address + offset */
			qtx_skb = quick_tx_alloc_skb_fill(dev, NET_SKB_PAD + entry->length, GFP_NOWAIT,
					0, NUMA_NO_NODE, dma_block->kernel_addr + entry->block_offset, full_size);
			if (unlikely(!qtx_skb)) {
				atomic_dec(&dma_block->users);
				qtx_error("ALLOC_ERROR: Decrement on %d. Users at = %d",
						entry->dma_block_index, atomic_read(&dma_block->users));
				continue;
			}

			skb = &qtx_skb->skb;

			/* Copy over the bits of the DMA block index */
			*(u16*)(skb->cb + (sizeof(skb->cb) - sizeof(u16))) = entry->dma_block_index;

			/* Set queue mapping */
			skb->dev = dev->netdev;

			ret = quick_tx_send_skb(qtx_skb, dev, 128, false);

			/* The device is not running we will stop, rollback any changes */
			if (unlikely(ret == NETDEV_NOT_RUNNING)) {
				data->error_flags |= QUICK_TX_ERR_NOT_RUNNING;
				kmem_cache_free(qtx_skbuff_head_cache, qtx_skb);
				atomic_dec(&dma_block->users);
				dev->num_skb_freed--;
				return;
			}

#ifdef QUICK_TX_DEBUG
			qtx_error("Consumed entry at index = %d, dma_block_index = %d, offset = %d, len = %d",
					data->lookup_consumer_index, entry->dma_block_index, entry->block_offset, entry->length);
#endif

			/* Set this entry as consumed, increment to next entry */
			entry->consumed = 1;
			wmb();

			data->lookup_consumer_index = (data->lookup_consumer_index + 1) % LOOKUP_TABLE_SIZE;
			entry = data->lookup_table + data->lookup_consumer_index;
		} else {
			if (dev->quit_work) {

				/* flush all remaining SKB's in the list before exiting */
				quick_tx_send_skb(NULL, dev, 0, true);
				dev->time_end_tx = ktime_get_real();

				qtx_error("All packets have been transmitted successfully, exiting.");

				/* wait until cleaning the SKB list is finished
				 * as well before exiting so we do not have any memory leaks */
				while(!list_empty(&dev->skb_wait_list.list)) {
					quick_tx_free_skb(dev, true);
					schedule_timeout_interruptible(HZ);
				}

				qtx_error("Done freeing free_skb_list");

				quick_tx_calc_mbps(dev);
				quick_tx_print_stats(dev);

				break;
			}
#ifdef QUICK_TX_DEBUG
			qtx_error("No packets to process, sleeping (index = %d), entry->consumed = %d", data->lookup_consumer_index,
					entry->consumed);
#endif

			dev->numsleeps++;
			dev->shared_data->lookup_flag = 0;
			wmb();

			/* Free some DMA blocks before going to sleep */
			quick_tx_free_skb(dev, false);

			wait_event(dev->consumer_q, dev->shared_data->lookup_flag == 1);
		}
	}

	return;
}
