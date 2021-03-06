/*
 * drivers/video/tegra/host/dev.h
 *
 * Tegra Graphics Host Driver Entrypoint
 *
 * Copyright (c) 2010-2012, NVIDIA Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __NVHOST_DEV_H
#define __NVHOST_DEV_H

#include "nvhost_acm.h"
#include "nvhost_syncpt.h"
#include "nvhost_intr.h"
#include "nvhost_channel.h"

#define TRACE_MAX_LENGTH	128U
#define IFACE_NAME		"nvhost"

struct nvhost_hwctx;
struct mem_mgr;

struct nvhost_master {
	void __iomem *aperture;
	void __iomem *sync_aperture;
	struct resource *reg_mem;
	struct class *nvhost_class;
	struct cdev cdev;
	struct device *ctrl;
	struct nvhost_syncpt syncpt;
	struct mem_mgr *memmgr;
	struct nvhost_intr intr;
	struct nvhost_device *dev;
	atomic_t clientid;
};

extern struct nvhost_master *nvhost;

void nvhost_debug_init(struct nvhost_master *master);
void nvhost_debug_dump(struct nvhost_master *master);

struct nvhost_device *nvhost_get_device(char *name);
struct nvhost_channel *nvhost_alloc_channel(int index);
void nvhost_free_channel(struct nvhost_channel *ch);

extern pid_t nvhost_debug_null_kickoff_pid;

#endif
