
#define module_platform_driver(__platform_driver) \
	module_driver(__platform_driver, platform_driver_register, \
			platform_driver_unregister)
            
#define module_driver(__driver, __register, __unregister, ...) \
static int __init __driver##_init(void) \
{ \
	return __register(&(__driver) , ##__VA_ARGS__); \
} \
module_init(__driver##_init); \
static void __exit __driver##_exit(void) \
{ \
	__unregister(&(__driver) , ##__VA_ARGS__); \
} \
module_exit(__driver##_exit);

#define module_init(x)	__initcall(x);

#define __initcall(fn) device_initcall(fn)

#define device_initcall(fn)		__define_initcall(fn, 6)

#define platform_driver_register(drv) \
	__platform_driver_register(drv, THIS_MODULE)


int __platform_driver_register(struct platform_driver *drv,
				struct module *owner)
{
	drv->driver.owner = owner;
	drv->driver.bus = &platform_bus_type;
	drv->driver.probe = platform_drv_probe;
	drv->driver.remove = platform_drv_remove;
	drv->driver.shutdown = platform_drv_shutdown;

	return driver_register(&drv->driver);
}

__init rkisp1_plat_drv_init(void)
{
    return platform_driver_register(&rkisp1_plat_drv,args);
}

device_initcall(rkisp1_plat_drv_init);

__define_initcall(rkisp1_plat_drv_init,6)

#define __define_initcall(fn, id) \
	static initcall_t __initcall_##fn##id __used \
	__attribute__((__section__(".initcall" #id ".init"))) = fn; \
	LTO_REFERENCE_INITCALL(__initcall_##fn##id)



    static initcall_t __initcall_rkisp1_plat_drv_init6 __used   __attribute__((__section__(".initcall6.init"))) = rkisp1_plat_drv_init;







vb2_mem_ops vb2_dma_contig_memops

mem_ops.mmap ->vb2_dc_mmap->dma_mmap_attrs->(ops->mmap)->__iommu_mmap_attrs
->arch_get_dma_pgprot -> dma_get_attr



arch_setup_dma_ops(dev, 0, DMA_BIT_MASK(32), NULL, false);

void arch_setup_dma_ops(struct device *dev, u64 dma_base, u64 size,
                        struct iommu_ops *iommu, bool coherent)
{
        dev->archdata.dma_coherent = coherent;

        if (!common_iommu_setup_dma_ops(dev, dma_base, size, iommu))
                arch_set_dma_ops(dev, &swiotlb_dma_ops);
}


/* do not use this function in a driver */
static inline bool is_device_dma_coherent(struct device *dev)
{
        if (!dev)
                return false;
        return dev->archdata.dma_coherent;
}

vma->vm_page_prot = arch_get_dma_pgprot(attrs, vma->vm_page_prot,
					        is_device_dma_coherent(dev));


static inline pgprot_t arch_get_dma_pgprot(struct dma_attrs *attrs,
                                        pgprot_t prot, bool coherent)
{
        if (!coherent || dma_get_attr(DMA_ATTR_WRITE_COMBINE, attrs))
                return pgprot_writecombine(prot);
        return prot;
}


static inline int dma_get_attr(enum dma_attr attr, struct dma_attrs *attrs)
{
	if (attrs == NULL)
		return 0;
	BUG_ON(attr >= DMA_ATTR_MAX);
	return test_bit(attr, attrs->flags);
}

#define pgprot_writecombine(prot) \
	__pgprot_modify(prot, PTE_ATTRINDX_MASK, PTE_ATTRINDX(MT_NORMAL_NC) | PTE_PXN | PTE_UXN)














CAMERA QUERY  ALLOC


static void *vb2_dc_alloc(void *alloc_ctx, unsigned long size,
			  enum dma_data_direction dma_dir, gfp_t gfp_flags)
{
	struct vb2_dc_conf *conf = alloc_ctx;
	struct device *dev = conf->dev;
	struct vb2_dc_buf *buf;

	buf = kzalloc(sizeof *buf, GFP_KERNEL);
	if (!buf)
		return ERR_PTR(-ENOMEM);

	buf->attrs = conf->attrs;
	buf->cookie = dma_alloc_attrs(dev, size, &buf->dma_addr,
					GFP_KERNEL | gfp_flags, &buf->attrs);
	if (!buf->cookie) {
		dev_err(dev, "dma_alloc_coherent of size %ld failed\n", size);
		kfree(buf);
		return ERR_PTR(-ENOMEM);
	}

	if (!dma_get_attr(DMA_ATTR_NO_KERNEL_MAPPING, &buf->attrs))
		buf->vaddr = buf->cookie;

	/* Prevent the device from being released while the buffer is used */
	buf->dev = get_device(dev);
	buf->size = size;
	buf->dma_dir = dma_dir;

	buf->handler.refcount = &buf->refcount;
	buf->handler.put = vb2_dc_put;
	buf->handler.arg = buf;

	atomic_inc(&buf->refcount);

	return buf;
}


static inline void *dma_alloc_attrs(struct device *dev, size_t size,
				       dma_addr_t *dma_handle, gfp_t flag,
				       struct dma_attrs *attrs)
{
	struct dma_map_ops *ops = get_dma_ops(dev);
	void *cpu_addr;

	BUG_ON(!ops);

	if (dma_alloc_from_coherent(dev, size, dma_handle, &cpu_addr))
		return cpu_addr;

	if (!arch_dma_alloc_attrs(&dev, &flag))
		return NULL;
	if (!ops->alloc)
		return NULL;

	cpu_addr = ops->alloc(dev, size, dma_handle, flag, attrs);
	debug_dma_alloc_coherent(dev, size, *dma_handle, cpu_addr);
	return cpu_addr;
}


int dma_alloc_from_coherent(struct device *dev, ssize_t size,
				       dma_addr_t *dma_handle, void **ret)
{
	struct dma_coherent_mem *mem;
	int order = get_order(size);
	unsigned long flags;
	int pageno;

	if (!dev)
		return 0;
	mem = dev->dma_mem;
	if (!mem)
		return 0;

	*ret = NULL;
	spin_lock_irqsave(&mem->spinlock, flags);

	if (unlikely(size > (mem->size << PAGE_SHIFT)))
		goto err;

	pageno = bitmap_find_free_region(mem->bitmap, mem->size, order);
	if (unlikely(pageno < 0))
		goto err;

	/*
	 * Memory was found in the per-device area.
	 */
	*dma_handle = mem->device_base + (pageno << PAGE_SHIFT);
	*ret = mem->virt_base + (pageno << PAGE_SHIFT);
	memset(*ret, 0, size);
	spin_unlock_irqrestore(&mem->spinlock, flags);

	return 1;

err:
	spin_unlock_irqrestore(&mem->spinlock, flags);
	/*
	 * In the case where the allocation can not be satisfied from the
	 * per-device area, try to fall back to generic memory if the
	 * constraints allow it.
	 */
	return mem->flags & DMA_MEMORY_EXCLUSIVE;
}




#define MT_DEVICE_nGnRnE	0
#define MT_DEVICE_nGnRE		1
#define MT_DEVICE_GRE		2
#define MT_NORMAL_NC		3
#define MT_NORMAL		4
#define MT_NORMAL_WT		5