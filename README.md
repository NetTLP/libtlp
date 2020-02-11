
# LibTLP

LibTLP is a software implementation of the PCIe transaction layer.  It
provides a well-abstracted DMA API shown below for issuing DMAs from
software to hardware through a NetTLP adpater.

```c
ssize_t dma_read(struct nettlp *nt, uintptr_t addr, void *buf, size_t count);
ssize_t dma_write(struct nettlp *nt, uintptr_t addr, void *buf, size_t count);
```

Documents about NetTLP including LibTLP are in http://haeena.dev/nettlp