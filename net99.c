/*
 * Driver for qemu net99 device.
 *
 * Junbo Jiang
 */

#include <sys/param.h>		/* defines used in kernel.h */
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kernel.h>		/* types used in module initialization */
#include <sys/malloc.h>
#include <sys/bus.h>		/* structs, prototypes for pci bus stuff and DEVMETHOD macros! */
#include <sys/socket.h>                                                                                                                                                  

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>
#include <vm/vm.h>
#include <vm/pmap.h>
#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/bpf.h>                                                                                                                                                     

#define NET99_BUF_SIZE 389632

struct net99_softc {
	device_t dev;
    struct ifnet *ifp;
    struct resource *irq;
    void *intrhand;
    int res_id;
    struct mtx mtx;
    struct resource *res;
    char *rx_buf;
    char *tx_buf;
    uint8_t rx_cur;
    uint8_t rx_idx;
    uint8_t tx_cur;
    uint8_t tx_idx;

    struct ifmedia media;
};

enum net99_io_addr {
    INTR_STATUS = 0,
    RX_ADDR     = 4,
    RX_IDX      = 8,
    RX_CUR      = 12,
    RX_RST      = 16,
    TX_ADDR     = 20,
    TX_IDX      = 24,
    TX_CUR      = 28,
    TX_RST      = 32,
};

static uint8_t mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x99};

static void
net99_intr(void *arg)
{                                                                                                                                                                        
    struct net99_softc *sc = arg;
    struct ifnet *ifp = sc->ifp;
    struct mbuf *m;
    char *p;
    uint64_t size;

    bus_read_4(sc->res, INTR_STATUS);

    while(1){
        size = *(uint64_t *)(sc->rx_buf + (1514 + 8) * sc->rx_cur);

        if(size == 0)
            break;

        p = sc->rx_buf + (1514 + 8) * sc->rx_cur + 8;

        m = m_devget(p, size, 0, ifp, NULL);
        if(m){
            (*ifp->if_input)(ifp, m);
        }

        *(uint64_t *)(sc->rx_buf + (1514 + 8) * sc->rx_cur) = 0;

        sc->rx_cur++;
    }
}

static int
net99_probe(device_t dev)
{
	if(pci_get_vendor(dev) == 0x1234 && pci_get_device(dev) == 0x0099){
		device_set_desc(dev, "NET99 Network Adapter");
		return (BUS_PROBE_DEFAULT);
	}

	return (ENXIO);
}

static void net99_start(struct ifnet *ifp)
{
    struct net99_softc *sc = ifp->if_softc;
    struct mbuf *m;
    uint64_t size;
    uint8_t idx;

    idx = sc->tx_idx;
    while(1){
        struct mbuf *mf;

        IFQ_DRV_DEQUEUE(&ifp->if_snd, mf);

        m = mf;

        if(!m)
            break;

        size = m->m_pkthdr.len;

        if(size <= 1514){
            char *p;

            idx++;

            p =  (char *)(sc->tx_buf + idx * (1514 + 8) + 8);

            while(m){
                memcpy(p, m->m_data, m->m_len);
                p += m->m_len;
                m = m->m_next;
            }

            *(uint64_t*)(sc->tx_buf + idx * (1514 + 8)) = size;

            BPF_MTAP(ifp, m);

            bus_write_4(sc->res, TX_IDX, idx);
        }

        m_freem(mf);
    }

    sc->tx_idx = idx;
}

static int
net99_attach(device_t dev)
{
	struct net99_softc *sc;
    struct ifnet *ifp;
    int error = 1;
    int rid = 0;

	sc = device_get_softc(dev);

    bzero(sc, sizeof(*sc));

	sc->dev = dev;

    pci_enable_busmaster(dev);

    sc->res_id = PCIR_BAR(0);

    sc->res = bus_alloc_resource_any(dev, SYS_RES_IOPORT, &sc->res_id, RF_ACTIVE);

    if(!sc->res){
        return error;
    }

    sc->rx_buf = contigmalloc(NET99_BUF_SIZE, M_DEVBUF, M_NOWAIT | M_ZERO, 0, ~0ULL, PAGE_SIZE, 0);
    if(!sc->rx_buf){
        return error;
    }
    sc->tx_buf = contigmalloc(NET99_BUF_SIZE, M_DEVBUF, M_NOWAIT | M_ZERO, 0, ~0ULL, PAGE_SIZE, 0);
    if(!sc->tx_buf){
        contigfree(sc->rx_buf, NET99_BUF_SIZE, M_DEVBUF);
        return error;
    }

    bus_write_4(sc->res, RX_ADDR, vtophys(sc->rx_buf));
    bus_write_4(sc->res, RX_RST, 0);

    bus_write_4(sc->res, TX_ADDR, vtophys(sc->tx_buf));

    sc->rx_idx = -1;
    sc->irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid, RF_SHAREABLE | RF_ACTIVE);

    if(!sc->irq){
        goto free_buf;
    }

    if((error = bus_setup_intr(dev, sc->irq, INTR_TYPE_NET, NULL, net99_intr, sc, &sc->intrhand))){
        goto free_buf;
    }

    ifp = if_alloc(IFT_ETHER);
    if(!ifp)
        goto free_buf;

    sc->ifp = ifp;

    ifp->if_softc = sc;
    if_initname(ifp, device_get_name(dev), device_get_unit(dev));                                                                                                        

    ifp->if_mtu = ETHERMTU;

    ifp->if_drv_flags |= IFF_DRV_RUNNING;
    ifp->if_flags = IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST;
    ifp->if_start = net99_start;

    IFQ_SET_MAXLEN(&ifp->if_snd, ifqmaxlen);
    IFQ_SET_READY(&ifp->if_snd);

    ether_ifattach(ifp, mac);

    return 0;

free_buf:
    contigfree(sc->rx_buf, NET99_BUF_SIZE, M_DEVBUF);
    contigfree(sc->tx_buf, NET99_BUF_SIZE, M_DEVBUF);

    return error;
}

static int
net99_detach(device_t dev)
{
	struct net99_softc *sc;
    struct ifnet *ifp;

	sc = device_get_softc(dev);

    if(sc->rx_buf)
        contigfree(sc->rx_buf, NET99_BUF_SIZE, M_DEVBUF);

    if(sc->tx_buf)
        contigfree(sc->tx_buf, NET99_BUF_SIZE, M_DEVBUF);

    if(sc->intrhand)
        bus_teardown_intr(dev, sc->irq, sc->intrhand);

    if(sc->irq)
        bus_release_resource(dev, SYS_RES_IRQ, 0, sc->irq);

    if(sc->res)
        bus_release_resource(dev, SYS_RES_IOPORT, sc->res_id, sc->res);    

    ifp = sc->ifp;

    if(ifp){
        ether_ifdetach(ifp);
        if_free(ifp);
    }

	return (0);
}

static int
net99_shutdown(device_t dev)
{
	return (0);
}

static int
net99_suspend(device_t dev)
{
	return (0);
}

static int
net99_resume(device_t dev)
{
	return 0;
}

static device_method_t net99_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		net99_probe),
	DEVMETHOD(device_attach,	net99_attach),
	DEVMETHOD(device_detach,	net99_detach),
	DEVMETHOD(device_shutdown,	net99_shutdown),
	DEVMETHOD(device_suspend,	net99_suspend),
	DEVMETHOD(device_resume,	net99_resume),

	DEVMETHOD_END
};

static devclass_t net99_devclass;

static driver_t net99_driver = {
    "net99", net99_methods, sizeof(struct net99_softc),
};

DRIVER_MODULE(net99, pci, net99_driver, net99_devclass, 0, 0);
