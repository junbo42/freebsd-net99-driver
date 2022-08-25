KMOD=	net99
SRCS=	net99.c
SRCS+=	device_if.h bus_if.h pci_if.h

.include <bsd.kmod.mk>
