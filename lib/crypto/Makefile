include $(TOPDIR)/config.mk

LIB	:= $(obj)libcrypto.o

COBJS-y += crypto.o
COBJS-y += crypto_hash_sha512.o
COBJS-y += crypto_sign_25519.o

COBJS	:= $(COBJS-y)
SRCS	:= $(COBJS:.o=.c)
OBJS	:= $(addprefix $(obj),$(COBJS))

all:	$(LIB)

$(LIB): $(obj).depend $(OBJS)
	$(call cmd_link_o_target, $(OBJS))

#########################################################################

# defines $(obj).depend target
include $(SRCTREE)/rules.mk

sinclude $(obj).depend

#########################################################################