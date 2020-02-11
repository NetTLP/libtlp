
subdirs = lib test apps

install = /usr/bin/install -m 644 -D
install_h = include/libtlp.h include/tlp.h
install_l = lib/libtlp.a

all:
	@(for d in $(subdirs); do $(MAKE) -C $$d; done)
clean:
	@(for d in $(subdirs); do $(MAKE) -C $$d clean; done)

install: all
	$(install) $(install_h) /usr/local/include/
	$(install) $(install_l) /usr/local/lib/

remake: clean all
