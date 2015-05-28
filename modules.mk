mod_inject_msdomain.la: mod_inject_msdomain.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_inject_msdomain.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_inject_msdomain.la
