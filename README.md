# mod_inject_msdomain
=====================

APACHE 2.x module to inject MS-Domain into Authorization Header
This is useful in reverse proxy scenarios (MSExchange)



Apache Load: (inject_msdomain.load):
	LoadModule inject_msdomain_module /usr/lib/apache2/modules/mod_inject_msdomain.so

Apache Directives:
	InjectMSDomain DOMAIN



Authorization: Basic user:pass

	gets converted to

Authorization: Basic DOMAIN\user:pass


and sent back to upstream server.

