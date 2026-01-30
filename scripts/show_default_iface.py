from scapy.all import conf, get_if_list
ifaces = get_if_list()
defname = getattr(conf.iface, 'name', str(conf.iface))
print('scapy_default_iface:', defname)
print('first_listed_iface:', ifaces[0] if ifaces else 'none')
print('iface_count:', len(ifaces))