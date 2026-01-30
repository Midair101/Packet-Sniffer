from scapy.all import get_if_list
from scapy.interfaces import resolve_iface

l = get_if_list()
print('Total interfaces:', len(l))
for i, itf in enumerate(l, 1):
    try:
        resolve_iface(itf, retry=False)
        ok = True
    except Exception as e:
        ok = False
    print(i, ok, itf)