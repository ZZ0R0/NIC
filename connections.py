import ifcfg
import nmap


class Display:
    def __init__(self):
        pass

    def detailList(self, liste):
        for pos, value in enumerate(liste):
            if type(value) == list:
                print(f"{pos} - {' <=> '.join(value)}")
            else:
                print(f"{pos} - {value}")
        return int(input("=> "))


class Analyzer:
    def __init__(self):
        pass

    def listNetworkInterfaces(self):
        return [[interface['device'], interface['inet'], '.'.join(interface['inet'].split(".")[:-1]) + ".0/24"] for
                name, interface in ifcfg.interfaces().items() if interface['inet4']]

    def listConnectedDevices(self, host_ip, network_ip):
        nm = nmap.PortScanner()
        nm.scan(hosts=network_ip, arguments='-sP')
        host_list = []
        for host in nm.all_hosts():
            if host != host_ip:
                try:
                    if nm[host]['vendor'] == {}:
                        host_list.append([host, nm[host]['addresses']['mac']])
                    else:
                        host_list.append(
                            [host, nm[host]['addresses']['mac'], nm[host]['vendor'][nm[host]['addresses']['mac']]])
                except:
                    host_list.append([host])
        return host_list


D = Display()
A = Analyzer()
interfaces = A.listNetworkInterfaces()
interface = interfaces[D.detailList(interfaces)]
print(f"\nSelected {' <=> '.join(interface)}\n")

previous_hosts = []
while True:
    new_hosts = A.listConnectedDevices(interface[1], interface[2])

    if new_hosts != previous_hosts:
        print("\n############\n")

    for host in previous_hosts:
        if host not in new_hosts:
            print(f"Disconnected  => {' <=> '.join(host)}")

    for host in new_hosts:
        if host not in previous_hosts:
            print(f"Connected  => {' <=> '.join(host)}")

    previous_hosts = new_hosts
