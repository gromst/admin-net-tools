#!/usr/bin/env python3

import pickle
import signal
import multiprocessing as mp
from time import sleep
from datetime import datetime
from scapy.all import *

try:
    with open('sniffer.data', 'rb') as f:
        data_new = pickle.load(f)
except Exception as err:
    pass

iface      = "enp1s0"
filtr      = None
period     = 1
sniffProc  = None
sniffQueue = mp.SimpleQueue()
sigExit    = False


def ctrlc(signum, frame):
    global sigExit
    sigExit = True


def dosniff(iface=None, filtr=None, sniffQueue=None, period=1):
    try:
        t = AsyncSniffer(iface=iface, filter=filtr)
        t.start()
        lastdate = datetime.now()
        while not sigExit:
            sleep(period)
            t.stop()
            delta = datetime.now()-lastdate
            sniffQueue.put({"delta": delta.total_seconds(), "packets": t.results})
            t.start()
            lastdate = datetime.now()
        t.stop()
    except KeyboardInterrupt:
        print("ERR: dosniff: KeyboardInterrupt")
    except Exception as err:
        pass

    while not sniffQueue.empty():
        sleep(1)
    return


signal.signal(signal.SIGINT, ctrlc)
signal.signal(signal.SIGTERM, ctrlc)
#mp.set_start_method("fork")


packets = []

traff  = {}
revref = {}

duration = 0.

try:
#if True:
    while not sigExit:
        sleep(0.5)
        if sniffProc is None or not sniffProc.is_alive():
            if not sigExit:
                try:
                    sniffQueue = mp.SimpleQueue()
                    sniffProc  = mp.Process(target=dosniff, args=(iface, filtr, sniffQueue, period), group=None, name=None, daemon=False)
                    sniffProc.start()
                    print(f"Start Sniffer...")
                except Exception as err:
                    print(f"Error Start Process for sniff: {err}")

        if sniffProc.is_alive():
            if not sniffQueue.empty():
                captured = sniffQueue.get()
                duration += captured["delta"]
                print("Get {} packets for {} sec".format(len(captured["packets"]), captured["delta"]))
                for packet in captured["packets"]:
                    packetdata = {}
                    keyFwd = ""
                    keyRev = ""
                    keyLen = 0
                    if isinstance(packet, scapy.layers.l2.Ether):
                        packetdata = {"name": packet.name, "type": packet.type, "hwsrc": packet.src, "hwdst": packet.dst, "len": len(packet)}

                        keyFwd += " "+" ".join([str(packet.type), packet.src, packet.dst])
                        keyRev += " "+" ".join([str(packet.type), packet.dst, packet.src])
                        keyLen = len(packet)

                        EtherPayload = packet.payload

                        if   isinstance(EtherPayload, scapy.layers.inet6.IPv6):
                            packetdata["type"] = EtherPayload.name
                            packetdata[EtherPayload.name] = {"ipsrc": EtherPayload.src, "ipdst": EtherPayload.dst, "iplen": EtherPayload.plen, "proto": EtherPayload.nh}

                            keyFwd += " "+" ".join([str(EtherPayload.nh), EtherPayload.src, EtherPayload.dst])
                            keyRev += " "+" ".join([str(EtherPayload.nh), EtherPayload.dst, EtherPayload.src])

                            IpPayload = EtherPayload.payload

                            if   isinstance(IpPayload, scapy.layers.inet.UDP):
                                packetdata[EtherPayload.name]["proto"] = IpPayload.name
                                packetdata[IpPayload.name] = {"sport": IpPayload.sport, "dport": IpPayload.dport}

                                keyFwd += " "+" ".join([str(IpPayload.sport), str(IpPayload.dport)])
                                keyRev += " "+" ".join([str(IpPayload.dport), str(IpPayload.sport)])

                            elif isinstance(IpPayload, scapy.layers.inet.TCP):
                                packetdata[EtherPayload.name]["proto"] = IpPayload.name
                                packetdata[IpPayload.name] = {"sport": IpPayload.sport, "dport": IpPayload.dport}

                                keyFwd += " "+" ".join([str(IpPayload.sport), str(IpPayload.dport)])
                                keyRev += " "+" ".join([str(IpPayload.dport), str(IpPayload.sport)])

                            elif isinstance(IpPayload, scapy.layers.inet6.ICMPv6ND_RS):
                                packetdata[EtherPayload.name]["proto"] = IpPayload.name

                            else:
                                print("ERR: Unknown IP proto: {}: {}".format(type(IpPayload), IpPayload))

                        elif isinstance(EtherPayload, scapy.layers.inet.IP):
                            packetdata["type"] = EtherPayload.name
                            packetdata[EtherPayload.name] = {"ipsrc": EtherPayload.src, "ipdst": EtherPayload.dst, "iplen": EtherPayload.len, "proto": EtherPayload.proto}

                            keyFwd += " "+" ".join([str(EtherPayload.proto), EtherPayload.src, EtherPayload.dst])
                            keyRev += " "+" ".join([str(EtherPayload.proto), EtherPayload.dst, EtherPayload.src])

                            IpPayload = EtherPayload.payload

                            if   isinstance(IpPayload, scapy.layers.inet.UDP):
                                packetdata[EtherPayload.name]["proto"] = IpPayload.name
                                packetdata[IpPayload.name] = {"sport": IpPayload.sport, "dport": IpPayload.dport}

                                keyFwd += " "+" ".join([str(IpPayload.sport), str(IpPayload.dport)])
                                keyRev += " "+" ".join([str(IpPayload.dport), str(IpPayload.sport)])

                            elif isinstance(IpPayload, scapy.layers.inet.TCP):
                                packetdata[EtherPayload.name]["proto"] = IpPayload.name
                                packetdata[IpPayload.name] = {"sport": IpPayload.sport, "dport": IpPayload.dport}

                                keyFwd += " "+" ".join([str(IpPayload.sport), str(IpPayload.dport)])
                                keyRev += " "+" ".join([str(IpPayload.dport), str(IpPayload.sport)])

                            elif isinstance(IpPayload, scapy.layers.inet.ICMP):
                                packetdata[EtherPayload.name]["proto"] = IpPayload.name

                            else:
                                print("ERR: Unknown IP proto: {}: {}".format(type(IpPayload), IpPayload))

                        elif isinstance(EtherPayload, scapy.layers.l2.ARP):
                            packetdata["type"] = EtherPayload.name
                            packetdata[EtherPayload.name] = {"ipsrc": EtherPayload.psrc, "ipdst": EtherPayload.pdst}

                            keyFwd += " "+" ".join([EtherPayload.psrc, EtherPayload.pdst])
                            keyRev += " "+" ".join([EtherPayload.pdst, EtherPayload.psrc])

                        elif isinstance(EtherPayload, scapy.packet.Raw):
                            pass

                        else:
                            print("ERR: Unknown Type of Ethernet packet: {}: {}".format(type(EtherPayload), EtherPayload))

                    elif isinstance(packet, scapy.layers.l2.Dot3):
                        packetdata = {"name": packet.name, "type": packet.payload.name, "hwsrc": packet.src, "hwdst": packet.dst, "len": len(packet)}

                        keyFwd += " "+" ".join([packet.payload.name, packet.src, packet.dst])
                        keyRev += " "+" ".join([packet.payload.name, packet.dst, packet.src])
                        keyLen = len(packet)

                    else:
                        print("ERR: Unknown packet: {}: {}".format(type(packet), packet))

                  if keyFwd not in traff:
                        traff[keyFwd] = 0
                        traff[keyRev] = 0
                        revref[keyFwd] = keyRev
                        revref[keyRev] = keyFwd
                    traff[keyFwd] += keyLen
                outlines = []
                used = set()
                i = 0
                for key in reversed(sorted(list(traff.keys()), key=traff.__getitem__)):
                    if key in used:
                        continue
                    i += 1
                    used.add(key)
                    revkey = revref[key]
                    used.add(revkey)
                    outlines.append('{} кбит/с, {} кбит/с, {}'.format(int(800*traff[key]/1000/duration)/100, int(800*traff[revkey]/1000/duration)/100, key))
                    if i > 10:
                        break
                print("\n\n\n")
                for x in reversed(outlines):
                    print(x)

except Exception as err:
    print(f"ERR: main: {err}")
    if sniffProc is not None and sniffProc.is_alive():
        sniffProc.terminate()

while sniffProc is not None and sniffProc.is_alive():
    if not sniffQueue.empty():
        captured = sniffQueue.get()
    sleep(1)

with open('sniffer.data', 'wb') as f:
    pickle.dump(packets, f)

sniffProc.join()
