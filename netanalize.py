#!/usr/bin/env python3

import sys
import pickle
import signal
import multiprocessing as mp
from time import sleep
from datetime import datetime
from scapy.all import *

try:
    with open('sniffer.data', 'rb') as f: data_new = pickle.load(f)
except Exception as err:
    pass


global sigExit
sigExit  = False


def ctrlc(signum, frame):
    global sigExit
    sigExit = True


def dosniff(iface=None, filtr=None, sniffQueue=None, period=1):
    global sigExit

    print("Sniffer: iface={}, filtr={}, sniffQueue={}, period={}".format(iface, filtr, sniffQueue, period))

    try:
#        t = AsyncSniffer(iface=iface, filter=filtr)
        t = AsyncSniffer()
        print("Start Sniffer")
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
        print("ERR: sniffer: KeyboardInterrupt")
    except Exception as err:
        print(f"Error: sniffer: {err}")

    while not sniffQueue.empty():
        sleep(1)

    print("Sniffer Stoped")

    return


def getpkginfo(keyFwd, keyRev, keyLen, packet, packetdata):

    if   isinstance(packet, scapy.layers.l2.Ether):
        packetdata["Ether"] = {"name": packet.name, "type": packet.type, "hwsrc": packet.src, "hwdst": packet.dst, "len": len(packet)}

        keyFwd += " {:5d} {:17s} -> {:17s}".format(packet.type, packet.src, packet.dst)
        keyRev += " {:5d} {:17s} -> {:17s}".format(packet.type, packet.dst, packet.src)
        keyLen = len(packet)


    elif isinstance(packet, scapy.layers.inet6.IPv6):
        packetdata["IPv6"] = {"name": packet.name, "ipsrc": packet.src, "ipdst": packet.dst, "iplen": packet.plen, "proto": packet.nh}

        keyFwd += " IPv6: {:3d} {:17s} -> {:17s}".format(packet.nh, packet.src, packet.dst)
        keyRev += " IPv6: {:3d} {:17s} -> {:17s}".format(packet.nh, packet.dst, packet.src)

    elif isinstance(packet, scapy.layers.inet.UDP):
        packetdata["UDP"] = {"name": packet.name, "sport": packet.sport, "dport": packet.dport}

        keyFwd += " UDP: {:5d} -> {:5d}".format(packet.sport, packet.dport)
        keyRev += " UDP: {:5d} -> {:5d}".format(packet.dport, packet.sport)

    elif isinstance(packet, scapy.layers.inet.TCP):
        packetdata["TCP"] = {"name": packet.name, "sport": packet.sport, "dport": packet.dport}

        keyFwd += " TCP: {:5d} -> {:5d}".format(packet.sport, packet.dport)
        keyRev += " TCP: {:5d} -> {:5d}".format(packet.dport, packet.sport)

    elif isinstance(packet, scapy.layers.inet6.ICMPv6ND_RS):
        packetdata["ICMPv6ND_RS"] = {"name": packet.name}

        keyFwd += " ICMPv6ND_RS"
        keyRev += " ICMPv6ND_RS"

    elif isinstance(packet, scapy.layers.inet.ICMP):
        packetdata["ICMP"] = {"name": packet.name}

        keyFwd += " ICMP"
        keyRev += " ICMP"

    elif isinstance(packet, scapy.layers.inet.IP):
        packetdata["IPv4"] = {"name": packet.name, "ipsrc": packet.src, "ipdst": packet.dst, "iplen": packet.len, "proto": packet.proto}

        keyFwd += " IPv4: {:3d} {:15s} -> {:15s}".format(packet.proto, packet.src, packet.dst)
        keyRev += " IPv4: {:3d} {:15s} -> {:15s}".format(packet.proto, packet.dst, packet.src)

    elif isinstance(packet, scapy.layers.l2.ARP):
        packetdata["ARP"] = {"name": packet.name, "ipsrc": packet.psrc, "ipdst": packet.pdst}

        keyFwd += " ARP: {} -> {}".format(packet.psrc, packet.pdst)
        keyRev += " ARP: {} -> {}".format(packet.pdst, packet.psrc)

    elif isinstance(EtherPayload, scapy.packet.Raw):
        pass

    elif isinstance(packet, scapy.layers.l2.Dot3):
        packetdata = {"name": packet.name, "type": packet.payload.name, "hwsrc": packet.src, "hwdst": packet.dst, "len": len(packet)}

        keyFwd += " {}: {}: {}: {} -> {}".format(packet.name, packet.payload.name, packet.src, packet.dst)
        keyRev += " {}: {}: {}: {} -> {}".format(packet.name, packet.payload.name, packet.dst, packet.src)
        keyLen = len(packet)

    else:
        print("ERR: Unknown packet: {}: {}".format(type(packet), packet))


def outdata(traff, revref, duration, lines):
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
        if i > lines:
            break
    print("\n\n\n")
    for x in reversed(outlines):
        print(x)


def analize(packets, traff, revref, sniffed):

    global sigExit

    for packet in sniffed:
        if sigExit:
            break

        keyFwd = ""
        keyRev = ""
        keyLen = 0

        packetdata = {}

        while not isinstance(packet, scapy.packet.NoPayload):
            getpkginfo(keyFwd, keyRev, keyLen, packet, packetdata)
            packet = packet.payload

        if keyFwd not in traff:
            traff[keyFwd] = 0
            traff[keyRev] = 0
            revref[keyFwd] = keyRev
            revref[keyRev] = keyFwd
        traff[keyFwd] += keyLen

    return


if __name__ == '__main__':
    signal.signal(signal.SIGINT, ctrlc)
    signal.signal(signal.SIGTERM, ctrlc)
    mp.set_start_method('fork')

    iface      = None
    filtr      = None
    period     = 1
    lines      = 20
    cont       = False

    lenargv = len(sys.argv)
    if lenargv > 1:
        i = 1
        while(i<lenargv):
            if sys.argv[i] == '-i' and i+1 < lenargv:
                iface = sys.argv[i+1].split(',')
                if len(iface) == 1:
                    iface = iface[0]
                i += 1

            elif sys.argv[i] == '-p' and i+1 < lenargv:
                if sys.argv[i+1].isdecimal():
                    period = int(sys.argv[i+1])
                    i += 1
                else:
                    print("Error: Period must be decimal")
                    exit()

            elif sys.argv[i] == '-l' and i+1 < lenargv:
                if sys.argv[i+1].isdecimal():
                    lines = int(sys.argv[i+1])
                    i += 1
                else:
                    print("Error: Lines num must be decimal")
                    exit()

            elif sys.argv[i] == '-c':
                cont = True

            elif sys.argv[i] == '-h':
                helpmess()
                exit()

            else:
                filtr = " ".join(sys.argv[i:])
                break

            i +=1

    try:
        packets = []

        traff  = {}
        revref = {}

        duration = 0.

        sniffQueue = mp.SimpleQueue()
        sniffProc  = mp.Process(target=dosniff, args=(iface, filtr, sniffQueue, period), group=None, name=None, daemon=False)
        sniffProc.start()

        try:
            while sigExit:
                if cont:
                    traff  = {}
                sleep(0.5)
                newdata = False
                if sniffProc.is_alive():
                    while not sniffQueue.empty():
                        newdata = True
                        captured = sniffQueue.get()
                        duration += captured["delta"]
                        print("Get {} packets for {} sec".format(len(captured["packets"]), captured["delta"]))
                        analize(packets, traff, revref, captured["packets"])
                if newdata:
                    outdata(traff, revref, duration, lines)

        except Exception as err:
            print(f"Error: {err}")

        sniffProc.terminate()

        while sniffProc.is_alive():
            if not sniffQueue.empty():
                captured = sniffQueue.get()
            sleep(1)
        sniffProc.join()

    except Exception as err:
        print(f"Error: {err}")

    try:
        print("Save data.")
        with open('sniffer.data', 'wb') as f: pickle.dump(packets, f)
    except Exception as err:
        print(f"Error: {err}")
