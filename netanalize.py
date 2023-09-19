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


sigExit  = False


def ctrlc(signum, frame):

    global sigExit
    sigExit = True


def dosniff(iface=None, filtr=None, sniffQueue=None, period=1):

    global sigExit

    try:
        print("Start Sniffer")
        t = AsyncSniffer(iface=iface, filter=filtr)
        t.start()
        lastdate = datetime.now()
        sleep(period)
        while not sigExit:
            t.stop()
            delta = datetime.now()-lastdate
            sniffQueue.put({"delta": delta.total_seconds(), "packets": t.results})
            t.start()
            lastdate = datetime.now()
            sleep(period)
        t.stop()
    except KeyboardInterrupt:
        print(f"Error: sniffer: KeyboardInterrupt")
    except Exception as err:
        print(f"Error: sniffer: {err}")

    while not sniffQueue.empty():
        sleep(1)

    print("Sniffer Stoped")

    return


def getpkginfo(keyFwd, keyRev, keyLen, packet, packetdata, packets):

    stop = True

    if   isinstance(packet, scapy.layers.l2.Ether):
        packetdata["Ether"] = {"name": packet.name, "type": packet.type, "hwsrc": packet.src, "hwdst": packet.dst, "len": len(packet)}

        keyFwd += " {:5d} {:17s} -> {:17s}".format(packet.type, packet.src, packet.dst)
        keyRev += " {:5d} {:17s} -> {:17s}".format(packet.type, packet.dst, packet.src)
        if keyLen == 0:
            keyLen = len(packet)

        stop = False

    elif isinstance(packet, scapy.layers.l2.Dot3):
        packetdata["Dot3"] = {"name": packet.name, "type": packet.payload.name, "hwsrc": packet.src, "hwdst": packet.dst, "len": len(packet)}

        keyFwd += " {}: {}: {} -> {}".format(packet.name, packet.payload.name, packet.src, packet.dst)
        keyRev += " {}: {}: {} -> {}".format(packet.name, packet.payload.name, packet.dst, packet.src)
        if keyLen == 0:
            keyLen = len(packet)

        stop = False

    elif isinstance(packet, scapy.layers.l2.Dot1Q):
        packetdata["Dot1Q"] = {"name": packet.name, "type": packet.type, "vlan": packet.vlan, "len": len(packet)}

        keyFwd += " {}: {:5d}: vlan={:4d} ".format(packet.name, packet.type, packet.vlan)
        keyRev += " {}: {:5d}: vlan={:4d} ".format(packet.name, packet.type, packet.vlan)
        if keyLen == 0:
            keyLen = len(packet)

        stop = False

    elif isinstance(packet, scapy.layers.ppp.PPP):
        packetdata["PPP"] = {"name": packet.name, "proto": packet.proto}

        keyFwd += " PPP: {:3d}".format(packet.proto)
        keyRev += " PPP: {:3d}".format(packet.proto)

        stop = False

    elif isinstance(packet, scapy.layers.ppp.PPPoE):
        packetdata["PPPoE"] = {"name": packet.name, "sessionid": packet.sessionid, "len": packet.len}

        keyFwd += " PPPoE:"
        keyRev += " PPPoE:"
        if keyLen == 0:
            keyLen = len(packet)

        stop = False

    elif isinstance(packet, scapy.layers.inet.IP):
        packetdata["IPv4"] = {"name": packet.name, "ipsrc": packet.src, "ipdst": packet.dst, "iplen": packet.len, "proto": packet.proto}

        keyFwd += " IPv4: {:3d} {:15s} -> {:15s}".format(packet.proto, packet.src, packet.dst)
        keyRev += " IPv4: {:3d} {:15s} -> {:15s}".format(packet.proto, packet.dst, packet.src)
        if keyLen == 0:
            keyLen = packet.len

        stop = False

    elif isinstance(packet, scapy.layers.inet6.IPv6):
        packetdata["IPv6"] = {"name": packet.name, "ipsrc": packet.src, "ipdst": packet.dst, "iplen": packet.plen, "proto": packet.nh}

        keyFwd += " IPv6: {:3d} {:17s} -> {:17s}".format(packet.nh, packet.src, packet.dst)
        keyRev += " IPv6: {:3d} {:17s} -> {:17s}".format(packet.nh, packet.dst, packet.src)
        if keyLen == 0:
            keyLen = packet.plen

        stop = False

    elif isinstance(packet, scapy.layers.inet6.IPv6ExtHdrHopByHop):
        packetdata["IPv6ExtHdrHopByHop"] = {"name": packet.name}

        keyFwd += " IPv6ExtHdrHopByHop:"
        keyRev += " IPv6ExtHdrHopByHop:"

        stop = True

    elif isinstance(packet, scapy.layers.inet6.IPv6ExtHdrFragment):
        packetdata["IPv6ExtHdrFragm"] = {"name": packet.name, "proto": packet.nh}

        keyFwd += " IPv6ExtHdrFragm: {:3d}".format(packet.nh)
        keyRev += " IPv6ExtHdrFragm: {:3d}".format(packet.nh)

        stop = False

    elif isinstance(packet, scapy.layers.inet6.ICMPv6TimeExceeded):
        packetdata["ICMPv6TimeExceeded"] = {"name": packet.name}

        keyFwd += " ICMPv6TOut:"
        keyRev += " ICMPv6TOut:"

        stop = False

    elif isinstance(packet, scapy.layers.ipsec.ESP):
        packetdata["ESP"] = {"name": packet.name}

        keyFwd += " IPSec.ESP:"
        keyRev += " IPSec.ESP:"

        stop = True

    elif isinstance(packet, scapy.layers.inet6.IPerror6):
        packetdata["IPerror6"] = {"name": packet.name, "proto": packet.nh, "src": packet.src, "dst": packet.dst}

        keyFwd += " IPv6Err: {:3d} {:26s} -> {:26s}".format(packet.nh, packet.src, packet.dst)
        keyRev += " IPv6Err: {:3d} {:26s} -> {:26s}".format(packet.nh, packet.dst, packet.src)

        stop = False

    elif isinstance(packet, scapy.layers.sctp.SCTP):
        packetdata["SCTP"] = {"name": packet.name, "sport": packet.sport, "dport": packet.dport}

        keyFwd += " {}: {:5d} -> {:5d}".format(packet.name, packet.sport, packet.dport)
        keyRev += " {}: {:5d} -> {:5d}".format(packet.name, packet.dport, packet.sport)
        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.layers.inet.UDP):
        packetdata["UDP"] = {"name": packet.name, "sport": packet.sport, "dport": packet.dport}

        keyFwd += " UDP: {:5d} -> {:5d}".format(packet.sport, packet.dport)
        keyRev += " UDP: {:5d} -> {:5d}".format(packet.dport, packet.sport)
        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.layers.inet.TCP):
        packetdata["TCP"] = {"name": packet.name, "sport": packet.sport, "dport": packet.dport}

        keyFwd += " TCP: {:5d} -> {:5d}".format(packet.sport, packet.dport)
        keyRev += " TCP: {:5d} -> {:5d}".format(packet.dport, packet.sport)
        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.layers.inet6.ICMPv6ND_NA):
        packetdata["ICMPv6ND_NA"] = {"name": packet.name, "tgt": packet.tgt}

        keyFwd += " ICMPv6ND_NA: tgt={}".format(packet.tgt)
        keyRev += " ICMPv6ND_NA: tgt={}".format(packet.tgt)

        stop = False

    elif isinstance(packet, scapy.layers.inet6.ICMPv6ND_NS):
        packetdata["ICMPv6ND_NS"] = {"name": packet.name, "tgt": packet.tgt}

        keyFwd += " ICMPv6ND_NS: tgt={}".format(packet.tgt)
        keyRev += " ICMPv6ND_NS: tgt={}".format(packet.tgt)

        stop = False

    elif isinstance(packet, scapy.layers.inet6.ICMPv6NDOptSrcLLAddr):
        packetdata["ICMPv6NDOptSrcLLAddr"] = {"name": packet.name, "lladdr": packet.lladdr}

        keyFwd += " ICMPv6NDOptSrcLLAddr: lladdr={}".format(packet.lladdr)
        keyRev += " ICMPv6NDOptSrcLLAddr: lladdr={}".format(packet.lladdr)
        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.layers.inet6.ICMPv6ND_RS):
        packetdata["ICMPv6ND_RS"] = {"name": packet.name}

        keyFwd += " ICMPv6ND_RS"
        keyRev += " ICMPv6ND_RS"
        if keyLen == 0:
            keyLen = len(packet)

        stop = False

    elif isinstance(packet, scapy.layers.inet.ICMP):
        packetdata["ICMP"] = {"name": packet.name}

        keyFwd += " ICMP"
        keyRev += " ICMP"
        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.layers.l2.ARP):
        packetdata["ARP"] = {"name": packet.name, "ipsrc": packet.psrc, "ipdst": packet.pdst}

        keyFwd += " ARP: {} -> {}".format(packet.psrc, packet.pdst)
        keyRev += " ARP: {} -> {}".format(packet.pdst, packet.psrc)
        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.layers.l2.LLC):
        packetdata["LLC"] = {"name": packet.name, "dsap": packet.dsap, "ssap": packet.ssap, "ctrl": packet.ctrl}

        keyFwd += " LLC: dsap={} ssap={} ctrl={}".format(packet.dsap, packet.ssap, packet.ctrl)
        keyRev += " LLC: dsap={} ssap={} ctrl={}".format(packet.dsap, packet.ssap, packet.ctrl)
        if keyLen == 0:
            keyLen = len(packet)

        stop = False

    elif isinstance(packet, scapy.layers.l2.STP):
        packetdata["STP"] = {"name": packet.name, "rootid": packet.rootid, "rootmac": packet.rootmac, "bridgeid": packet.bridgeid, "bridgemac": packet.bridgemac, "portid": packet.portid}

        keyFwd += " STP: rootid={} rootmac={} bridgeid={} bridgemac={} portid={}".format(packet.rootid, packet.rootmac, packet.bridgeid, packet.bridgemac, packet.bridgemac)
        keyRev += " STP: rootid={} rootmac={} bridgeid={} bridgemac={} portid={}".format(packet.rootid, packet.rootmac, packet.bridgeid, packet.bridgemac, packet.bridgemac)
        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.layers.l2.SNAP):
        packetdata["SNAP"] = {"name": packet.name, "oui": packet.OUI, "code": packet.code}

        keyFwd += " SNAP: oui={} code={}".format(packet.OUI, packet.code)
        keyRev += " SNAP: oui={} code={}".format(packet.OUI, packet.code)
        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.packet.Raw):

        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    elif isinstance(packet, scapy.packet.NoPayload):

        if keyLen == 0:
            keyLen = len(packet)

        stop = True

    else:
        keyFwd += " UNKNOWN"
        keyRev += " UNKNOWN"
        if keyLen == 0:
            keyLen = len(packet)

        print("ERR: Unknown packet: {}: {}".format(type(packet), packet))
        packets.append(packet)
        print("Store in packets under index", len(packets)-1)

        stop = True

    return stop, keyFwd, keyRev, keyLen


def outdata(traff, revref, lines, duration):
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
        outlines.append('{:9.2f} kbit/s, {:9.2f} kbit/s, {}'.format(8*traff[key]/1000/duration, 8*traff[revkey]/1000/duration, key))
        if i > lines:
            break
    while len(outlines) < lines+3:
        outlines.append("")
    for x in reversed(outlines):
        print(x)
    print('SUMMARY: {:10.2f} Mbit/s'.format(8*sum(list(traff.values()))/1000000/duration))

    return


def analize(packets, traff, revref, sniffed):

    global sigExit

    for packet in sniffed:
        if sigExit:
            break

        keyFwd = ""
        keyRev = ""
        keyLen = 0

        packetdata = {}

        while True:
            stop, keyFwd, keyRev, keyLen = getpkginfo(keyFwd, keyRev, keyLen, packet, packetdata, packets)
            if stop:
                break
            packet = packet.payload

        if keyFwd not in traff:
            traff[keyFwd] = 0
            traff[keyRev] = 0
            revref[keyFwd] = keyRev
            revref[keyRev] = keyFwd
        traff[keyFwd] += keyLen

    return


def main(iface, filtr, period, lines, cont):
    signal.signal(signal.SIGINT, ctrlc)
    signal.signal(signal.SIGTERM, ctrlc)
    mp.set_start_method('fork')

    global sigExit

    try:
        packets = []

        traff  = {}
        revref = {}
        duration = 0.

        sniffQueue = mp.SimpleQueue()
        sniffProc  = mp.Process(target=dosniff, args=(iface, filtr, sniffQueue, period), group=None, name=None, daemon=False)
        sniffProc.start()

        try:
            while not sigExit:
                if cont:
                    traff  = {}
                    revref = {}
                    duration = 0.
                sleep(0.5)
                newdata = False
                if sniffProc.is_alive():
                    while not sniffQueue.empty():
                        newdata = True
                        captured = sniffQueue.get()
                if newdata:
                    duration += captured["delta"]
                    print("Get {} packets for {} sec".format(len(captured["packets"]), captured["delta"]))
                    analize(packets, traff, revref, captured["packets"])
                    outdata(traff, revref, lines, duration)

        except Exception as err:
            print(f"Error: main: circle: {err}")

        sniffProc.terminate()

        while sniffProc.is_alive():
            if not sniffQueue.empty():
                captured = sniffQueue.get()
            sleep(1)
        sniffProc.join()

    except Exception as err:
        print(f"Error: main: {err}")

    try:
        print("Save data.")
        with open('sniffer.data', 'wb') as f: pickle.dump(packets, f)
    except Exception as err:
        print(f"Error: main: {err}")

    return


def helpmess():

    return


if __name__ == '__main__':

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

    main(iface, filtr, period, lines, cont)
