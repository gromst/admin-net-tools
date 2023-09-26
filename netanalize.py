#!/usr/bin/env python3

import sys
import pickle
import signal
import subprocess
from time import sleep
from datetime import datetime
from scapy.all import *


sigExit = False

def ctrlc(signum, frame):
    global sigExit
    sigExit = True


def getpkginfo(keyFwd, keyRev, keyLen, packet, packetdata, packets):

    global sigExit

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

#        print("ERR: Unknown packet: {}: {}".format(type(packet), packet))
#        packets.append(packet)
#        print("Store in packets under index", len(packets)-1)

        stop = True

    return stop, keyFwd, keyRev, keyLen


def outdata(traff, revref, lines, duration):
    outlines = []
    used = set()
    i = 0
    for key in reversed(sorted(list(traff.keys()), key=traff.__getitem__)):
        if key in used:
            continue
        used.add(key)
        revkey = revref[key]
        used.add(revkey)
        outlines.append('{:9.2f} kbit/s, {:9.2f} kbit/s, {}'.format(8*traff[key]/1000/duration, 8*traff[revkey]/1000/duration, key))

        i += 1
        if i > lines:
            break
    while len(outlines) < lines+1:
        outlines.append("")
    for x in reversed(outlines):
        print(x)
    print('SUMMARY: {:10.2f} Mbit/s for {:5.2f} sec'.format(8*sum(list(traff.values()))/1000000/duration, duration))

    return


def analize(rampath, packets, traff, revref):

    global sigExit

    print("Analizing... ", end="")
    for packet in sniff(offline=rampath+"/netdump.pcap"):
        if sigExit:
            break

        keyFwd = ""
        keyRev = ""
        keyLen = 0

        packetdata = {}

        while True:
            if sigExit:
                break
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

    print("Done. ")
    return


def ramPathDir(cmd, rampath):

    ret = True

    if cmd:
        if not os.path.isdir(rampath):
            try:
                os.mkdir(rampath, mode=0o300, dir_fd=None)
            except Exception as err:
                ret = False
    else:
        if os.path.isdir(rampath):
            try:
                os.rmdir(rampath)
            except Exception as err:
                pass
        if os.path.isdir(rampath):
            ret = False

    return ret


def ramMountDir(cmd, ramvol, rampath):

    ret = False

    if cmd:
        rescmd = subprocess.run(["mount", "-t", "tmpfs", "-o", "size="+ramvol, "ramdisk", rampath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rescmd = subprocess.run(['df', '-k', rampath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in rescmd.stdout.decode('utf-8').split('\n'):
            parts = line.strip().split()
            if len(parts) > 0:
                if parts[-1] == rampath:
                    ret = True
    else:
        ret = True
        rescmd = subprocess.run(["umount", rampath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rescmd = subprocess.run(['df', '-k', rampath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in rescmd.stdout.decode('utf-8').split('\n'):
            parts = line.strip().split()
            if len(parts) > 0:
                if parts[-1] == rampath:
                    ret = False
    return ret

def netCapture(rampath, iface, filtr, period):

    info = ""
    error = ""

    tcpdump = ["tcpdump", "--immediate-mode", "--dont-verify-checksums", "--packet-buffered", "-w", rampath+"/netdump.pcap", "-G", period, "-W", "1"]

    if iface is not None:
        tcpdump.extend(["-i", iface])

    if filtr is not None:
        tcpdump.extend(filtr.split())

    rescmd = subprocess.run(['df', '-k', rampath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in rescmd.stdout.decode('utf-8').split('\n'):
        parts = line.strip().split()
        if len(parts) > 0:
            if parts[-1] == rampath:
                if parts[-2] == "100%" or parts[-2][0] == "9":
                    print("Emeggency: RAM Disk is Full. Increase it by -m key.\nExammple:\n\t-m 500m - for 500 Mbyste\n\t-m 5G - for 5 Gbytes")


    rescmd = subprocess.run(["rm", "-rf", rampath+"/netdump.pcap"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    info += " ".join(tcpdump)+"\n"
    print("Start sniffing...", end="")
    lastdate = datetime.now()
    rescmd = subprocess.run(tcpdump, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    delta = datetime.now()-lastdate
    print("Sniffing stopped.", end="")
    for x in rescmd.stdout.decode('utf-8').split("\n"):
        print(x+" ", end="")
#    info += rescmd.stdout.decode('utf-8')+"\n"
#    info += rescmd.stderr.decode('utf-8')+"\n"

    return delta.total_seconds(), info, error

def main(iface, filtr, period, lines, cont, ramvol, rampath):

    global sigExit

    if not ramPathDir(True, rampath):
        exit()

    if ramMountDir(True, ramvol, rampath):
        print(f"Info: {ramvol} RAM Disk is mounted to {rampath}")
    else:
        print("Warning: RAM Disk is not mounted")

    packets = []
    traff  = {}
    revref = {}
    duration = 0.

    try:
        while not sigExit:
            sleep(0.5)
            if cont:
                traff  = {}
                revref = {}
                duration = 0.
            delta, info, error = netCapture(rampath, iface, filtr, period)
            duration += delta
            analize(rampath, packets, traff, revref)
            print("Duration: {:5.2f} sec".format(delta))
            print(info)
            outdata(traff, revref, lines, duration)
            print(error)

    except KeyboardInterrupt:
        print(f"Info: Unmount RAM Disk {rampath}")
        ramMountDir(False, ramvol, rampath)
        print(f"Info: Remove temporary Path {rampath}")
        ramPathDir(False, rampath)

    except Exception as err:
        print(f"Error: main: {err}")

    return


def helpmess():

    return


if __name__ == '__main__':

    iface      = None
    filtr      = None
    period     = "1"
    lines      = 20
    cont       = False
    ramvol     = '150m'
    rampath    = '/tmp/netanalizer'

    signal.signal(signal.SIGINT, ctrlc)
    signal.signal(signal.SIGTERM, ctrlc)

    lenargv = len(sys.argv)
    if lenargv > 1:
        i = 1
        while(i<lenargv):

            if sys.argv[i] == '-i' and i+1 < lenargv:
                iface = sys.argv[i+1]
                i += 1

            elif sys.argv[i] == '-p' and i+1 < lenargv:
                if sys.argv[i+1].isdecimal():
                    period = sys.argv[i+1]
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

            elif sys.argv[i] == '-m' and i+1 < lenargv:
                ramvol = sys.argv[i+1]
                i += 1

            elif sys.argv[i] == '-t' and i+1 < lenargv:
                ramvol = sys.argv[i+1]
                i += 1

            elif sys.argv[i] == '-c':
                cont = True

            elif sys.argv[i] == '-h':
                helpmess()
                exit()

            else:
                filtr = " ".join(sys.argv[i:])
                break

            i +=1

    main(iface, filtr, period, lines, cont, ramvol, rampath)
