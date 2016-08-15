#!/usr/bin/env python
"""
  Copyright (c) 2015 Cisco Systems, Inc. and others.  All rights reserved.

  This program and the accompanying materials are made available under the
  terms of the Eclipse Public License v1.0 which accompanies this distribution,
  and is available at http://www.eclipse.org/legal/epl-v10.html

  .. moduleauthor:: Tim Evens <tievens@cisco.com>
"""
import sys
import getopt
import socket
from struct import unpack

ATTR_FLAGS_OPT = 0x80
ATTR_FLAGS_TRANS = 0x40
ATTR_FLAGS_PARTIAL = 0x20
ATTR_FLAGS_EXLEN = 0x10


def bgpParse_nlri_v4(data):
    """ Parses NRLI tuples (IPv4) from data buffer

    :param data:        Data buffer of tuples, this is not the FD

    :return:    Array of IP/bits string
    """
    nlri_list = []

    if (not data):
        return []

    length = len(data)

    i = 0
    while (i < length):
        (bits,) = unpack('>B', data[i])
        i += 1

        addr_bytes = bits / 8
        if (bits % 8):
            addr_bytes += 1

        raw_ip = data[i:i+addr_bytes]

        ip = socket.inet_ntop(socket.AF_INET, raw_ip.ljust(4, '\0'))
        nlri_list.append("%s/%d" % (ip, bits))

        i += addr_bytes

    return nlri_list

def get_asn_encoding(attr_data, len):
    """ Goes through all attribute data to detect the ASN encoding

        Attempts to parse the AS_PATH using 4 octet. If parse fails, it's
        2-octet encoded.  Aggregator can also be used to detect this, but
        that attribute isn't always present.

        :param attr_data:   Attribute data from BGP update message
        :param len:         Length of the attribute data

        :return: 2 for 2-octet, 4 for 4-octet, and 0 if cannot be detected
    """
    asn_len = 0
    attr_read = 0

    while attr_read < len:
        (attr_flags, attr_type) = unpack('!BB', attr_data[attr_read: attr_read + 2])
        attr_read += 2

        #print "Attribute flags %x type = %r (%d/%d)" % (attr_flags, attr_type, attr_read, len)

        if ATTR_FLAGS_EXLEN & attr_flags:
            #print "Attribute %d is extended length" % attr_type
            (attr_len,) = unpack('!H', attr_data[attr_read: attr_read + 2])
            attr_read += 2
        else:
            (attr_len,) = unpack('!B', attr_data[attr_read: attr_read + 1])
            attr_read += 1

        if attr_type == 2:
            print "Attribute is AS_PATH"
            path_data = attr_data[attr_read: attr_read + attr_len]
            path_read = 0
            while path_read < attr_len:
                (path_type, path_count) = unpack("!BB", path_data[path_read: path_read + 2])
                path_read += 2
                print "path seg type = %d count = %d" % (path_type, path_count)
                path_read += 4 * path_count

            if path_read > attr_len:
                print "2-octet encoding"
                asn_len = 2
            else:
                print "4-octet encoding"
                asn_len = 4
            break

        attr_read += attr_len


    return asn_len

def bgpParse_update(fd, len):
    """ Parse BGP update message from file

    :param fd:      Opened file descriptor to the BMP file
    :param len:     Length of the update message

    :return: dictionary defined as::
            {
            }
    """
    hdr = { 'nlri_list': [],
            'withdrawn_list': []}

    (withdrawn_len,) = unpack('>H', fd.read(2))
    withdrawn_data = fd.read(withdrawn_len)

    (attr_len,) = unpack('>H', fd.read(2))
    attr_data = fd.read(attr_len)

    hdr['nlri_len'] = (len - 4) - (withdrawn_len + attr_len)
    if (hdr['nlri_len'] > 0):
        nlri_data = fd.read(hdr['nlri_len'])
    else:
        nlri_data = None

    hdr['withdrawn_len'] = withdrawn_len
    hdr['attr_len'] = attr_len
    hdr['nlri_len'] = len - (withdrawn_len + attr_len)
    hdr['nlri_list'] = bgpParse_nlri_v4(nlri_data)

    if (withdrawn_len > 0):
        hdr['withdrawn_list'] = bgpParse_nlri_v4(withdrawn_data)

    get_asn_encoding(attr_data, attr_len)

    return hdr


def bgpParse_Hdr(fd):
    """ Parse BGP header from file

    :param fd:      Opened file descriptor to the BMP file

    :return: dictionary defined as::
            {
                type:       <string; Type of BGP message>,
                length:     <int; length of bgp message, not including common header>
            }
    """
    hdr = {}

    marker = fd.read(16)

    (len, type) = unpack('>HB', fd.read(3))

    hdr['length'] = len - 19

    if (type == 1):
        hdr['type'] = "OPEN"
    elif (type == 2):
        hdr['type'] = "UPDATE"
    elif (type == 3):
        hdr['type'] = "NOTIFICATION"
    elif (type == 4):
        hdr['type'] = "KEEPALIVE"
    elif (type == 5):
        hdr['type'] = "ROUTE_REFRESH"
    else:
        hdr['type'] = "UNKNOWN=%d" % type

    return hdr

def bmpParse_peerHdr(fd):
    """ Parse BMP peer header from file

    :param fd:      Opened file descriptor to the BMP file

    :return: dictionary defined as::
            {
                type:       <string; either 'GLOBAL' or 'L3VPN'>,
                dist_id:    <int; 64bit route distinguisher id>,
                addr:       <string, printed form of IP>,
                asn:        <int; asn>,
                bgp_id:     <int; bgp ID>,
                isIPv4:     <bool>,
                isPrePolicy <bool; either pre or post>
                is2ByteASN  <bool; either 2 or 4 byte ASN>
                ts_secs:    <timestamp in unix time>,
                ts_usecs:   <timestamp microseconds>
            }
    """
    hdr = { 'type': None,
            'dist_id': 0,
            'addr': None,
            'asn': 0,
            'bgp_id': 0,
            'isIPv4': True,
            'isPrePolicy': True,
            'is2ByteASN': False,
            'ts_secs': 0,
            'ts_usecs': 0}

    (type, flags, hdr['dist_id']) = unpack('>BBQ', fd.read(10))

    if (type == 0):
        hdr['type'] = 'GLOBAL'
    else:
        hdr['type'] = 'L3VPN'

    if (flags & 0x80):  # V flag
        hdr['isIPv4'] = False
    else:
        hdr['isIPv4'] = True

    if (flags & 0x40):  # L flag
        hdr['isPrePolicy'] = False
    else:
        hdr['isPrePolicy'] = True

    if (flags & 0x20):  # A flag
        hdr['is2ByteASN'] = True
    else:
        hdr['is2ByteASN'] = False

    if (hdr['isIPv4']):
        fd.read(12)     # skip to the ipv4 address
        hdr['addr'] = socket.inet_ntop(socket.AF_INET, fd.read(4))
    else:
        hdr['addr'] = socket.inet_ntop(socket.AF_INET6, fd.read(16))


    (hdr['asn'],) = unpack('>I', fd.read(4))

    hdr['bgp_id'] = socket.inet_ntop(socket.AF_INET, fd.read(4))

    (hdr['ts_secs'], hdr['ts_usecs']) = unpack('>II', fd.read(8))

    return hdr


def bmpParse_peerUpHdr(fd, bmp_peer_hdr):
    """ Parse BMP peer UP header from file

    :param fd:              Opened file descriptor to the BMP file
    :param bmp_peer_hdr:    Reference to the parsed bmp peer header

    ..note: info TLV's should be checked after initial header parse.  BGP OPEN messages should be checked
          after the initial header parse

    :return: dictionary defined as::
            {
                local_address:    <string; printed form of local IP>,
                local_port:       <int; local port>,
                remote_port:      <int; remote port>,
            }
    """
    hdr = { 'local_addr': None,
            'local_port': 0,
            'remote_port': 0}

    if (bmp_peer_hdr['isIPv4']):
        fd.read(12)     # skip to the ipv4 address
        hdr['local_address'] = socket.inet_ntop(socket.AF_INET, fd.read(4))
    else:
        hdr['local_address'] = socket.inet_ntop(socket.AF_INET6, fd.read(16))

    (hdr['local_port'], hdr['remote_port'],) = unpack('>HH', fd.read(4))

    return hdr


def bmpParse_bmpHdr(fd):
    """ Parse BMP header from file

    :param fd:      Opened file descriptor to the BMP file

    :return: dictionary defined as::
            {
                version:    <int; version of bmp>,
                length:     <int; bmp message length in bytes not including common header>,
                type:       <string; BMP type of message>,
            }
    """
    hdr = { 'version': None,
            'length': 0,
            'type': None }

    data = fd.read(1)
    if (not data):
        return None

    (hdr['version'],) = unpack('B', data)

    if (hdr['version'] == 3):
        (hdr['length'], type) = unpack('>IB', fd.read(5))
        hdr['length'] -= 6 # remove the bytes of the common header

        if (type == 0):
            hdr['type'] = 'ROUTE_MON'
        elif (type == 1):
            hdr['type'] = 'STATS_REPORT'
        elif (type == 2):
            hdr['type'] = 'PEER_DOWN'
        elif (type == 3):
            hdr['type'] = 'PEER_UP'
        elif (type == 4):
            hdr['type'] = 'INIT'
        elif (type == 5):
            hdr['type'] = 'TERM'
        else:
            hdr['type'] = "UNKNOWN=%d" % type

    else:
        print "ERROR: Unsupported BMP version type of %d, cannot proceed" % hdr['version']
        return None

    return hdr

def bmpRead(cfg):
    """ Reads the BMP binary file (from bmp_play record) and parses it.

    :param cfg:     Configuration dict
    """
    print "Parsing %s" % cfg['file']
    print "------------------------------------------------------------------"

    with open(cfg['file'], "rb") as f:

        bmp_hdr = bmpParse_bmpHdr(f)
        while (bmp_hdr):
            print "BMP = %r" % bmp_hdr

            if (bmp_hdr):
                # Parse the BMP message
                if (bmp_hdr['type'] == 'ROUTE_MON'):
                    peer_hdr = bmpParse_peerHdr(f)
                    print "  | Peer addr = %s asn = %s bgp-id = %s" % (
                                                peer_hdr['addr'],
                                                peer_hdr['asn'],
                                                peer_hdr['bgp_id'])
                    print "  |  ----------------------"

                    bgp_hdr = bgpParse_Hdr(f)
                    print "  |    BGP = %r" % bgp_hdr

                    upd_hdr = bgpParse_update(f, bgp_hdr['length'])
                    print "  |    Update attr_len = %d nlri_len = %d nlri_prefixes = %d wd_len = %d wd_prefixes = %d" % (
                                upd_hdr['attr_len'], upd_hdr['nlri_len'], len(upd_hdr['nlri_list']),
                                upd_hdr['withdrawn_len'], len(upd_hdr['withdrawn_list'])
                                )

                    if (upd_hdr['nlri_len'] == 0 and upd_hdr['withdrawn_len'] == 0):
                        print "  |    == EOR =="

                    for nlri in upd_hdr['nlri_list']:
                        print "  |       preifx = %s" % nlri

                    for nlri in upd_hdr['withdrawn_list']:
                        print "  |       withdrawn preifx = %s" % nlri


                    print "  |  ----------------------"

                elif (bmp_hdr['type'] == 'PEER_UP'):
                    peer_hdr = bmpParse_peerHdr(f)

                    print "  | Peer addr = %s asn = %s bgp-id = %s" % (
                                                peer_hdr['addr'],
                                                peer_hdr['asn'],
                                                peer_hdr['bgp_id'])


                    # peer_up_hdr = bmpParse_peerUpHdr(f, peer_hdr)
                    # print "  |       local addr = %s local port = %d remote port %d" % (
                    #
                    #                             peer_up_hdr['local_addr'],
                    #                             peer_up_hdr['local_port'],
                    #                             peer_up_hdr['remote_port'])
                    #
                    # print "  |  ----------------------"
                    #
                    # bgp_hdr = bgpParse_Hdr(f)
                    # print "  |   OPEN (sent) BGP = %r" % bgp_hdr
                    #
                    # bgp_hdr = bgpParse_Hdr(f)
                    # print "  |   OPEN (recv) BGP = %r" % bgp_hdr

                    print "Peer UP Hex DUMP:"

                    for i in range(0, ((bmp_hdr['length'] - 42))):  # loop and hex dump the remaining data
                        if ((i % 16) == 0):
                            print ""
                        value = unpack("B", f.read(1))
                        print (" %2x " % value),
                    print "\n"

                else:
                    f.read(bmp_hdr['length'])

                # Get next BMP message
                bmp_hdr = bmpParse_bmpHdr(f)

    print "------------------------------------------------------------------"


def parseCmdArgs(argv):
    """ Parse commandline arguments

        Usage is printed and program is terminated if there is an error.

        :param argv:   ARGV as provided by sys.argv.  Arg 0 is the program name

        :returns:  dictionary defined as::
                {
                    file:   <filename to write to or read from>,
                }
    """
    REQUIRED_ARGS = 1
    found_req_args = 0
    cmd_args = { 'file': None,
               }

    if (len(argv) < 1):
        print "ERROR: Missing required args"
        usage(argv[0])
        sys.exit(1)

    try:
        (opts, args) = getopt.getopt(argv[1:], "hf:",
                                       ["help", "file="])

        for o, a in opts:
            if o in ("-h", "--help"):
                usage(argv[0])
                sys.exit(0)

            elif o in ("-f", "--file"):
                found_req_args += 1
                cmd_args['file'] = a

            else:
                usage(argv[0])
                sys.exit(1)

        if (found_req_args < REQUIRED_ARGS):
            print "ERROR: Missing required args, found %d required %d" % (found_req_args, REQUIRED_ARGS)
            usage(argv[0])
            sys.exit(1)

        return cmd_args

    except (getopt.GetoptError, TypeError), err:
        print str(err)  # will print something like "option -a not recognized"
        usage(argv[0])
        sys.exit(2)


def usage(prog):
    """ Usage - Prints the usage for this program.

        :param prog:  Program name
    """
    print ""
    print "Usage: %s [OPTIONS]" % prog
    print ""

    print "REQUIRED OPTIONS:"
    print "  -f, --file".ljust(30) + "Filename to write to or read from"
    print ""

    print "OPTIONAL OPTIONS:"
    print "  -h, --help".ljust(30) + "Print this help menu"


def main():
    """
        Start of program from shell
    """
    cfg = parseCmdArgs(sys.argv)
    bmpRead(cfg)


if __name__ == '__main__':
    main()
