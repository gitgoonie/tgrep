#!/usr/bin/env python
#
#
# This script searches a text file for a given matchcode (like grep)
# and print out the whole paragraph in which the matchcode was found
#
# A paragraph is defind as follows:
#
# 1. Each line beginning with a "non-space" starts a new paragraph
# 2. Each line starting with a space belongs to the current paragraph
# 
# Script has to be called using two cli arguments:
#
#  1. match string
#  2. file to be searched through
#
# tgrep.py matchstring filename  
#

import sys, stat, os, socket, struct, re
from optparse import OptionParser

PORT_NAMES = {
# to be removed
    "aol": "5190",
    "bgp": "179",
    "biff": "512",
 }

class ACLParser:
    """Helper class to parse an ACL file line by line.
       This will find out protocol, networks and ports for each line and keeps track
       of the name of the current ACL rule."""
    source_net = None
    source_port = None
    destination_net = None
    destination_port = None
    protocol = None

    # Add special patterns to detect IP networks and hosts here
    # Make sure they start with the most specific, as they are tried in order
    net_patterns = [
        r"host\D+(\d+\.\d+\.\d+\.\d+)",
        r"\D(\d+\.\d+\.\d+\.\d+\D\d+\.\d+\.\d+\.\d+)",
        r"\D(\d+\.\d+\.\d+\.\d+\/\d+)",
        r"\s(any)",
    ]

    # Add special patterns to detect port descriptions here
    # Make sure they start with the most specific, as they are tried in order
    port_patterns = [
        r"\s(range\s+\d+\s+\d+)",
        r"\s(n?eq\s(\d+(\s|$))+)",
        r"\s(n?eq\s+\S+)",
        r"\s(gt\s+\d+)",
        r"\s(lt\s+\d+)",
        r"\s(any)",
    ]

    protocol_patterns = [
        r"\s(icmp|ip|tcp|udp)\s"
    ]

    def __init__(self):
        # compile all patterns to regexes
        self.net_patterns = [re.compile(p) for p in self.net_patterns]
        self.port_patterns = [re.compile(p) for p in self.port_patterns]
        self.protocol_patterns = [re.compile(p) for p in self.protocol_patterns]

        # prepare port name map regex (see https://www.safaribooksonline.com/library/view/python-cookbook-2nd/0596007973/ch01s19.html)
        self.port_names = re.compile("\\b" + "\\b|\\b".join(map(re.escape, PORT_NAMES)) + "\\b")

    def reset_transients(self):
        self.source_net = None
        self.source_port = None
        self.destination_net = None
        self.destination_port = None
        self.protocol = None

    def match_patterns(self, line, patterns):
        """We might get invalid matches, e.g. "source_mask destination_net. This gets sorted out by taking
           the first and the last match later on."""
        hits = {}
        for p in patterns:
            m = p.search(line)
            while m:
                if not m.start() in hits:
                    hits[m.start()] = m.group(1)
                m = p.search(line, m.start() + 1)
        return hits

    def assign_source_dest(self, hits, line):
        """Take the first and last one to weed out the invalid hits."""
        result = [None, None]
        sorted_keys = sorted(hits.keys())
        if len(sorted_keys) > 0:
            result[0] = hits[sorted_keys[0]].strip()
        if len(sorted_keys) > 1:
            result[1] = hits[sorted_keys[-1]].strip()

        # if there is only one hit, we must decide whether it is source or destination
        # This should only happen for ports, so let's see if it is at the end of the line
        # (should be destination then)
        if len(sorted_keys) == 1:
            hit = hits[sorted_keys[0]]
            if line.index(hit) + len(hit) > len(line) - 4:

                result[1] = result[0]
                result[0] = None
        return result

    def next_line(self, line):
        self.reset_transients()

        # transform named ports to numbers (see https://www.safaribooksonline.com/library/view/python-cookbook-2nd/0596007973/ch01s19.html)
        line = self.port_names.sub(lambda match: PORT_NAMES[match.group(0)], line)

        # first look for all net matches
        hits = self.match_patterns(line, self.net_patterns)
        (self.source_net, self.destination_net) = self.assign_source_dest(hits, line)

        # transform simple hosts into CIDR form
        if self.source_net and not "any" in self.source_net and not "/" in self.source_net and not " " in self.source_net:
            self.source_net += "/32"
        if self.destination_net and not "any" in self.destination_net and not "/" in self.destination_net and not " " in self.destination_net:
            self.destination_net += "/32"

        # second look for all port matches
        hits = self.match_patterns(line, self.port_patterns)
        (self.source_port, self.destination_port) = self.assign_source_dest(hits, line)

        # look for all protocol matches
        hits = self.match_patterns(line, self.protocol_patterns)
        if len(hits) == 1:
            self.protocol = hits.popitem()[1]

class ACLGrepper:
    '''The main class which handles the grep process as a whole.'''
    splitter = re.compile(r"[^0-9.]")

    parser = ACLParser()

    source_ip_string = None
    source_ip_address = None
    source_port = None

    destination_ip_string = None
    destination_ip_address = None
    destination_port = None

    protocol = None
    match_any = False


    def __init__(self, sip = None, sport = None, dip = None, dport = None, protocol = None, match_any = None):
        self.source_ip_string = sip
        if sip:
            self.source_ip_address = self.ip_to_bits(sip)
        self.source_port = sport

        self.destination_ip_string = dip
        if dip:
            self.destination_ip_address = self.ip_to_bits(dip)
        self.destination_port = dport

        self.protocol = protocol
        self.match_any = match_any

    def ip_to_bits(self, address):
        '''Turns an IP address in dot notation into a single long value.'''

        # Fixup IP addresses with leading zeros
        fixed_address = ".".join([str(int(x)) for x in address.split(".")])

        try:
            return struct.unpack("!L", socket.inet_aton(fixed_address))[0]
        except socket.error:
            raise ValueError("Invalid IP address")

    def ip_in_net(self, ip, net):
        '''Checks if an IP adress is contained in a network described by a pair (net address, subnetmask).
           All values are given as longs.'''
        return (net[0] & net[1] == ip & net[1])

    def ip_and_mask_to_pair(self, pattern):
        '''Takes a mask pattern and creates a pair (net address, subnetmask) from it.
           Detects automatically if the mask is a subnetmask or a wildcard mask, assuming the bits are
           set continuously in either.'''
        parts = re.split(self.splitter, pattern)
        net = self.ip_to_bits(parts[0])
        net_or_wildcard = self.ip_to_bits(parts[1])

        # special case full bits -> subnet mask
        if 0xffffffff == net_or_wildcard:
            return (net, 0xffffffff)

        # check if the mask is really a mask (only set bits from the right or left)
        if net_or_wildcard & (net_or_wildcard + 1) != 0:
            net_or_wildcard = 0xffffffff ^ net_or_wildcard
            if net_or_wildcard & (net_or_wildcard + 1) != 0:
                # it's not, never match
                return (0, 0xffffffff)

        return (net, 0xffffffff ^ net_or_wildcard)

    def ip_and_cidr_to_pair(self, pattern):
        '''Takes a CIDR pattern and creates a pair (net address, subnetmask) from it.'''
        parts = pattern.split("/")
        net = self.ip_to_bits(parts[0])
        wildcard = (1 << (32-int(parts[1])))-1
        return (net, 0xffffffff ^ wildcard)

    def net_string_to_pair(self, pattern):
        if pattern.find("/") == -1:
            return self.ip_and_mask_to_pair(pattern)
        else:
            return self.ip_and_cidr_to_pair(pattern)


    def grep(self, line):
        self.parser.next_line(line)
        
        try:

            # FIXME check any if desired
            if self.source_ip_address:
                if self.parser.source_net == "any":
                    return self.match_any
                if not self.parser.source_net:
                    return False
                if not self.ip_in_net(self.source_ip_address, self.net_string_to_pair(self.parser.source_net)):
                    return False

            if self.destination_ip_address:
                if self.parser.destination_net == "any":
                    return self.match_any
                if not self.parser.destination_net:
                    return False
                if not self.ip_in_net(self.destination_ip_address, self.net_string_to_pair(self.parser.destination_net)):
                    return False
                
            if self.protocol:
                if not (self.parser.protocol == self.protocol or self.parser.protocol == "ip"):
                    return False
                
            if self.source_port:
                pattern = self.parser.source_port
            
                # no source port found in rule
                if not pattern:
                    return False

                # any is ok anyway

                # eq
                if pattern[:2] == "eq":
                    parts = pattern.split()
                    if not self.source_port in parts[1:]:
                        return False

                # neq
                if pattern[:3] == "neq":
                    if self.source_port == pattern[4:]:
                        return False

                # gt
                if pattern[:2] == "gt":
                    if int(self.source_port) <= int(pattern[3:]):
                        return False

                # lt
                if pattern[:2] == "lt":
                    if int(self.source_port) >= int(pattern[3:]):
                        return False

                # range
                if pattern[:5] == "range":
                    parts = pattern.split()
                    if int(self.source_port) < int(parts[1]) or int(self.source_port) > int(parts[2]):
                        return False

            if self.destination_port:
                pattern = self.parser.destination_port

                # no destination port found in rule
                if not pattern:
                    return False

                # any is ok anyway

                # eq
                if pattern[:2] == "eq":
                    parts = pattern.split()
                    if not self.destination_port in parts[1:]:
                        return False

                # neq
                if pattern[:3] == "neq":
                    if self.destination_port == pattern[4:]:
                        return False

                # gt
                if pattern[:2] == "gt":
                    if int(self.destination_port) <= int(pattern[3:]):
                        return False

                # lt
                if pattern[:2] == "lt":
                    if int(self.destination_port) >= int(pattern[3:]):
                        return False

                # range
                if pattern[:5] == "range":
                    parts = pattern.split()
                    if int(self.destination_port) < int(parts[1]) or int(self.destination_port) > int(parts[2]):
                        return False
        except ValueError:
            # some trouble when parsing stuff, let's assume this is not a match
            return False

        return True

def tgrepper(lmatch, lf, lopt, lfn):
                output = 0
                n = 0
                para = [ ]

                # initializations based on options
                if lopt.ip:
                    lgrepper = ACLGrepper(None,None,lmatch,None,None,False)

                lno = 0         # paragraph line counter
                toutput = [ ]   # title only output

                if lopt.prn == '1':
                    print '>>>processed file: ', lfn

                for line in lf:

                    if line[0] !=' ':    # if begin of new paragraph
                        if output == 1:      # eventually print last paragraph and reset paraarray
                            if lopt.title:
                                while n < len(toutput):
                                    if ( lopt.prn == '2' ):
                                        print lfn, (': '),
                                    print para[ toutput[n] ].rstrip('\n')                       
                                    n = n + 1
                                toutput = [ ]
                                output = 0
                                para = [ ]
                                lno = 0
                                n = 0
                            else:
                                while n < len(para):
                                    if ( lopt.prn == '2' ):
                                        print lfn, (': '),
                                    print para[n],
                                    n = n + 1
                                output = 0
                                para = [ ]
                                n = 0
                                lno = 0     # reset paragraph line counter
                        else:                # else reset paraarray only
                            para = [ ]
                            lno = 0         # reset paragraph line counter
                            toutput = [ ]   # reset para title
                            
                        toutput.append(lno) # save para title for title-only output
                        
                        if ( lopt.ip == None ):
                            if lmatch in line:  # if matchcode found set output flag
                                output = 1
                        if lopt.ip:
                            if lgrepper.grep(line):  # if ip address is found set output flag
                                output = 1
         
                    elif line[0] == ' ':   # if line belongs to a paragraph...

                        if ( lopt.ip == None ):
                            if lmatch in line:  # if matchcode found set output flag
                                output = 1
                                toutput.append(lno) # save line number for title only output
                        if lopt.ip:
                            if lgrepper.grep(line):  # if ip address is found set output flag
                                output = 1
                                toutput.append(lno) # save line number for title only output
                    else:
                        print "*** WARNING: Line not classified ***"    # For debug
                        print line
                    para.append(line)  # save line
                    lno = lno + 1

def main():

    parser = OptionParser(usage="Usage: \n    %prog [options] [matchstring] [file, file, ...]     or\n    cat textfile | tgrep [options] [matchstring]")
    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False, help="turn on debug")
    parser.add_option("-i", "--ipadd", dest="ip", default=None, help="matching ip addresses within subnets")
    parser.add_option("-t", "--title-only", dest="title", action="store_true", default=None, help="only show paragraph titles and matching lines")
    parser.add_option("-p", "--print-filename", dest="prn", default="1", help="print filename in outputs (p1 = once per file, p2 = once per line")
#    parser.add_option("-r", "--recursive", dest="rec", action="store_true", default=False, help="search through subfolders")


    (options, args) = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()

    if options.ip:
        match = options.ip
    else:
        match = args[0]     # grab matchcode
        del args[0]             # remove matchcode from arguments and leave files

    fh_stdin = ''
    i = 00

    try:
        # check if stdin contains some data:
        mode = os.fstat(0).st_mode
        
        if ( stat.S_ISFIFO(mode) or stat.S_ISREG(mode) ):  # if data is piped or redirected via stdin
            fh_stdin = sys.stdin                                                # save file handle
            tgrepper(match, fh_stdin, options, '<stdin>') # call tgrepper with stdin file handle
        else:
            while ( i < len(args) ):                # go through all filenames listed as arguments
                file = args[i]
                if not os.path.exists(file):
                    print 'file not found: ', file
                elif os.path.isfile(file):
                    fh = open(file, 'r')
                    tgrepper(match, fh, options, file)       # call tgrepper with filename, no file handle needed
                i = i + 1

    except IOError as err:
        print "--------------------------------------------------------------"
        print "my exception handling:"
        print "I/O error({0}): {1}".format(err.errno, err.strerror)
        print "--------------------------------------------------------------"
        if option.debug():
            print "--------------------------------------------------------------"
            print "original exception output:"
            print "--------------------------------------------------------------"
            raise
    
    except:
        print "--------------------------------------------------------------"
        print "Unexpected error:", sys.exc_info()[0]
        print "--------------------------------------------------------------"
        raise
    
main()	
