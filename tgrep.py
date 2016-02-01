#!/usr/bin/env python
#
def main():

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

    import argparse, sys, fileinput
    from optparse import OptionParser

    parser = OptionParser(usage="Usage: %prog [options] [file, file, ...]")
#    parser.add_option("-a", "--any", dest="match_any", action="store_true", default=False, help="Match ACLs with 'any', too")
#    parser.add_option("-m", "--match", dest="matchcode", default=None, help="string to be matched")


    (options, args) = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()

    match = args[0]

    output = 0
    i = 0
    n = 0
    para = [ '' ]

    del args[0]     # remove match code and leave files
    
    for line in fileinput.input(args):

        if line[0] !=' ':    # if begin of new paragraph
            if output == 1:      # eventually print last paragraph and reset paraarray
                while n < len(para):
                    print para[n],
                    n = n + 1
                output = 0
                para = [ '' ]
                i = 0            # (not used)
                n = 0
            else:                # else reset paraarray only
                para = [ '' ]
                i = 0
            if match in line:  # if matchcode found set output flag
                output = 1

        elif line[0] == ' ':   # if line belongs to a paragraph...
            i = i + 1          # (not used)
            if match in line:  # check matchode and set output flag in case
                output = 1
        else:
            print "*** WARNING: Line not classified ***"    # For debug
            print line
        para.append(line)  # save line

main()	
