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

def tgrepper(lmatch, lfn, lfh):
                output = 0
                n = 0
                para = [ '' ]

                if not lfh:
                    lf = open(lfn,'r')
                else:
                    lf = lfh
                    
                for line in lf:

                    if line[0] !=' ':    # if begin of new paragraph
                        if output == 1:      # eventually print last paragraph and reset paraarray
                            while n < len(para):
                                print para[n],
                                n = n + 1
                            output = 0
                            para = [ '' ]
                            n = 0
                        else:                # else reset paraarray only
                            para = [ '' ]
                        if lmatch in line:  # if matchcode found set output flag
                            output = 1

                    elif line[0] == ' ':   # if line belongs to a paragraph...
                        if lmatch in line:  # check matchode and set output flag in case
                            output = 1
                    else:
                        print "*** WARNING: Line not classified ***"    # For debug
                        print line
                    para.append(line)  # save line
                lf.close()

def main():

    import argparse, sys, stat, os
    from optparse import OptionParser

    parser = OptionParser(usage="Usage: \n    %prog [options] [matchstring] [file, file, ...]     or\n    cat textfile | tgrep [options] [matchstring]")
    parser.add_option("-d", "--debug", dest="debug", action="store_true", default=False, help="turn on debug")
#    parser.add_option("-r", "--recursive", dest="rec", action="store_true", default=False, help="search through subfolders")
# ignore   parser.add_option("-m", "--match", dest="matchcode", default=None, help="string to be matched")


    (options, args) = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit()

    match = args[0]     # grab matchcode
    del args[0]             # remove matchcode from arguments and leave files

    output = 0             # flag to set if paragraph has to be printed out
    fh_stdin =''            # file handle for stdin
    i = 0
    n = 0
    para = [ '' ]

    try:
        # check if stdin contains some data:
        mode = os.fstat(0).st_mode
        
        if ( stat.S_ISFIFO(mode) or stat.S_ISREG(mode) ):
            fh_stdin = sys.stdin
            tgrepper(match, '', fh_stdin ) # call tgrepper with stdin file handle
        else:
            while ( i < len(args) ):                # go through all filenames listed as arguments
                file = args[i]
                if not os.path.exists(file):
                    print "file not found: ", file
                elif os.path.isfile(file):
                    tgrepper(match, file, '')       # call tgrepper with filename, no file handle needed
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
