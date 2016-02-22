# tgrep

## Brief description

This script searches a text file for a given matchcode (like grep)
and print out the whole paragraph in which the matchcode was found

A paragraph is defind as follows:

1. Each line beginning with a "non-space" starts a new paragraph
2. Each line starting with a space belongs to the current paragraph
 
Script has to be called using two cli arguments:

1. match string
2. file to be searched through

tgrep.py matchstring filename  


## Purpose

Configuration files on Cisco platforms typically have section as described above.
With this script config files can easily be parsed and the whole section and interest can be shown.


