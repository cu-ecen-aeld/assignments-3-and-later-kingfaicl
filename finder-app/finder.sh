#!/bin/sh
# finder.sh for assignment 1
# Author: Clifford Loo 
if [ $# -lt 2 ]; then
	echo "Error: expected two arguments: directory path, search string"
	exit 1
else
	if [ -d $1 ]; then
		NUMFILES=`find $1 -type f|wc -l`
		NUMMATCHES=`grep -r $2 $1|wc -l`
		echo "The number of files are $NUMFILES and the number of matching lines are $NUMMATCHES"	
		exit 0
	else
		echo "Error: $1 is not a directory"
		exit 1
	fi
fi	
