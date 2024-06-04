#!/bin/sh
# writer.sh for assignment 1
# Author: Clifford Loo 
if [ $# -lt 2 ]; then
	echo "Error: expected two arguments: full path to a file, text string to be written to the file"
	exit 1
else
	# split the full path into two parts: the directory and the file name 
	DIR=${1%/*}
	FILE=${1##*/}
	echo "Directory: $DIR"
	echo "File: $FILE"
	# create directory if non-existent
	if [ -d $DIR ]; then
		echo "Directory $DIR exists" 	
	else
		mkdir -p $DIR
	fi
	# create or overwrite the file	
	echo $2 > $1
	if [ $? -eq 0 ]; then
		echo "Success"	
		exit 0
	else
		echo "Error: the file $1 could not be created"
		exit 1
	fi
fi	
