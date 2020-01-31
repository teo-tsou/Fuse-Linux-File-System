#!/bin/bash	
		#check this with "which bash"

cd mountdir

touch $1

read		#Press Enter to continue the script


read

cat $2 $3 > $1

less $1

cd ..


