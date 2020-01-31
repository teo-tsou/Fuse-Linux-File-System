#!/bin/bash
		#check this with "which bash"

cd mountdir

echo ""
echo "About to copy file abcdefghijklmnopqrstuvwxyz.txt to new_file.txt"
echo ""

read

cp abcdefghijklmnopqrstuvwxyz.txt new_file.txt

echo "COPY DONE"
read

ls -l

cd ..
