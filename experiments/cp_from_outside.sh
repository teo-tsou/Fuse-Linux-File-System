#!/bin/bash
		#check this with "which bash"


cd mountdir

echo ""
echo "About to copy the whole test_files directory in mountdir"
echo "Press any key to continue: "

read

cp ../test_files/* .

echo "COPY DONE"
echo ""

read

ls -l

cd ..
