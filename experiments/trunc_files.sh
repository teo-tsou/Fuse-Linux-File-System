#!/bin/bash
		#check this with "which bash"

# Create file and truncate to 3 * BLOCK_SIZE
./create_large_file.sh

cd mountdir
echo ""
echo "Created file...about to truncate it to 12288 bytes: "
read
truncate --size 12288 create_large_file.txt
ls -l
rm create_large_file.txt
echo ""
echo "File removed"
cd ..

read

# Create file and truncate more than its size
./create_large_file.sh

cd mountdir
echo ""
echo "Created file...about to truncate it to 122880 bytes: "
read
truncate --size 122880 create_large_file.txt
ls -l
cd ..
echo ""
echo "A '\0' block has been created in order to extend the file"
