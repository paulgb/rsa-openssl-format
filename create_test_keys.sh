#!/bin/sh

# Create an empty scratch directory to work in.
SCRATCH=$(mktemp -d -t ci-XXXXXXXXXX)

for keysize in 1024 2048 4096
do
    for i in $(seq 1 10)
    do
        FILENAME="${SCRATCH}/id_rsa_${i}-${keysize}"
        ssh-keygen -t rsa -b 4096 -f $FILENAME -N "" -C "test-${i}-${keysize}"
        echo "Created ${FILENAME}"
        cat "${FILENAME}.pub" >> test_keys.txt
    done
done
