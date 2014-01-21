#!/bin/sh -e

TNAME="test_fstrm_io_file"
FILENAME="./test.fstrm"

if [ -z "$DIRNAME" ]; then
    DIRNAME="$(dirname $(readlink -f $0))"
fi

for QUEUE_MODEL in SPSC MPSC; do
    for NUM_THREADS in 1 4 16; do
        for NUM_MESSAGES in 1 1000 100000; do
            $DIRNAME/$TNAME "$FILENAME" $QUEUE_MODEL $NUM_THREADS $NUM_MESSAGES
        done
    done
done

rm -f "$FILENAME"
