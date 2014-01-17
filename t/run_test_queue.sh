#!/bin/sh -e

TNAME="test_queue"

if [ -z "$DIRNAME" ]; then
    DIRNAME="."
fi

if [ -z "$QSIZE" ]; then
    QSIZE=128
fi

if [ -z "$QSECONDS" ]; then
    QSECONDS=1
fi

$DIRNAME/$TNAME spin "$QSIZE" "$QSECONDS"
echo
$DIRNAME/$TNAME slow_producer "$QSIZE" "$QSECONDS"
echo
$DIRNAME/$TNAME slow_consumer "$QSIZE" "$QSECONDS"
echo
