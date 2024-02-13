#!/bin/sh

TNAME="test_fstrm_io_sock_hang"
SOCKNAME="./test.sock.hang"
_res=0

do_test() {
  _timeout=$1
  _result=$2
  timeout 5 $DIRNAME/$TNAME unix "$SOCKNAME" $_timeout
  _res=$?
  rm -f "$SOCKNAME"
  echo "Received result $_res. Expected $_result"
  if [ "$_res" != "$_result" ]; then
    killall $TNAME
    exit 1
  fi
}

if [ -z "$DIRNAME" ]; then
    DIRNAME="$(dirname $(readlink -f $0))"
fi

# Test with 0 timeout (blocking socket) hangs
do_test 0 124
# Test with non zero timeout (non blocking socket) works
do_test 1 0


