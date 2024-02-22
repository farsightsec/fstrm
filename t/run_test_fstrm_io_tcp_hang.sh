#!/bin/sh

TNAME="test_fstrm_io_sock_hang"
ADDRESS="127.0.0.1"
PORT=5678
_res=0

do_test() {
  _timeout=$1
  _result=$2
  timeout 10 $DIRNAME/.libs/$TNAME tcp "$ADDRESS" $PORT $_timeout
  _res=$?
  echo "Received result $_res. Expected $_result"
  if [ "$_res" != "$_result" ]; then
    killall $TNAME
    exit 1
  fi
}

if [ -z "$DIRNAME" ]; then
    DIRNAME="$(dirname $(readlink -f $0))"
fi

# Test with 0 read timeout should hang
do_test 0 124
# Test with default timeout should work
do_test -1 0
# Test with non zero read timeout should work
do_test 1 0
# Test with non zero read timeout should work
do_test 1000 0


