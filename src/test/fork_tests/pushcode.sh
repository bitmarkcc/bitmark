#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

source assert.sh

datadir="$(pwd)/.bitmark"
datadirD="$datadir"
unameS="`uname -s`"
if [[ "$unameS" == "CYGWIN"* ]]
then
    datadirD="$(cygpath -w -- "$datadir")"
fi
bcli="bitmark-cli -datadir=$datadirD"

function checkcode { # assume one pushcode per tx
    nOutput="`$bcli getrawtransaction "$1" 1 | jq .vout | grep -B 4 pushcode | grep '"n"' | awk '{print $2}' | tr -d ',\n'`"
    $bcli setgenerate true 1 1
    code="`$bcli getcode "$1" "$nOutput" | tr '\n' '-' | sed 's/..$//'`"
    if ASSERT_EQUALS "$code" "$2"
    then
	echo "$nOutput"
    else
	return 1
    fi
}

txid=""
n=""

function pushcode1 {
    txid="`$bcli pushcode "$1"`"
    set +e
    n="`checkcode "$txid" $2`"
    set -e
    if [[ "$n" == *"FAIL"* ]]
    then
	echo "pushcode1 error: txid $txid"
	return 1
    fi
}

function pushcode3 {
    txid="`$bcli pushcode "$1" "$2" "$3"`"
    set +e
    n="`checkcode "$txid" $4`"
    set -e
    if [[ "$n" == *"FAIL"* ]]
    then
	echo "pushcode3 error: txid $txid"
	return 1
    fi
}

function pushcode5 {
    txid="`$bcli pushcode $1 "$2" "$3" "$4" "$5"`"
    set +e
    n="`checkcode "$txid" $6`"
    set -e
    if [[ "$n" == *"FAIL"* ]]
    then
	echo "pushcode5 error: txid $txid"
	return 1
    fi
}

function pushcode6 {
    txid="`$bcli pushcode $1 "$2" "$3" "$4" "$5" "$6"`"
    set +e
    n="`checkcode "$txid" $7`"
    set -e
    if [[ "$n" == *"FAIL"* ]]
    then
	echo "pushcode6 error: txid $txid"
	return 1
    fi
}

pushcode1 01 01
pushcode3 "$txid" "$n" 02 01-02
pushcode5 6 "$txid" "$n" 1 010c 01-010c-02
pushcode5 6 "$txid" "$n" 0 000c 000c-01-010c-02
pushcode5 6 "$txid" "$n" 2 010b 000c-01-010b-010c-02
pushcode3 "$txid" "$n" 03 000c-01-010b-010c-02-03

pushcode1 01 01
pushcode5 6 "$txid" "$n" 0 000c 000c-01
pushcode5 7 "$txid" "$n" 0 000d 000d-01
pushcode5 6 "$txid" "$n" 1 000f 000d-000f-01
pushcode3 "$txid" "$n" 02 000d-000f-01-02
pushcode5 6 "$txid" "$n" 3 010c 000d-000f-01-010c-02
pushcode6 15 "$txid" "$n" 1 2 000e 000d-000e-010c-02
pushcode5 7 "$txid" "$n" 1 "00" 000d-00-010c-02
pushcode5 7 "$txid" "$n" 1 "" 000d--010c-02

echo "PUSHCODE TESTS PASSED"
