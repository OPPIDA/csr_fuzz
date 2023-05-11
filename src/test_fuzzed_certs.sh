#!/bin/sh

KEY=$2
URL=$3

for cert in $(find "$1" -name *.crt)
do
	echo "Test: $cert ..."
	out=`curl --cert $cert --key $KEY -k $URL`
	if [ -z "$prev" ]
	then
		echo "Premiere iteration - pas de point de comparaison: vérifier le verdict manuellement"
		prev=$out
	fi
	if [ "$prev" != "$out" ]
	then
		echo "\033[31mATTENTION! sortie différente pour $cert\033[0m"
	else
		echo "\033[32mVerdict: OK\033[0m"
	fi
	prev=$out
done