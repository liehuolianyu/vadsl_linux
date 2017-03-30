#!/bin/sh

# config
INSTALL_PATH=/usr/local/bin
CONFIG_PATH=/etc/vadsl

# vars in this sh file

# config file
cfile=$CONFIG_PATH/vadsl.conf

log_out=$INSTALL_PATH/vadsl_logout
ip_tables=iptables

# functions

# check if user run this as root
uid=$(id -u)
if [ "$uid" != "0" ]
then
	echo vadsl: ERROR: Please run this as root !
	exit 1
fi

if [ -f $cfile ]
then
	echo vadsl: INFO: Use config file $cfile
else
	echo vadsl: ERROR: Can not find config file $cfile
	exit 1
fi

interface=$(sed -ne '/^#/d; s/\(interface\)\( \)\(.*\)/\3/p' $cfile)
bindip=$(sed -ne '/^#/d; s/\(bindip\)\( \)\(.*\)/\3/p' $cfile)
authserver=$(sed -ne '/^#/d; s/\(authserver\)\( \)\(.*\)/\3/p' $cfile)
account=$(sed -ne '/^#/d; s/\(account\)\( \)\(.*\)/\3/p' $cfile)
threadsnum=$(sed -ne '/^#/d; s/\(threadsnum\)\( \)\(.*\)/\3/p' $cfile)
logpath=$(sed -ne '/^#/d; s/\(logpath\)\( \)\(.*\)/\3/p' $cfile)
logfile=$(sed -ne '/^#/d; s/\(logfile\)\( \)\(.*\)/\3/p' $cfile)

# process log file

# create log path
(cd $logpath || mkdir $logpath || echo vadsl: ERROR: Can not access logpath $logpath ! ; exit 1)

logfile=$logpath/$logfile

touch $logfile

[ -z $threadsnum ] || threadsnum=2

# set iptables
if [ -z $(grep IptablesRulesSet $logfile) ]
then
	echo vadsl: WARNING: Not found such iptables rules !
else
	echo vadsl: INFO: Cleaning iptables rules ...
	$ip_tables -t mangle -D OUTPUT -d 127.0.0.0/8 -j ACCEPT
	#$ip_tables -t mangle -D OUTPUT -d 255.0.0.0/8 -j ACCEPT
	for rf in $(grep RF $logfile | cut -d':' -f2)
	do
		[ -z $rf ] || $ip_tables -t mangle -D OUTPUT -d $rf -j ACCEPT
	done
	$ip_tables -t mangle -D OUTPUT -j NFQUEUE --queue-balance 0:$(expr $threadsnum - 1)
	echo vadsl: [ OK ] Clean iptables rules finished.
fi

# end login and route filter process
echo vadsl: INFO: Checking longin and route filter process ...
loginpid=$(grep loginpid $logfile | cut -d':' -f5)
logindpid=$(grep logindpid $logfile | cut -d':' -f5)
[ -z $loginpid ] || [ -z $(ps -eo pid | grep $loginpid) ] || (echo vadsl: INFO: Found longin process $loginpid && kill $loginpid)
[ -z $logindpid ] || [ -z $(ps -eo pid | grep $logindpid) ] || (echo vadsl: INFO: Found background login process $logindpid && kill $logindpid)
echo vadsl: INFO: Login process ended.
nfqpid=$(grep nfqpid $logfile | cut -d':' -f5)
nfqdpid=$(grep nfqdpid $logfile | cut -d':' -f5)
[ -z $nfqpid ] || [ -z $(ps -eo pid | grep $nfqpid) ] || (echo vadsl: INFO: Found route filter process $nfqpid && kill $nfqpid)
[ -z $nfqdpid ] || [ -z $(ps -eo pid | grep $nfqdpid) ] || (echo vadsl: INFO: Found background route filter process $nfqdpid && kill $nfqdpid)
echo vadsl: INFO: Route filter process ended.

echo vadsl: INFO: Restore $interface MTU settings \(set MTU to 1500\)
ifconfig $interface mtu 1500

echo vadsl: INFO: Sending logout request ...
$log_out -b $bindip -s $authserver -a $account 2> $logfile

exit 0
