#!/bin/sh

# config
INSTALL_PATH=/usr/local/bin
CONFIG_PATH=/etc/vadsl

# vars in this sh

# config file
cfile=$CONFIG_PATH/vadsl.conf

log_in=$INSTALL_PATH/vadsl_login
nfq=$INSTALL_PATH/vadsl_tnfq
ip_tables=iptables

# functions
exit_when_request(){
	voff
	exit 0
}

trap "exit_when_request" INT QUIT TERM

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
	echo vadsl: ERROR: Can not find config file $cfile !
	exit 1
fi

# get pargramers from config file
interface=$(sed -ne '/^#/d; s/\(interface\)\( \)\(.*\)/\3/p' $cfile)
bindip=$(sed -ne '/^#/d; s/\(bindip\)\( \)\(.*\)/\3/p' $cfile)
authserver=$(sed -ne '/^#/d; s/\(authserver\)\( \)\(.*\)/\3/p' $cfile)
account=$(sed -ne '/^#/d; s/\(account\)\( \)\(.*\)/\3/p' $cfile)
password=$(sed -ne '/^#/d; s/\(password\)\( \)\(.*\)/\3/p' $cfile)
threadsnum=$(sed -ne '/^#/d; s/\(threadsnum\)\( \)\(.*\)/\3/p' $cfile)
logpath=$(sed -ne '/^#/d; s/\(logpath\)\( \)\(.*\)/\3/p' $cfile)
logfile=$(sed -ne '/^#/d; s/\(logfile\)\( \)\(.*\)/\3/p' $cfile)

[ -z $interface ] || [ -z $bindip ] || [ -z $authserver ] || \
[ -z $account ] || [ -z $password ] || [ -z $logfile ] && echo vadsl: ERROR: Config file error ! && exit 1

# process log file

# create log path
(cd $logpath || mkdir $logpath || echo vadsl: ERROR: Can not access logpath $logpath ! ; exit 1)

logfile=$logpath/$logfile

[ -f $logfile ] && mv $logfile $logfile.last
touch $logfile

echo vadsl: INFO: Use log file $logfile

# starting authenticate
echo vadsl: INFO: Starting authenticate ...
$log_in -i $interface -s $authserver -a $account -p $password -f $logfile &

# check if authenticate program is running
loginpid=$(grep loginpid $logfile | cut -d':' -f5)
while [ -z $loginpid ]
do
	loginpid=$(grep loginpid $logfile | cut -d':' -f5)
done
#echo vadsl: INFO: login process PID: $loginpid

# check if authenticate finished
authresult=$(grep AuthResult $logfile | cut -d':' -f5)
while [ -z $authresult ]
do
# check if authenticate process run correct
	if [ -z $(ps -eo pid | grep $loginpid) ]
	then
		authresult=$(grep AuthResult $logfile | cut -d':' -f5)
		[ -z $authresult ]  && echo vadsl: ERROR: Can not authenticate, please see log file for more information.  && exit 1
	fi
	authresult=$(grep AuthResult $logfile | cut -d':' -f5)
done
#echo vadsl: INFO: authenticate result: $authresult

# check authenticate resulet
[ "$authresult" = "SUCCESS" ] || exit 1
echo vadsl: [ OK ] Finished authenticate.

echo vadsl: INFO: Set $interface Max Transport Unit \(MTU\) size to 1476
ifconfig $interface mtu 1476

[ -z $threadsnum ] || threadsnum=2

# set iptables
echo vadsl: INFO: Setting iptables rules ...
$ip_tables -t mangle -A OUTPUT -d 127.0.0.0/8 -j ACCEPT
#$ip_tables -t mangle -A OUTPUT -d 255.0.0.0/8 -j ACCEPT
for rf in $(grep RF $logfile | cut -d':' -f2)
do
	[ -z $rf ] || $ip_tables -t mangle -A OUTPUT -d $rf -j ACCEPT
done
$ip_tables -t mangle -A OUTPUT -j NFQUEUE --queue-balance 0:$(expr $threadsnum - 1)
echo IptablesRulesSet >> $logfile
echo vadsl: [ OK ] Set iptables rules finished.

# route filter process
echo -n vadsl: INFO: Starting route filter process ...
relayip=$(grep RelayIP $logfile | cut -d':' -f2)
[ -z $relayip ] || nice --10 $nfq -d -b $bindip -r $relayip -f $logfile -t $threadsnum &

# check if route filter process is running
nfqpid=$(grep nfqdpid $logfile | cut -d':' -f5)
while [ -z $nfqpid ]
do
	nfqpid=$(grep nfqdpid $logfile | cut -d':' -f5)
#	[ -z $(ps -eo pid,cmd | grep $nfq | grep -v grep) ] && [ -z $nfqpid ] && (echo vadsl: ERRER: route filter process filed, please see log file for more information && voff && exit 1)
done
#echo vadsl: INFO: route filter process PID: $nfqpid

# check if init finished
nfqresult=$(grep nfqresult $logfile | cut -d':' -f5)
while [ -z $nfqresult ]
do
	echo -n .
	sleep 1
# check if route filter process run correct
	if [ -z $(ps -eo pid | grep $nfqpid) ]
	then
		nfqresult=$(grep nfqresult $logfile | cut -d':' -f5)
		[ -z $nfqresult ] && \
		echo vadsl: ERROR: route filter process exited unpredicted. \
		Please see log file for more information. \
		&& voff && exit 1
	fi
	nfqresult=$(grep nfqresult $logfile | cut -d':' -f5)
done
echo .

# check the resulet of the route filter process
if [ "$nfqresult" = "SUCCESS" ]
then
	echo vadsl: [ OK ] Start route filter process finished.
else
	echo vadsl: ERROR: Can not run route filter process, please see log file for more information. && voff && exit 1
fi

wait

exit 0
