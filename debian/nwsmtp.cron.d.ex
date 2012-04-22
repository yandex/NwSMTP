#
# Regular cron jobs for the nwsmtp package
#
0 4	* * *	root	[ -x /usr/bin/nwsmtp_maintenance ] && /usr/bin/nwsmtp_maintenance
