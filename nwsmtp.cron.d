SHELL=/bin/sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
MAILTO=mail-root@yandex-team.ru

*/1 * * * * root nc -z -w 2 localhost 26 >/dev/null 2>&1; [ $? != "0" ] && (/etc/init.d/nwsmtp restart ; logger -p daemon.err "nwsmtp restarted") >/dev/null 2>&1
