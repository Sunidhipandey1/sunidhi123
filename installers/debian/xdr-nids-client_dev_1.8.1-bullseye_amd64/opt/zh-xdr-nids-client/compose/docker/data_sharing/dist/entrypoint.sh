#!/bin/bash

#source vars if file exists
DEFAULT=/etc/default/fluentd

#!/bin/bash

# This file downloads latest connection maps from the listbot website.
function check_connection () {
website=$1
error=0
for i in $website;
  do
    curl --connect-timeout 5 -Is $i 2>&1 > /dev/null
      if [ $? -ne 0 ];
        then
          let error+=1
      fi;
  done;
  echo $error
}

# Updating listbot configurations.
status=$(check_connection "get.zerohack.in")
if [ "$status" == "0" ];
  then
    echo "[*] Updating IP translation maps."
    cd /etc/listbot
    aria2c -s16 -x 16 https://get.zerohack.in/reputations/cve.json.bz2 && \
    aria2c -s16 -x 16 https://get.zerohack.in/reputations/iprep.json.bz2 && \
    bunzip2 -f *.bz2 && \
    cd /
  else
    echo "[*] Failed to update latest reputation maps. Starting with previous configurations."
fi

if [ -r $DEFAULT ]; then
    set -o allexport
    . $DEFAULT
    set +o allexport
fi

# If the user has supplied only arguments append them to `fluentd` command
if [ "${1#-}" != "$1" ]; then
    set -- fluentd "$@"
fi

# If user does not supply config file or plugins, use the default
if [ "$1" = "fluentd" ]; then
    if ! echo $@ | grep ' \-c' ; then
       set -- "$@" -c /fluentd/etc/${FLUENTD_CONF}
    fi

    if ! echo $@ | grep ' \-p' ; then
       set -- "$@" -p /fluentd/plugins
    fi
fi

exec "$@"