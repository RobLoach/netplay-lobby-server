#!/bin/bash

function finish() {
  exit 0
}

wget -t 1 -T 5 -O /dev/null --no-check-certificate http://lobby.libretro.com/admin/ >/dev/null 2>&1

if [ $? != 0 ] ; then
  sleep 5
  wget -t 1 -T 5 -O /dev/null --no-check-certificate http://lobby.libretro.com/admin/ >/dev/null 2>&1

  if [ $? != 0 ] ; then
    sleep 5
    wget -t 1 -T 5 -O /dev/null --no-check-certificate http://lobby.libretro.com/admin/ >/dev/null 2>&1

    if [ $? != 0 ] ; then
      echo "restarting django."
      ~/lobby/run_django.sh
    else
      finish
    fi
  else
    finish
  fi
else
  finish
fi
