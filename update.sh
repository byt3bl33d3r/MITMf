#!/usr/bin/env bash
if [[ $EUID -ne 0 ]]; then
  echo "You must root" 2>&1
  exit 1
fi

echo 'Updating MITMf'
git pull
echo 'Updating the-backdoor-factory'
cd libs/bdfactory/
git pull origin master
./update.sh
