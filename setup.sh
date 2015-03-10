#!/usr/bin/env bash
if [[ $EUID -ne 0 ]]; then
  echo "You must be root" 2>&1
  exit 1
fi

git submodule init
git submodule update
cd libs/bdfactory/ && ./install.sh
