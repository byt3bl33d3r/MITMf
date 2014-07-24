#!/bin/bash
echo 'Updating MITMf'
git pull
echo 'Updating the-backdoor-factory'
cd bdfactory/
git pull origin master

