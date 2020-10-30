#!/bin/bash

export WORKDIRECTORY="../info"

rm linux_info_collector.spec
rm -rf ./build
rm -rf ./dist

echo "Build start"

/usr/local/bin/pyinstaller --onefile ${WORKDIRECTORY}/linux_info_collector.py
