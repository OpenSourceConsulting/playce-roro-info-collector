#!/bin/bash

export WORKDIRECTORY="../info"

rm system_info_collector.spec
rm -rf ./build
rm -rf ./dist

echo "Build start"

/usr/local/bin/pyinstaller --onefile --paths=${WORKDIRECTORY} ${WORKDIRECTORY}/system_info_collector.py
