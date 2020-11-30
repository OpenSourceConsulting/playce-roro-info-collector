#!/bin/bash

export WORKDIRECTORY="../info"

rm system_info_collector.spec
rm -rf ./build
rm -rf ./dist

echo "Build start"

/usr/local/bin/pyinstaller --onefile --paths=${WORKDIRECTORY} ${WORKDIRECTORY}/system_info_collector.py

# Need to configuration aws access key & secret key
#sudo aws s3 cp "./dist/system_info_collector" s3://roro-repository/scripts/ --acl public-read
