# How to build

## Run build script.
> run script '/script/build.sh'

## Result directory structure
```shell script
 script
    ├── build (build info..)
    │   └── linux_info_collector
    │   
    ├── build.sh (build script)
    ├── dist
    │   └── linux_info_collector (result executor)
    └── linux_info_collector.spec (spec file)
```
## Run options

* -H : host
* -P : port
* -u : username
* -p : password
* -T : target os type (linux, unix(only aix))
* -L : loggin path

For example.
```shell script
linux_info_collector -H 172.143.0.2 -P 22 -u admin -p admin -T linux -L /roro/assessments/server/
```

