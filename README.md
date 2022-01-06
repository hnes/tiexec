# TiExec

This opensource project is inspired by the [TiDB Hackathon 2021](https://tidb.io/events/hackathon2021). Here is the [RFC](RFC.md) doc of this opensource project (only Chinese version is available currently).

I would like to name this opensource project with a prefix "Ti" to show my sincere respect for the marvelous contributions they have done to the opensource community.

# Status

Prototype is ready. 

You should wait for its v1.0 release if you want to use it in production.

# Synopsis

```bash
$ tiexec /bin/echo -e "Hi, I am loaded by tiexec ❤️\nIt may try to make me more performant ☺\n"
Hi, I am loaded by tiexec ❤️
It may try to make me more performant ☺

$ tiexec /usr/local/go/bin/go version
go version go1.16.4 linux/amd64

$ tiexec /root/.cargo/bin/rustc -V
rustc 1.55.0 (c8dfcfe04 2021-09-06)

$ tiexec bin/pd-server ...
$ tiexec bin/tidb-server ...
$ tiexec bin/tikv-server ...
$ tiexec bin/tiflash/tiflash ...

$ # or even any elf you like
$ tiexec bin/prometheus/prometheus ...
$ tiexec bin/bin/grafana-server ...
```

# Description

TiExec will try to alleviate the iTLB-Cache-Miss problem of the application it loaded may face in future execution, so it will bring some direct performance improvement to those applications that are being punished by iTLB-Cache-Miss problem. Generally speaking, one program may face such iTLB-Cache-Miss if the .text segment of its elf is very large. 

For example, the .text size of some components in TiDB is from ~46MB to ~160MB, and a test in an OLTP scenario of TiDB with these components optimized by TiExec shows that it could bring about an overall 6-11% performance improvement directly.

# Build and Have a Try

WIP

# Design

WIP

# Copyright and License

Copyright (C) 2021, by Sen Han [<00hnes@gmail.com>](mailto:00hnes@gmail.com).

Under the Apache License, Version 2.0.

See the [LICENSE](LICENSE) file for details.