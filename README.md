# Lumination

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

Lumination is a *very* basic library to display network connections. The goal is for it to be a simpler version of `netstat` and to be cross platform.

It currently supports:
- Windows
- macOS
- Linux

This library would have been impossible without prior work done by other libraries:
- [listeners](https://github.com/GyulyVGC/listeners) by GyulyVGC
- [nestat2-rs](https://github.com/ohadravid/netstat2-rs) by ohadravid

There is an example file if you want to try the library out:

```
sudo ./lumos
Run with sudo/admin if you want to see all connections!

State: Established - Remote IP: 140.82.113.25:443 - Local IP: 192.168.1.208:49838 - Protocol: Tcp - Process: GitHub Desktop Helper (PID:88075)
State: Established - Remote IP: 34.107.243.93:443 - Local IP: 192.168.1.208:49806 - Protocol: Tcp - Process: firefox (PID:13891)
State: Listen - Remote IP: 0.0.0.0:0 - Local IP: 127.0.0.1:49394 - Protocol: Tcp - Process: GitHub Desktop Helper (Renderer (PID:88076)
State: TimeWait - Remote IP: 17.248.228.71:443 - Local IP: 192.168.1.208:65454 - Protocol: Tcp - Process: syspolicyd (PID:468)
State: Established - Remote IP: 140.82.112.26:443 - Local IP: 192.168.1.208:65451 - Protocol: Tcp - Process: com.apple.WebKit.Networking (PID:5017)
State: Established - Remote IP: 140.82.113.26:443 - Local IP: 192.168.1.208:65447 - Protocol: Tcp - Process: com.apple.WebKit.Networking (PID:5017)
State: Established - Remote IP: 140.82.113.25:443 - Local IP: 192.168.1.208:65435 - Protocol: Tcp - Process: com.apple.WebKit.Networking (PID:5017)
State: Established - Remote IP: 140.82.113.25:443 - Local IP: 192.168.1.208:65424 - Protocol: Tcp - Process: com.apple.WebKit.Networking (PID:5017)
State: Established - Remote IP: 140.82.113.25:443 - Local IP: 192.168.1.208:65406 - Protocol: Tcp - Process: com.apple.WebKit.Networking (PID:5017)
State: Established - Remote IP: 140.82.112.25:443 - Local IP: 192.168.1.208:65398 - Protocol: Tcp - Process: com.apple.WebKit.Networking (PID:5017)
```