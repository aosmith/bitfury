Bitfury Docs
============

This repository contains submodules.  You should clone with the `--recursive` flag.  Alternatively you may run `git submodule init; git submodule update;`.

This is a pretty vanilla rasbian image.  Chanes to:

```
/etc/rc.local
/miner
```

Packages installed:

```
sudo apt-get install screen python-dev libssl-dev
```

Submodule configured:
https://github.com/slush0/stratum-mining-proxy/blob/master/README.md

Starting the miner:
--------------------

Everything should start on boot.  JIC:

```
/miner/miner_start.sh
```

The miner_start script kills any existing miner, updates the codebase/settings and spawns new processes.  This includes 3 stratum proxies and a single "chainminer" instance.  At boot /etc/rc.local runs it.

Configuration is managed through this git repository.  Whenever a miner is rebooted the latest code is pulled and used.


Checking running instances:
---------------------------

You'll need to drop to root in order to see the screen sessions:

```
sudo -s
screen -list
``

There should be 4 session running at any given time.  These are named `stratum1`, `stratum2`, `stratum3`, `miner`.

