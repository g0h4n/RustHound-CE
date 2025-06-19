<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/g0h4n/RustHound-CE/raw/main/img/rusthoundce-transparent-dark-theme.png">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/g0h4n/RustHound-CE/raw/main/img/rusthoundce-transparent-light-theme.png">
        <img src="https://github.com/g0h4n/RustHound-CE/raw/main/img/rusthoundce-transparent-dark-theme.png" alt="rusthound-ce logo" width='250' />
    </picture>
</p>

<hr />

RustHound-CE is a cross-platform and cross-compiled BloodHound collector tool written in Rust, making it compatible with Linux, Windows, and macOS. It therefore generates all the JSON files that can be analyzed by BloodHound Community Edition. This version is only compatible with [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound). The version compatible with [BloodHound Legacy](https://github.com/BloodHoundAD/BloodHound) can be found on [NeverHack's github](https://github.com/NH-RED-TEAM/RustHound).

RustHound was created during my years as a pentester at Armature Technologies, renamed later Opencyber then NeverHack. I would like to thanks NeverHack for giving me time to research and develop the original RustHound project, which is still available on their github. We've decided to continue working together to contribute to both versions. This one will remain compatible with the community edition, and the NeverHack version with the Legacy version of BloodHound.

- [HELP.md](HELP.md) - How to compile it and how to use it?
- [CHANGELOG.md](CHANGELOG.md) - A record of all significant version changes.
- [ROADMAP.md](ROADMAP.md) - List of planned evolutions
- [LINKS.md](LINKS.md) - Useful resources

# Quick usage

## Compilation

This project can be compiled directly from `make` command like:

```bash
# Compile it for your current system
make release
# Compile it for Windows
make windows
```

Or using `docker` like below:

```bash
docker build --rm -t rusthound-ce .

# Then
docker run --rm -v $PWD:/usr/src/rusthound-ce rusthound-ce help
docker run --rm -v $PWD:/usr/src/rusthound-ce rusthound-ce release
docker run --rm -v $PWD:/usr/src/rusthound-ce rusthound-ce windows
docker run --rm -v $PWD:/usr/src/rusthound-ce rusthound-ce linux
```

## Installation

<img alt="Crates.io Version" src="https://img.shields.io/crates/v/rusthound-ce"> <img alt="Crates.io Total Downloads" src="https://img.shields.io/crates/d/rusthound-ce?color=f74c00">

```bash
# Install the libkrb5-dev dependency
sudo apt-get install libkrb5-dev

# Install and/or update RustHound-CE from cargo command
cargo install rusthound-ce
```

## Usage

Here's an example of a command to collect domain objects and obtain the zip archive containing the json files to be imported into BloodHound CE:

```bash
rusthound-ce -d DOMAIN.LOCAL -u USERNAME@DOMAIN.LOCAL -z
```

More information and examples with how to compile RustHound-CE or how to use RustHound-CE can be found directly on the [help page](HELP.md).

# Special thanks to 

[![](https://github.com/NH-RED-TEAM.png?size=50)](https://github.com/NH-RED-TEAM)
[![](https://github.com/f3rn0s.png?size=50)](https://github.com/f3rn0s)
[![](https://github.com/barney0.png?size=50)](https://github.com/barney0)
