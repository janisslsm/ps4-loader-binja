# ps4-loader-binja

PS4 ELF/PRX loader plugin for Binary Ninja

## Installation

To install this plugin, go to Binary Ninja's plugin directory (can be found by going to Tools -> "Open Plugin Folder"), and run the following command:

```
git clone https://github.com/janisslsm/ps4-loader-binja
```

## Usage

Load a PS4 binary (.prx, .sprx, .elf) and switch over to the "PS4 Executable Format" view. For larger files, it's normal for Binary Ninja to hang for a while.

## License

This plugin is released under the [GPL3](LICENSE) license.

## Thanks
- zecoxao for [NIDs](https://github.com/zecoxao/sce_symbols)
- SocraticBliss for [ps4-module-loader](https://github.com/SocraticBliss/ps4_module_loader) as this is essentially a port of it.