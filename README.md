# rshell
A simple reverse shell for linux which can fork its self into the background with built-in encryption based on libsodium. 

## Build instructions
* Change the seed const in cryptwrapper/include/wrapper.h to something unique.
* Build!
```
$ mkdir build && cd build && cmake .. && make
```
* Deploy!
