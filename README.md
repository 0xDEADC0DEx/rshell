# rshell
A simple reverse shell for Linux which can fork itself into the background + built-in encryption using libsodium. 

## Build instructions
1. Change the seed const in cryptwrapper/include/wrapper.h to something unique.
2. Build!
```
# Do an out-of-tree build.
$ mkdir build
$ cd build
$ cmake ..
$ make
```
3. Run!

Options for rshell_listener:
```
-p <port> // Changes the port to listen on.
-v // Increases verbosity of the debug output.
```

Options for rshell:
```
-i <IP> // Address to connect to. (Some machine a listener is running on)
-p <port> // The port to connect to.
-v // Increases verbosity of the debug output.
```

For testing purpose one can run both on the same machine like so:
```
$ cd build
$ rshell/rshell -i 127.0.0.1 -p 8080 -v
$ rshellserver/rshell_listen -p 8080
```
