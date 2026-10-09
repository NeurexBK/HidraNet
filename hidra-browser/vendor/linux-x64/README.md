# Shared libraries shipped with the Linux package

## libevent-2.1.so.7

The Tor build we bundle is dynamically linked against libevent, which is not
part of a base install on most distributions. Without this file Tor dies at
startup with

    error while loading shared libraries: libevent-2.1.so.7

and the browser opens with nothing connecting — the one failure mode worse
than not shipping Tor at all, because it looks like it worked.

It goes into the Linux package next to `resources/bin/tor/tor`, and
`src/main/tor-manager.js` puts that directory on `LD_LIBRARY_PATH` when it
spawns Tor.

Version 2.1.12-stable, from Ubuntu's `libevent-2.1-7t64` package. libevent is
under the 3-clause BSD licence: https://github.com/libevent/libevent

It links only against libc, so it does not drag a distribution's other
libraries along with it.
