This is a demo project that builds a GCS middleware plugin for Munki 7.

It is a port of Wade Robson's gcs-auth middleware:
https://github.com/waderobson/gcs-auth

Some unit testing is in place to confirm that given the same inputs, the Swift implementation generates the same outputs as the Python implementation. A brief test against a repo hosted on Google Cloud Storage was successful (thanks @natewalck).

The middleware plugin must be installed in `/usr/local/munki/middleware/`, and you need Munki 7.0.0.5152 or later to test.

The preferred location of the gcs.json file is `/usr/local/munki/middleware/gcs.json`, but the path `/usr/local/munki/gcs.json` (which is used by the Python implementation of this middleware) should work as well.

To build the middleware plugin and an Installer pkg that installs it, cd into this directory and run `./build_pkg.sh`. You will need a recent version of Xcode.
