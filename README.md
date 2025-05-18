This is a demo project that builds a GCS middleware plugin for Munki 7.

It is a port of Wade Robson's gcs-auth middleware:
https://github.com/waderobson/gcs-auth

Though some unit testing was done to confirm that given the same inputs, the Swift implementation generates the same outputs as the Python implementation, as of May 17, 2025, this has not actually been tested against a repo hosted on Google Cloud Storage. If you test it and it works, please let me know!

The middleware plugin must be installed in /usr/local/munki/middleware/, and you need Munki 7.0.0.5139 or later to test.

To build the middleware plugin and an Installer pkg that installs it, cd into this directory and run `./build_pkg.sh`. You will need a recent version of Xcode.
