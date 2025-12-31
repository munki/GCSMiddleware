> **Maintainer needed**  
> This middleware was ported from Python to Swift for Munki 7 by Greg Neagle. However, Greg does not actually use this middleware and is not particularly motivated to support it. If you or your organization rely on this middleware, please consider taking over the responsibility for maintaining it.

This is a project that builds a GCS middleware plugin for Munki 7.

It is a port of Wade Robson's gcs-auth middleware:
https://github.com/waderobson/gcs-auth

Some unit testing is in place to confirm that given the same inputs, the Swift implementation generates the same outputs as the Python implementation. A brief test against a repo hosted on Google Cloud Storage was successful (thanks @natewalck).

This middleware plugin requires Munki 7.0.0.5152 or later.

Configuration is the same as the earlier Python version:
- Copy the service account json keystore file to `/usr/local/munki/middleware/gcs.json`. Ensure it is named exactly "gcs.json".
- Change your repo to point to your Google Storage bucket.
```
    sudo defaults write /Library/Preferences/ManagedInstalls SoftwareRepoURL  "https://storage.googleapis.com/<bucket goes here>"
```

The preferred location of the gcs.json file is `/usr/local/munki/middleware/gcs.json`, but the path `/usr/local/munki/gcs.json` (which is used by the Python implementation of this middleware) should work as well.

You may download an installer pkg for the most recent release of the plugin [here](https://github.com/munki/GCSMiddleware/releases).

To build the middleware plugin and an Installer pkg that installs it, `git clone` this project, `cd` into the directory containing the GCSMiddleware files, and run `./build_pkg.sh`. You will need a recent version of Xcode.
