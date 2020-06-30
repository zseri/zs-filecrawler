# Design decisions for upcoming zs-filecrawler 0.1.0-rc1

* port to [`sled`](https://github.com/spacejam/sled) instead
  of a raw serialized file. Version guarantees stay the same
  (e.g. no compatiblity with newer or older versions)
* use the `sled::Tree` with `name=hashes` to store `hash o file -> hash o hook` data
* recalculate file hashes on each run, trust first hash of file
* do not store `hash o file -> file paths...` anymore
* don't use a separate ingestion phase
* no more GC, users need to start fresh if they would need it
