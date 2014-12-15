# mod_webgfarm
This apache module provides a HTTP interface of Gfarm File System.

## Build and Install

    $ apxs -l gfarm -c mod_webgfarm.c
    $ apxs -i -A -b webgfarm mod_webgfarm.la
`-A` option, the module is just prepared for later activation but initially disabled.
