Add POST body excerpt to the HTTP log
-------------------------------------

A fork of Corelight's package - thanks Seth.

This script gives analysts the ability to peek into HTTP POST body 
and corresponding server response.  It provides this by simply 
extending the HTTP log.

Installation
------------

::

  bro-pkg refresh
  bro-pkg install srozb/log-add-http-post-bodies

Usage
-----

The HTTP log will have a new field named *post_body* and *post_resp* which will
be populated with a configurable amount of data from the beginning of every 
seen POST body.

You can redefine target list to log only communication to specific hosts/uris

::

  redef Corelight::target_list += { ["www.example.com"] = set("/api/") };

  will log every POST BODY & server response to www.example.com where URI
  contains "/api/".