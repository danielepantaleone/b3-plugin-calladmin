Calladmin Plugin for BigBrotherBot [![BigBrotherBot](http://i.imgur.com/7sljo4G.png)][B3]
==================================

Description
-----------

A [BigBrotherBot][B3] plugin which is capable of spamming admin requests on a Teamspeak 3 server.

Download
--------

Latest version available [here](https://github.com/danielepantaleone/b3-plugin-calladmin/archive/master.zip).

Installation
------------

* create a Admin Server Query account on your Teamspeak 3 server: [manual](http://media.teamspeak.com/ts3_literature/TeamSpeak%203%20Server%20Query%20Manual.pdf)
* copy the `calladmin` folder into `b3/extplugins`
* add to the `plugins` section of your `b3.xml` config file:

  ```xml
  <plugin name="calladmin" config="@b3/extplugins/calladmin/conf/plugin_calladmin.ini" />
  ```

In-game user guide
------------------

* **!calladmin &lt;reason&gt;** `send an admin request`

Support
-------

If you have found a bug or have a suggestion for this plugin, please report it on the [B3 forums][Support].

[B3]: http://www.bigbrotherbot.net/ "BigBrotherBot (B3)"
[Support]: http://forum.bigbrotherbot.net/plugins-by-fenix/calladmin-plugin-6649/ "Support topic on the B3 forums"

[![Build Status](https://travis-ci.org/danielepantaleone/b3-plugin-calladmin.svg?branch=master)](https://travis-ci.org/danielepantaleone/b3-plugin-calladmin)

