#
# Calladmin Plugin for BigBrotherBot(B3) (www.bigbrotherbot.net)
# Copyright (C) 2013 Daniele Pantaleone <fenix@bigbrotherbot.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

import time
from mock import Mock
from mock import call
from mockito import when
from textwrap import dedent
from tests import CalladminTestCase
from tests import logging_disabled
from calladmin import CalladminPlugin
from b3.config import CfgConfigParser

class Test_commands(CalladminTestCase):

    def setUp(self):
        CalladminTestCase.setUp(self)
        self.conf = CfgConfigParser()
        self.conf.loadFromString(dedent(r"""
            [teamspeak]
            ip: 127.0.0.1
            port: 10011
            serverid: 1
            username: fakeusername
            password: fakepassword
            msg_groupid: -1

            [settings]
            treshold: 3600
            useirc: no

            [commands]
            calladmin: user
        """))

        self.p = CalladminPlugin(self.console, self.conf)
        self.p.onLoadConfig()
        self.p.onStartup()

        with logging_disabled():
            from b3.fake import FakeClient

        self.mike = FakeClient(console=self.console, name="Mike", guid="mikeguid", groupBits=1)
        self.bill = FakeClient(console=self.console, name="Bill", guid="billguid", groupBits=16)

    ####################################################################################################################
    ##                                                                                                                ##
    ##  TEST EVT_CLIENT_CONNECT                                                                                       ##
    ##                                                                                                                ##
    ####################################################################################################################

    def test_admin_connect_with_active_request(self):
        # GIVEN
        self.p.send_teamspeak_message = Mock()
        self.mike.connects('1')
        self.mike.says('!calladmin test reason')
        # WHEN
        self.mike.clearMessageHistory()
        self.bill.connects('2')
        # THEN
        self.p.send_teamspeak_message.assert_has_calls([call('[B][ADMIN REQUEST][/B] [B]Mike[/B] requested an admin on [B]Test Server[/B] : [B]test reason[/B]')])
        self.p.send_teamspeak_message.assert_has_calls([call('[B][ADMIN REQUEST][/B] [B]Bill [40][/B] connected to [B]Test Server[/B]')])
        self.assertListEqual(['[ADMIN ONLINE] Bill [40]'], self.mike.message_history)
        self.assertIsNone(self.p.adminRequest)

    ####################################################################################################################
    ##                                                                                                                ##
    ##  TEST EVT_CLIENT_DISCONNECT                                                                                    ##
    ##                                                                                                                ##
    ####################################################################################################################

    def test_client_disconnect_with_active_request(self):
        # GIVEN
        self.p.send_teamspeak_message = Mock()
        self.mike.connects('1')
        self.mike.says('!calladmin test reason')
        # WHEN
        self.mike.disconnects()
        # THEN
        self.p.send_teamspeak_message.assert_has_calls([call('[B][ADMIN REQUEST][/B] [B]Mike[/B] disconnected from [B]Test Server[/B]')])
        self.assertIsNone(self.p.adminRequest)
