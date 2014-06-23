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

            [settings]
            treshold: 3600

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
    ##  TEST CMD CALLADMIN                                                                                            ##
    ##                                                                                                                ##
    ####################################################################################################################

    def test_cmd_calladmin_no_arguments(self):
        # GIVEN
        self.mike.connects('1')
        # WHEN
        self.mike.clearMessageHistory()
        self.mike.says("!calladmin")
        # THEN
        self.assertListEqual(['missing data, try !help calladmin'], self.mike.message_history)
        self.assertIsNone(self.p.adminRequest)

    def test_cmd_calladmin_failed(self):
        # GIVEN
        self.mike.connects('1')
        when(self.p).send_teamspeak_message(self.p.patterns['p3'] % ('Mike', 'Test Server', 'test reason')).thenReturn(False)
        # WHEN
        self.mike.clearMessageHistory()
        self.mike.says("!calladmin test reason")
        # THEN
        self.assertListEqual(['Admin request failed: try again in few minutes'], self.mike.message_history)
        self.assertIsNone(self.p.adminRequest)

    def test_cmd_calladmin(self):
        # GIVEN
        self.mike.connects('1')
        when(self.p).send_teamspeak_message(self.p.patterns['p3'] % ('Mike', 'Test Server', 'test reason')).thenReturn(True)
        # WHEN
        self.mike.clearMessageHistory()
        self.mike.says("!calladmin test reason")
        # THEN
        self.assertListEqual(['Admin request sent: an admin will connect as soon as possible'], self.mike.message_history)
        self.assertIsInstance(self.p.adminRequest, dict)

    def test_cmd_calladmin_with_active_request(self):
        # GIVEN
        self.mike.connects('1')
        self.p.adminRequest = { 'client': self.mike, 'reason': 'test reason', 'time': int(time.time()) - 60 }
        # WHEN
        self.mike.clearMessageHistory()
        self.mike.says("!calladmin test reason")
        # THEN
        self.assertListEqual(['Admin request aborted: already sent 1 minute ago'], self.mike.message_history)
        self.assertIsNotNone(self.p.adminRequest)

    def test_cmd_calladmin_with_inactive_request(self):
        # GIVEN
        self.mike.connects('1')
        self.p.adminRequest = { 'client': self.mike, 'reason': 'test reason', 'time': int(time.time()) - 6000 }
        when(self.p).send_teamspeak_message(self.p.patterns['p3'] % ('Mike', 'Test Server', 'test reason')).thenReturn(True)
        # WHEN
        self.mike.clearMessageHistory()
        self.mike.says("!calladmin test reason")
        # THEN
        self.assertListEqual(['Admin request sent: an admin will connect as soon as possible'], self.mike.message_history)
        self.assertIsInstance(self.p.adminRequest, dict)

    def test_cmd_calladmin_with_admin_online(self):
        # GIVEN
        self.mike.connects('1')
        self.bill.connects('2')
        # WHEN
        self.mike.clearMessageHistory()
        self.mike.says("!calladmin test reason")
        # THEN
        self.assertListEqual(['Admin already online: Bill [40]'], self.mike.message_history)
        self.assertIsNone(self.p.adminRequest)