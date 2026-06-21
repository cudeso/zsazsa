"""Tests for the unified notification dispatch model (N-1).

Verifies that _dispatch sends to channel types with a sender and reports types
without one (e.g. flowintel on the preview path) as skipped rather than
dropping them silently.

    python -m unittest tests.test_dispatcher
"""

import unittest
from types import SimpleNamespace

import config
from notifier import dispatcher


class Dispatch(unittest.TestCase):
    def setUp(self):
        self._orig_channels = config.NOTIFICATION_CHANNELS
        self._orig_instances = config.FLOWINTEL_INSTANCES
        config.NOTIFICATION_CHANNELS = [
            {"id": "mm1", "name": "MM", "type": "mattermost", "url": "x", "enabled": True},
            {"id": "em1", "name": "Mail", "type": "email", "recipient": "soc@x.test", "enabled": True},
        ]
        config.FLOWINTEL_INSTANCES = [
            {"id": "fi1", "name": "FI", "enabled": True},
        ]

    def tearDown(self):
        config.NOTIFICATION_CHANNELS = self._orig_channels
        config.FLOWINTEL_INSTANCES = self._orig_instances

    def test_mattermost_sent_and_channel_ids_passed(self):
        received = {}

        def fake_sender(channel_ids):
            received["ids"] = channel_ids
            return True

        stakeholder = SimpleNamespace(name="Acme", notification_channels=["mm1"])
        summary = dispatcher._dispatch([stakeholder], {"mattermost": fake_sender}, "rfi", "RFI-001")

        self.assertEqual(summary["sent_types"], ["mattermost"])
        self.assertEqual(summary["skipped_types"], [])
        self.assertEqual(received["ids"], ["mm1"])

    def test_email_routed_to_email_sender(self):
        received = {}

        def email_sender(channel_ids):
            received["ids"] = channel_ids
            return True

        stakeholder = SimpleNamespace(name="Acme", notification_channels=["em1"])
        summary = dispatcher._dispatch(
            [stakeholder],
            {"mattermost": lambda ids: True, "email": email_sender},
            "rfi", "RFI-001",
        )

        self.assertEqual(summary["sent_types"], ["email"])
        self.assertEqual(received["ids"], ["em1"])

    def test_mattermost_and_email_both_sent(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["mm1", "em1"])
        summary = dispatcher._dispatch(
            [stakeholder],
            {"mattermost": lambda ids: True, "email": lambda ids: True},
            "rfi", "RFI-001",
        )
        self.assertEqual(sorted(summary["sent_types"]), ["email", "mattermost"])

    def test_type_without_sender_is_skipped_not_dropped(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["flowintel:fi1"])
        # Preview path only has a mattermost sender.
        summary = dispatcher._dispatch([stakeholder], {"mattermost": lambda ids: True}, "rfi", "RFI-001")

        self.assertEqual(summary["sent_types"], [])
        self.assertEqual(summary["skipped_types"], ["flowintel"])
        self.assertEqual(summary["attempted_types"], ["flowintel"])

    def test_failed_sender_reported_as_skipped(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=["mm1"])
        summary = dispatcher._dispatch([stakeholder], {"mattermost": lambda ids: False}, "rfi", "RFI-001")
        self.assertEqual(summary["sent_types"], [])
        self.assertEqual(summary["skipped_types"], ["mattermost"])

    def test_no_channels_reports_nothing_attempted(self):
        stakeholder = SimpleNamespace(name="Acme", notification_channels=[])
        summary = dispatcher._dispatch([stakeholder], {"mattermost": lambda ids: True}, "rfi", "RFI-001")
        self.assertEqual(summary["attempted_types"], [])
        self.assertEqual(summary["sent_types"], [])


if __name__ == "__main__":
    unittest.main()
