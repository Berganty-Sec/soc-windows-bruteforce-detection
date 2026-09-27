import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analisar_logins import FailedLogon, _event_from_xml, _failure_description, build_report, find_bursts, read_events


def make_event(minute, username="alice", source_ip="192.0.2.10", workstation="PC-01"):
    return FailedLogon(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=minute),
        username=username,
        source_ip=source_ip,
        workstation=workstation,
        logon_type="3",
        status="0xC000006D",
        sub_status="0xC000006A",
    )


def xml_event(event_id="4625", username="alice", system_time="2026-01-01T12:00:00.000Z"):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>{event_id}</EventID><TimeCreated SystemTime="{system_time}" /></System>
      <EventData>
        <Data Name="TargetUserName">{username}</Data>
        <Data Name="IpAddress">192.0.2.10</Data>
        <Data Name="WorkstationName">PC-01</Data>
        <Data Name="LogonType">3</Data>
        <Data Name="Status">0xC000006D</Data>
        <Data Name="SubStatus">0xC000006A</Data>
      </EventData>
    </Event>'''


class EventParsingTests(unittest.TestCase):
    def test_parses_failed_logon_fields(self):
        event = _event_from_xml(xml_event())
        self.assertIsNotNone(event)
        self.assertEqual(event.username, "alice")
        self.assertEqual(event.source_ip, "192.0.2.10")
        self.assertEqual(event.logon_type, "3")
        self.assertEqual(event.timestamp, datetime(2026, 1, 1, 12, tzinfo=timezone.utc))

    def test_ignores_other_event_ids_and_malformed_xml(self):
        self.assertIsNone(_event_from_xml(xml_event(event_id="4624")))
        self.assertIsNone(_event_from_xml("<Event>"))

    def test_parses_kerberos_failure_event(self):
        event = _event_from_xml(xml_event(event_id="4771").replace("0xC000006D", "0x18"))
        self.assertEqual(event.event_id, "4771")
        self.assertEqual(event.event_title, "Falha de pré-autenticação Kerberos")

    def test_explains_local_smartcard_pin_failure_and_missing_username(self):
        xml = xml_event().replace("alice", "-").replace("0xC000006A", "0xC0000380")
        event = _event_from_xml(xml)
        self.assertEqual(event.username, "(não informado pelo Windows)")
        self.assertIn("PIN incorreto", _failure_description(event))

    def test_ignores_successful_ntlm_validation(self):
        event = _event_from_xml(xml_event(event_id="4776").replace("0xC000006D", "0x0"))
        self.assertIsNone(event)

    def test_reads_events_from_exported_xml_file(self):
        contents = f"<Events>{xml_event()}<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4624</EventID></System></Event></Events>"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "security.xml"
            path.write_text(contents, encoding="utf-8")
            events = list(read_events(path))
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].username, "alice")


class BruteForceDetectionTests(unittest.TestCase):
    def test_report_includes_each_failure_even_below_bruteforce_threshold(self):
        events = [make_event(i) for i in range(4)]
        alerts = find_bursts(events, threshold=5, window_minutes=10, spray_threshold=5)
        report = build_report(events, alerts, "log Segurança", 5, 5, 10)
        self.assertIn("Tentativas de autenticação malsucedidas: 4", report)
        self.assertEqual(report.count("Falha de logon em "), 4)

    def test_detects_repeated_failures_for_same_account(self):
        events = [make_event(0), make_event(2), make_event(4)]
        alerts = find_bursts(events, threshold=3, window_minutes=10, spray_threshold=5)
        brute_force = [alert for alert in alerts if alert[0] == "Força bruta contra uma conta"]
        self.assertEqual(len(brute_force), 1)
        self.assertEqual(brute_force[0][1:3], ("192.0.2.10", "alice"))
        self.assertEqual(len(brute_force[0][3]), 3)

    def test_does_not_alert_below_repeated_failure_threshold(self):
        alerts = find_bursts([make_event(0), make_event(1)], 3, 10, 5)
        self.assertFalse(any(alert[0] == "Força bruta contra uma conta" for alert in alerts))

    def test_does_not_combine_attempts_outside_time_window(self):
        events = [make_event(0), make_event(11), make_event(22)]
        alerts = find_bursts(events, threshold=3, window_minutes=10, spray_threshold=5)
        self.assertEqual(alerts, [])

    def test_detects_password_spraying_from_same_origin(self):
        events = [make_event(i, username=f"user{i}") for i in range(4)]
        alerts = find_bursts(events, threshold=5, window_minutes=10, spray_threshold=4)
        spraying = [alert for alert in alerts if alert[0] == "Possível password spraying"]
        self.assertEqual(len(spraying), 1)
        self.assertEqual(spraying[0][1], "192.0.2.10")
        self.assertEqual(spraying[0][2], "user0, user1, user2, user3")

    def test_uses_workstation_when_source_ip_is_missing(self):
        events = [make_event(i, source_ip="-") for i in range(2)]
        alerts = find_bursts(events, threshold=2, window_minutes=10, spray_threshold=5)
        self.assertEqual(alerts[0][1], "PC-01")


if __name__ == "__main__":
    unittest.main()
