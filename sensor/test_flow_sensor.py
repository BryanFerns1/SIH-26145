"""Unit checks for feature derivation; these records are never exported."""

import argparse
import ipaddress
import time
import unittest
from types import SimpleNamespace

from scapy.all import Ether, IP, TCP

from flow_sensor import FlowState, LabFlowSensor, private_address


class PrivateLabAddressTests(unittest.TestCase):
    def test_accepts_private_lab_address(self):
        self.assertEqual(str(private_address("10.0.0.8")), "10.0.0.8")

    def test_rejects_public_address(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            private_address("8.8.8.8")


class FlowFeatureTests(unittest.TestCase):
    def test_derives_packet_observed_forward_features(self):
        flow = FlowState("10.0.0.2", "10.0.0.8", 51000, 5173, 6, 100.0, 100.0)
        flow.add(100.0, 60, 0, 60, 0x02, 64240, None)
        flow.add(100.001, 1000, 946, 54, 0x18, 64240, None)

        record = flow.to_record("unit-check")
        self.assertEqual(record["Total Fwd Packet"], 2)
        self.assertEqual(record["Total Length of Fwd Packet"], 1060)
        self.assertAlmostEqual(record["Flow Duration"], 1000.0)
        self.assertEqual(record["FWD Init Win Bytes"], 64240)
        self.assertEqual(record["pkt_flags"], [0x02, 0x18])
        self.assertTrue(record["sensor_metadata"]["lgbm_inputs_complete"])
        self.assertFalse(record["sensor_metadata"]["cicflowmeter_compatible"])
        self.assertEqual(record["sensor_metadata"]["feature_profile"], "packet-derived-lab-v1")

    def test_does_not_invent_a_missing_tcp_initial_window(self):
        flow = FlowState("10.0.0.2", "10.0.0.8", 51000, 5173, 6, 100.0, 100.0)
        flow.add(100.0, 1000, 946, 54, 0x18, 64240, None)

        record = flow.to_record("unit-check")
        self.assertIsNone(record["FWD Init Win Bytes"])
        self.assertFalse(record["sensor_metadata"]["lgbm_inputs_complete"])
        self.assertIn("FWD Init Win Bytes (TCP SYN was not observed)", record["sensor_metadata"]["missing_features"])

    def test_capture_parser_keeps_only_configured_target_and_port(self):
        args = SimpleNamespace(
            target=ipaddress.ip_address("192.168.10.5"),
            port=5173,
            source_network=None,
            flow_timeout=5.0,
            active_timeout=60.0,
        )
        sensor = LabFlowSensor(args)
        now = time.time()
        allowed = Ether() / IP(src="10.0.0.2", dst="192.168.10.5") / TCP(sport=51000, dport=5173, flags="S", window=64240)
        allowed.time = now
        sensor.handle_packet(allowed)
        self.assertEqual(sensor.packets_seen, 1)
        self.assertEqual(len(sensor.flows), 1)

        wrong_port = Ether() / IP(src="10.0.0.2", dst="192.168.10.5") / TCP(sport=51001, dport=22, flags="S")
        wrong_port.time = now
        sensor.handle_packet(wrong_port)
        wrong_target = Ether() / IP(src="10.0.0.2", dst="192.168.10.6") / TCP(sport=51002, dport=5173, flags="S")
        wrong_target.time = now
        sensor.handle_packet(wrong_target)
        self.assertEqual(sensor.packets_seen, 1)
        self.assertEqual(len(sensor.flows), 1)


if __name__ == "__main__":
    unittest.main()
