import unittest

import numpy as np

from app.ml.preprocess.lgbm import BASE_FEATURES
from app.pipeline.ensemble import Pipeline, lgbm_input_is_compatible, lgbm_input_is_usable, map_lgbm_attack_label
from app.schemas import ThreatClass


MODEL_CARD_LABELS = {
    0: "BENIGN",
    1: "Botnet",
    2: "DDoS",
    3: "DoS GoldenEye",
    4: "DoS Hulk",
    5: "DoS Slow",
    6: "FTP-Patator",
    7: "Portscan",
    8: "SSH-Patator",
    9: "Web Attack",
}


class FakeRegistry:
    def __init__(self, models):
        self.models = models
        self.artifacts_dir = None

    def record_inference(self, *_args):
        pass


class FakeIsolationForest:
    def decision_function(self, matrix):
        return np.zeros(len(matrix))


class FakeBinaryCalibrator:
    def __init__(self, probability=0.93, invalid=False):
        self.probability = probability
        self.invalid = invalid

    def predict_proba(self, data):
        if self.invalid:
            return np.full((len(data), 2), np.nan)
        return np.tile([1 - self.probability, self.probability], (len(data), 1))


class FakeMulticlassCalibrator:
    classes_ = np.arange(10)

    def __init__(self, class_id=0, invalid=False):
        self.class_id = class_id
        self.invalid = invalid

    def predict_proba(self, data):
        if self.invalid:
            return np.full((len(data), 10), np.nan)
        probabilities = np.full((len(data), 10), 0.02)
        probabilities[:, self.class_id] = 0.82
        return probabilities / probabilities.sum(axis=1, keepdims=True)


class FakeBeaconSession:
    def __init__(self, score):
        self.score = score

    def run(self, _outputs, _inputs):
        return [np.asarray([[self.score]], dtype=np.float32)]


class FakeBeaconCalibrator:
    def predict(self, scores):
        return scores


def make_lgbm_pipeline(class_id=0, binary_probability=0.93, invalid_multi=False, invalid_binary=False):
    models = {
        "lgbm_iforest": {
            "iforest": FakeIsolationForest(),
            "cal_bin": FakeBinaryCalibrator(binary_probability, invalid_binary),
            "cal_multi": FakeMulticlassCalibrator(class_id, invalid_multi),
            "multi_class_ids": list(range(10)),
            "multi_class_labels": MODEL_CARD_LABELS,
        }
    }
    return Pipeline(FakeRegistry(models))


def make_flow(**updates):
    flow = {name: 1.0 for name in BASE_FEATURES}
    flow.update({
        "Src IP": "192.168.73.128",
        "Src Port": 51000,
        "Dst IP": "192.168.1.157",
        "Dst Port": 5173,
        "Protocol": 6,
        "sensor_metadata": {"cicflowmeter_compatible": True, "lgbm_inputs_complete": True},
    })
    flow.update(updates)
    return flow


class AttackMappingTests(unittest.IsolatedAsyncioTestCase):
    async def test_label_mapping_only_assigns_exact_supported_subtypes(self):
        self.assertEqual(map_lgbm_attack_label("DDoS"), ThreatClass.DDOS)
        self.assertEqual(map_lgbm_attack_label("Portscan"), ThreatClass.SCAN)
        for label in ("BENIGN", "Botnet", "DoS Hulk", "FTP-Patator", "Web Attack", None):
            self.assertEqual(map_lgbm_attack_label(label), ThreatClass.ANOMALY)

    async def test_complete_packet_derived_vector_restores_scan_detection_without_iforest(self):
        flow = make_flow(sensor_metadata={"cicflowmeter_compatible": False, "lgbm_inputs_complete": True})
        self.assertFalse(lgbm_input_is_compatible(flow))
        self.assertTrue(lgbm_input_is_usable(flow))
        alert = (await make_lgbm_pipeline(class_id=7).process_batch([flow]))[0]
        self.assertEqual(alert.threat_class, ThreatClass.SCAN)
        self.assertFalse(any(score.name == "iforest" for score in alert.models))

    async def test_packet_derived_supported_attack_in_review_range_is_counted(self):
        flow = make_flow(sensor_metadata={"cicflowmeter_compatible": False, "lgbm_inputs_complete": True})
        alert = (await make_lgbm_pipeline(class_id=7, binary_probability=0.01).process_batch([flow]))[0]
        self.assertEqual(alert.threat_class, ThreatClass.SCAN)
        self.assertEqual([score.label for score in alert.models], ["ATTACK", "Portscan"])

    async def test_each_review_qualified_attack_flow_has_its_own_alert(self):
        flows = [make_flow(
            **{"Src Port": 51000 + index},
            sensor_metadata={"cicflowmeter_compatible": False, "lgbm_inputs_complete": True},
        ) for index in range(5)]
        alerts = await make_lgbm_pipeline(class_id=7, binary_probability=0.01).process_batch(flows)
        self.assertEqual(len(alerts), len(flows))
        self.assertEqual([alert.threat_class for alert in alerts], [ThreatClass.SCAN] * len(flows))

    async def test_documented_missing_syn_window_still_allows_supported_attack(self):
        flow = make_flow(
            **{
                "FWD Init Win Bytes": None,
                "sensor_metadata": {
                    "feature_profile": "packet-derived-lab-v1",
                    "cicflowmeter_compatible": False,
                    "lgbm_inputs_complete": False,
                    "missing_features": ["FWD Init Win Bytes (TCP SYN was not observed)"],
                },
            }
        )
        self.assertTrue(lgbm_input_is_usable(flow))
        alert = (await make_lgbm_pipeline(class_id=7).process_batch([flow]))[0]
        self.assertEqual(alert.threat_class, ThreatClass.SCAN)

    async def test_binary_attack_with_benign_subtype_becomes_generic_anomaly(self):
        alerts = await make_lgbm_pipeline(class_id=0).process_batch([make_flow()])
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.threat_class, ThreatClass.ANOMALY)
        self.assertAlmostEqual(alert.confidence, 0.93)
        self.assertTrue(any("predicted BENIGN" in note for note in alert.evidence["assessment_notes"]))
        self.assertEqual([score.label for score in alert.models], ["ATTACK", "BENIGN"])
        self.assertTrue({"alert_id", "threat_class", "confidence", "models", "evidence"}.issubset(alert.model_dump(mode="json")))

    async def test_known_benign_http_tcp_flow_with_benign_outputs_does_not_alert(self):
        flow = make_flow(**{
            "Flow Duration": 218.0,
            "Total Fwd Packet": 2.0,
            "Total Length of Fwd Packet": 76.0,
            "Fwd Packet Length Max": 38.0,
            "Fwd Packet Length Min": 38.0,
            "Fwd Packet Length Mean": 38.0,
            "Fwd Packet Length Std": 0.0,
        })
        alerts = await make_lgbm_pipeline(class_id=0, binary_probability=0.001).process_batch([flow])
        self.assertEqual(alerts, [])

    async def test_verified_multiclass_predictions_keep_their_exact_supported_labels(self):
        ddos = (await make_lgbm_pipeline(class_id=2).process_batch([make_flow()]))[0]
        scan = (await make_lgbm_pipeline(class_id=7).process_batch([make_flow()]))[0]
        self.assertEqual(ddos.threat_class, ThreatClass.DDOS)
        self.assertEqual(scan.threat_class, ThreatClass.SCAN)
        self.assertAlmostEqual(ddos.confidence, ddos.models[1].score)
        self.assertAlmostEqual(scan.confidence, scan.models[1].score)

    async def test_supported_ddos_with_positive_beacon_keeps_ddos(self):
        registry = make_lgbm_pipeline(class_id=2).registry
        registry.models["beacon_cnn"] = {
            "session": FakeBeaconSession(0.96), "input_name": "packet_seq", "calibrator": FakeBeaconCalibrator(),
        }
        alert = (await Pipeline(registry).process_batch([make_flow(
            sensor_metadata={"cicflowmeter_compatible": False, "lgbm_inputs_complete": True},
            pkt_sizes=[60, 1000], pkt_iats=[0.0, 1000.0], pkt_flags=[2, 24],
        )]))[0]
        self.assertEqual(alert.threat_class, ThreatClass.DDOS)
        self.assertEqual([score.name for score in alert.models], ["lgbm_binary", "lgbm_multi", "beacon_cnn"])

    async def test_corroborated_beacon_is_reported_as_c2_beacon(self):
        registry = make_lgbm_pipeline(class_id=1).registry
        registry.models["beacon_cnn"] = {
            "session": FakeBeaconSession(0.96), "input_name": "packet_seq", "calibrator": FakeBeaconCalibrator(),
        }
        flow = make_flow(
            sensor_metadata={"cicflowmeter_compatible": False, "lgbm_inputs_complete": True},
            pkt_sizes=[60, 1000], pkt_iats=[0.0, 1000.0], pkt_flags=[2, 24],
        )
        alert = (await Pipeline(registry).process_batch([flow]))[0]
        self.assertEqual(alert.threat_class, ThreatClass.C2_BEACON)
        self.assertAlmostEqual(alert.confidence, 0.96, places=6)

    async def test_unsupported_dos_subtype_is_not_mislabeled_as_ddos(self):
        alert = (await make_lgbm_pipeline(class_id=4).process_batch([make_flow()]))[0]
        self.assertEqual(alert.threat_class, ThreatClass.ANOMALY)
        self.assertEqual(alert.models[1].label, "DoS Hulk")

    async def test_invalid_subtype_output_does_not_create_a_guessed_label(self):
        alert = (await make_lgbm_pipeline(invalid_multi=True).process_batch([make_flow()]))[0]
        self.assertEqual(alert.threat_class, ThreatClass.ANOMALY)
        self.assertEqual([score.label for score in alert.models], ["ATTACK"])
        self.assertTrue(any("missing or invalid" in note for note in alert.evidence["assessment_notes"]))

    async def test_invalid_binary_output_does_not_generate_an_attack_alert(self):
        alerts = await make_lgbm_pipeline(invalid_binary=True).process_batch([make_flow()])
        self.assertEqual(alerts, [])

    async def test_beacon_model_output_without_lgbm_corroboration_does_not_alert(self):
        registry = FakeRegistry({"beacon_cnn": {
            "session": FakeBeaconSession(0.96), "input_name": "packet_seq", "calibrator": FakeBeaconCalibrator(),
        }})
        flow = {
            "Src IP": "192.168.73.128", "Src Port": 51000, "Dst IP": "192.168.1.157", "Dst Port": 5173,
            "Protocol": 6, "pkt_sizes": [60, 1000], "pkt_iats": [0.0, 1000.0], "pkt_flags": [2, 24],
        }
        self.assertEqual(await Pipeline(registry).process_batch([flow]), [])

    async def test_separate_connections_do_not_imply_scan_without_portscan_output(self):
        flows = [make_flow(**{"Src Port": 51000 + index}) for index in range(3)]
        alerts = await make_lgbm_pipeline(class_id=0).process_batch(flows)
        self.assertEqual([alert.threat_class for alert in alerts], [ThreatClass.ANOMALY] * 3)


if __name__ == "__main__":
    unittest.main()
