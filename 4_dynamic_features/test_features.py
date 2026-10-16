import unittest

from features import build_features


class FeatureTests(unittest.TestCase):
    def test_aggregate_and_runtime_events(self):
        samples = [
            {"cpu": {"cpu_percent": 2.0}, "memory": {"pss_kb": 100.0, "rss_kb": 200.0}, "process": {"process_count": 1, "thread_count": 3}, "network": {"socket_table_rows": 0, "rx_bytes_snapshot": 10, "tx_bytes_snapshot": 5}},
            {"cpu": {"cpu_percent": 6.0}, "memory": {"pss_kb": 140.0, "rss_kb": 260.0}, "process": {"process_count": 2, "thread_count": 8}, "network": {"socket_table_rows": 1, "rx_bytes_snapshot": 30, "tx_bytes_snapshot": 6}},
        ]
        row = build_features({"sha256": "abc"}, samples, "E/Test: error\nActivityTaskManager: START")
        self.assertEqual(row["cpu_percent_mean"], 4.0)
        self.assertEqual(row["pss_kb_max"], 140.0)
        self.assertEqual(row["thread_count_max"], 8)
        self.assertEqual(row["rx_bytes_delta"], 20)
        self.assertEqual(row["network_active"], 1)
        self.assertEqual(row["activity_event_count"], 1)


if __name__ == "__main__":
    unittest.main()
