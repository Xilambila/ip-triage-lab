import contextlib
import io
import json
import unittest

from ip_triage import classify, main


class IPTriageTests(unittest.TestCase):
    def test_documentation_ranges_are_explicit(self):
        for value in ["192.0.2.10", "198.51.100.10", "203.0.113.10", "2001:db8::10"]:
            with self.subTest(value=value):
                result = classify(value)
                self.assertEqual(result["scope"], "documentation")
                self.assertEqual(result["assessment"], "not-performed")

    def test_local_and_special_ranges(self):
        for value, expected in [
            ("127.0.0.1", "loopback"), ("::1", "loopback"),
            ("10.0.0.1", "private"), ("172.16.0.1", "private"),
            ("192.168.0.1", "private"), ("fd00::1", "private"),
            ("169.254.0.1", "link-local"), ("fe80::1", "link-local"),
            ("224.0.0.1", "multicast"), ("ff02::1", "multicast"),
            ("0.0.0.0", "unspecified"), ("::", "unspecified"),
            ("100.64.0.1", "special-use"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(classify(value)["scope"], expected)

    def test_invalid_values_are_rejected(self):
        for value in ["", "invalid", "192.0.2.999", "192.0.2.1/24", "fe80::1%eth0", "192.000.2.1", "example.invalid", None]:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    classify(value)

    def test_ipv4_mapped_ipv6_exposes_embedded_scope(self):
        result = classify("::ffff:192.0.2.10")
        self.assertEqual(result["scope"], "ipv4-mapped")
        self.assertEqual(result["embedded_ipv4"]["scope"], "documentation")

    def test_normalization(self):
        result = classify(" 2001:0db8:0:0::1 ")
        self.assertEqual(result["address"], "2001:db8::1")

    def test_cli_outputs_json_and_success_status(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["192.0.2.10"]), 0)
        self.assertEqual(json.loads(output.getvalue())["network_queries"], 0)

    def test_cli_error_does_not_echo_input(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(main(["sensitive.invalid"]), 2)
        self.assertNotIn("sensitive.invalid", output.getvalue())


if __name__ == "__main__":
    unittest.main()
