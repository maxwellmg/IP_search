import ipaddress
import unittest

from ipintel import local
from ipintel.compare import Claims, evaluate
from ipintel.model import Section


def facts(sec):
    return {f.key: f.value for f in sec.facts}


class LocalTests(unittest.TestCase):
    def test_teredo_rfc4380_example(self):
        f = facts(local.analyze(ipaddress.ip_address("2001:0:4136:e378:8000:63bf:3fff:fdd2")))
        self.assertEqual(f["teredo_server"], "65.54.227.120")
        self.assertEqual(f["embedded_ipv4 (Teredo client, RFC 4380)"], "192.0.2.45")
        self.assertEqual(f["teredo_client_port"], 40000)

    def test_eui64_mac(self):
        f = facts(local.analyze(ipaddress.ip_address("2001:db8::0211:22ff:fe33:4455")))
        self.assertEqual(f["eui64_mac"], "00:11:22:33:44:55")

    def test_scopes(self):
        self.assertEqual(local.classify_scope(ipaddress.ip_address("100.64.1.1")),
                         "shared (carrier-grade NAT, RFC 6598)")
        self.assertTrue(local.classify_scope(ipaddress.ip_address("10.1.2.3")).startswith("private"))
        self.assertEqual(local.classify_scope(ipaddress.ip_address("8.8.8.8")), "global")


class CompareTests(unittest.TestCase):
    def _geo(self, country, tz, lat, lon):
        s = Section("Geolocation: ip-api.com")
        s.raw.update(country=country, timezone=tz, lat=lat, lon=lon, org_text="Comcast Cable")
        return s

    def test_timezone_and_country_mismatch(self):
        sections = {"Geolocation: ip-api.com": self._geo("NL", "Europe/Amsterdam", 52.37, 4.9)}
        sig = evaluate(sections, Claims(country="US", timezone="America/Chicago", isp="Comcast"))
        msgs = " ".join(s.message for s in sig)
        self.assertIn("Claimed country US", msgs)
        self.assertIn("timezone", msgs)
        self.assertNotIn("Claimed ISP", msgs)

    def test_consistent_claims_are_quiet(self):
        sections = {"Geolocation: ip-api.com": self._geo("US", "America/Chicago", 30.27, -97.74)}
        sig = evaluate(sections, Claims(country="us", timezone="America/Chicago", lat=30.3, lon=-97.7))
        self.assertEqual(sig, [])


if __name__ == "__main__":
    unittest.main()
