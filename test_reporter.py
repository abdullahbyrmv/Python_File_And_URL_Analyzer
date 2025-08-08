import unittest
from unittest.mock import patch
from reporter import Reporter


class TestReporter(unittest.TestCase):
    @patch("builtins.print")
    def test_display_metadata(self, mock_print):
        metadata = {"file_name": "test.txt", "file_size": 1024}
        hashes = {"md5": "hash_md5", "sha256": "hash_sha256"}
        Reporter.display_metadata(metadata, hashes)
        mock_print.assert_any_call("\nFile Metadata Information:")
        mock_print.assert_any_call("File Name: test.txt")
        mock_print.assert_any_call("File Size: 1024 bytes")
        mock_print.assert_any_call("MD5: hash_md5")

    @patch("builtins.print")
    def test_display_pe_analysis(self, mock_print):
        analysis = {
            "entry_point": "0x1000",
            "image_base": "0x400000",
            "compile_time": "2023-01-01 10:00:00",
            "imports": [{"dll": "kernel32.dll", "functions": ["ExitProcess"]}],
            "sections": [
                {
                    "name": ".text",
                    "virtual_address": "0x1000",
                    "size_of_raw_data": 512,
                    "entropy": 5.00,
                }
            ],
        }
        Reporter.display_pe_analysis(analysis)
        mock_print.assert_any_call("\nPE File Analysis:")
        mock_print.assert_any_call("Entry Point: 0x1000")
        mock_print.assert_any_call(
            "  .text - VA: 0x1000, Size: 512 bytes, Entropy: 5.00"
        )

    @patch("builtins.print")
    def test_display_virustotal_results(self, mock_print):
        results = {
            "attributes": {
                "last_analysis_results": {
                    "engine1": {"category": "undetected", "result": "clean"},
                    "engine2": {"category": "malicious", "result": "trojan"},
                }
            }
        }
        Reporter.display_virustotal_results(results)
        mock_print.assert_any_call("\nVirusTotal Scan Results:")
        mock_print.assert_any_call("engine1: undetected - clean")
        mock_print.assert_any_call("engine2: malicious - trojan")

    @patch("builtins.print")
    def test_display_summary(self, mock_print):
        summary = {"malicious": 2, "undetected": 10, "type-unsupported": 5}
        Reporter.display_summary(summary)
        mock_print.assert_any_call("\nSummary of Vendor Scan Results:")
        mock_print.assert_any_call("Malicious: 2")
        mock_print.assert_any_call("Undetected: 10")
        mock_print.assert_any_call("Type Unsupported: 5")


if __name__ == "__main__":
    unittest.main()
