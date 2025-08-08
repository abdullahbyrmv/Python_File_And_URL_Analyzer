import unittest
from unittest.mock import patch, MagicMock
from virustotal import VirusTotal


class TestVirusTotal(unittest.TestCase):
    def setUp(self):
        self.api_key = "test_api_key"
        self.virustotal = VirusTotal(self.api_key)

    @patch("requests.post")
    def test_upload_file_success(self, mock_post):
        """Test file upload functionality"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "analysis_id"}}
        mock_post.return_value = mock_response

        with patch("builtins.open", new_callable=unittest.mock.mock_open):
            result = self.virustotal.upload_file("test.exe")
            self.assertEqual(result, {"type": "analysis", "id": "analysis_id"})

    @patch("requests.post")
    @patch("virustotal.VirusTotal._get_sha256", return_value="sha256_hash")
    @patch.object(
        VirusTotal, "query_by_hash", return_value={"id": "existing_file_data"}
    )
    def test_upload_file_conflict(self, mock_query_by_hash, mock_get_sha256, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 409
        mock_post.return_value = mock_response

        with patch("builtins.open", new_callable=unittest.mock.mock_open):
            result = self.virustotal.upload_file("test.exe")
            self.assertEqual(
                result, {"type": "file", "data": {"id": "existing_file_data"}}
            )

    @patch("requests.post")
    def test_submit_url_success(self, mock_post):
        """Test URL submission functionality"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "analysis_id"}}
        mock_post.return_value = mock_response

        analysis_id = self.virustotal.submit_url("http://testurl.com")
        self.assertEqual(analysis_id, "analysis_id")

    @patch("requests.get")
    def test_get_scan_results_completed(self, mock_get):
        """Test the retrieval of scan results"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"attributes": {"status": "completed", "results": {}}}
        }
        mock_get.return_value = mock_response

        results = self.virustotal.get_scan_results("analysis_id")
        self.assertIn("attributes", results)
        self.assertEqual(results["attributes"]["status"], "completed")
        mock_get.assert_called_once()

    @patch("requests.get")
    @patch("time.sleep")
    def test_get_scan_results_pending(self, mock_sleep, mock_get):
        """Test retrieval of scan results when it is still pending"""
        mock_pending_response = MagicMock()
        mock_pending_response.status_code = 200
        mock_pending_response.json.return_value = {
            "data": {"attributes": {"status": "queued"}}
        }

        mock_completed_response = MagicMock()
        mock_completed_response.status_code = 200
        mock_completed_response.json.return_value = {
            "data": {"attributes": {"status": "completed", "results": {}}}
        }

        mock_get.side_effect = [mock_pending_response, mock_completed_response]

        results = self.virustotal.get_scan_results("analysis_id")
        self.assertIn("attributes", results)
        self.assertEqual(results["attributes"]["status"], "completed")
        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called_with(30)

    def test_summarize_results_file_scan(self):
        """Test summarizing results from a file scan"""
        results = {
            "attributes": {
                "results": {
                    "engine1": {"category": "malicious"},
                    "engine2": {"category": "undetected"},
                    "engine3": {"category": "malicious"},
                }
            }
        }
        summary = self.virustotal.summarize_results(results)
        self.assertEqual(summary["malicious"], 2)
        self.assertEqual(summary["undetected"], 1)

    def test_summarize_results_hash_lookup(self):
        """Test summarizing results from a hash lookup"""
        results = {
            "attributes": {
                "last_analysis_results": {
                    "engine1": {"category": "malicious"},
                    "engine2": {"category": "undetected"},
                    "engine3": {"category": "type-unsupported"},
                }
            }
        }
        summary = self.virustotal.summarize_results(results)
        self.assertEqual(summary["malicious"], 1)
        self.assertEqual(summary["undetected"], 1)
        self.assertEqual(summary["type-unsupported"], 1)

    @patch("requests.get")
    def test_query_by_hash_success(self, mock_get):
        """Test querying by hash with a successful response"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"id": "test_hash"}}
        mock_get.return_value = mock_response

        data = self.virustotal.query_by_hash("test_hash")
        self.assertIsNotNone(data)
        self.assertEqual(data["id"], "test_hash")


if __name__ == "__main__":
    unittest.main()
