import unittest
from unittest.mock import patch
from metadata_retriever import MetaDataRetriever


class TestMetaDataRetriever(unittest.TestCase):
    @patch("os.path.basename", return_value="test_file.txt")
    @patch("os.path.getsize", return_value=1024)
    def test_get_info(self, mock_getsize, mock_basename):
        """Test retrieval of metadata"""
        file_path = "/path/to/test_file.txt"
        retriever = MetaDataRetriever(file_path)
        info = retriever.get_file_info()

        self.assertEqual(info["file_name"], "test_file.txt")
        self.assertEqual(info["file_size"], 1024)
        mock_basename.assert_called_with(file_path)
        mock_getsize.assert_called_with(file_path)


if __name__ == "__main__":
    unittest.main()
