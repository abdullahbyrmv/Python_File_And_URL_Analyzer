import unittest
from unittest.mock import patch, MagicMock
from pe_analyzer import PEAnalyzer


class TestPEAnalyzer(unittest.TestCase):
    @patch("pe_analyzer.pefile")
    def test_analyze_success(self, mock_pefile):
        """Test PE file analysis functionality"""
        file_path = "test_pe.exe"
        analyzer = PEAnalyzer(file_path)

        # Mock the pefile.PE object and its attributes
        mock_pe = MagicMock()
        mock_pefile.PE.return_value = mock_pe

        # Mock IMAGE_IMPORT_DESCRIPTOR
        mock_dll_entry = MagicMock()
        mock_dll_entry.dll.decode.return_value = "KERNEL32.dll"
        mock_func_import = MagicMock()
        mock_func_import.name.decode.return_value = "CreateFileW"
        mock_dll_entry.imports = [mock_func_import]
        mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_dll_entry]

        # Mock sections
        mock_section = MagicMock()
        mock_section.Name.decode.return_value = ".text"
        mock_section.VirtualAddress = 0x1000
        mock_section.SizeOfRawData = 1000
        mock_section.get_entropy.return_value = 5.0
        mock_pe.sections = [mock_section]

        # Mock headers
        mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1234
        mock_pe.OPTIONAL_HEADER.ImageBase = 0x400000
        mock_pe.FILE_HEADER.TimeDateStamp = 1625097600  # A timestamp

        result = analyzer.analyze_pe_file()

        self.assertIn("entry_point", result)
        self.assertEqual(result["entry_point"], "0x1234")
        self.assertEqual(len(result["imports"]), 1)
        self.assertEqual(result["imports"][0]["dll"], "KERNEL32.dll")
        self.assertEqual(len(result["sections"]), 1)
        self.assertEqual(result["sections"][0]["name"], ".text")

    @patch("pe_analyzer.pefile")
    def test_analyze_failure(self, mock_pefile):
        """Test exception case where file is not PE type of file"""
        file_path = "corrupt_file.exe"
        analyzer = PEAnalyzer(file_path)

        mock_pefile.PE.side_effect = Exception("Invalid PE file")

        result = analyzer.analyze_pe_file()

        self.assertIn("error", result)
        self.assertEqual(result["error"], "PE analysis failed: Invalid PE file")


if __name__ == "__main__":
    unittest.main()
