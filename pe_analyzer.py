import pefile


class PEAnalyzer:

    # Constructor of PEAnalyzer Class
    def __init__(self, file_path: str):
        self.file_path = file_path

    def analyze_pe_file(self):
        """Analyze the PE file and retrieve all the essential information about the file"""
        try:
            pe = pefile.PE(self.file_path)

            # Retrieve Information about the Imports of PE File (DLLs and Functions)
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode()
                    functions = [
                        imp.name.decode() if imp.name else "ordinal"
                        for imp in entry.imports
                    ]
                    imports.append({"dll": dll_name, "functions": functions})

            # Retrieve Information about the Sections of PE File Including name, virtual_address, size_of_raw_data and entropy
            sections = [
                {
                    "name": s.Name.decode().strip("\x00"),
                    "virtual_address": hex(s.VirtualAddress),
                    "size_of_raw_data": s.SizeOfRawData,
                    "entropy": s.get_entropy(),
                }
                for s in pe.sections
            ]

            # Return the information about the entrypoint of file, load address of file, imports and sections of file
            return {
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "imports": imports,
                "sections": sections,
            }

        # Print Message that PE Analysis Failed
        except Exception as e:
            return {"error": f"PE analysis failed: {str(e)}"}
