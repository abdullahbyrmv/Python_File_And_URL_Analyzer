class Reporter:

    # Method for Displaying Metadata Information
    def display_metadata(metadata: dict, hashes: dict):
        """Display the metadata of file including file name, file size and hash values"""
        print("\nFile Metadata Information:")
        print(f"File Name: {metadata['file_name']}")
        print(f"File Size: {metadata['file_size']} bytes")
        print("File Hashes:")
        for k, v in hashes.items():
            print(f"{k.upper()}: {v}")

    # Method for Displaying PE File Analysis Results
    def display_pe_analysis(analysis: dict):
        """Display properties of PE file if provided file is PE type of file"""
        print("\nPE File Analysis:")

        # Return Errot to User if error happens
        if "error" in analysis:
            print(analysis["error"])
            return

        print(f"Entry Point: {analysis['entry_point']}")
        print(f"Image Base: {analysis['image_base']}")

        # Display Information about Imported DLLs
        print("\nImported DLLs:")
        for imp in analysis["imports"]:
            print(f"  {imp['dll']}: {', '.join(imp['functions'])}")

        # Display Information about Sections of PE File
        print("\nSections:")
        for sec in analysis["sections"]:
            print(
                f"  {sec['name']} - VA: {sec['virtual_address']}, "
                f"Size: {sec['size_of_raw_data']} bytes, Entropy: {sec['entropy']:.2f}"
            )

    # Method for Displaying VirusTotal Scan Results
    def display_virustotal_results(results: dict):
        """Display VirusTotal Vendor Scan Results"""
        print("\nVirusTotal Vendor Scan Results:")

        # Retrieve Scan Results
        vendor_scan_results = results.get("attributes", {}).get(
            "last_analysis_results"
        ) or results.get("attributes", {}).get("results")

        # If nothing Returns as Scan Result, Notify the User
        if not vendor_scan_results:
            print("\nNo detailed vendor scan results found in the response.")
            return

        # Otherwise, Return Scan Results
        for vendor, result in vendor_scan_results.items():
            category = result.get("category", "unknown")
            result_name = result.get("result", "None")
            print(f"{vendor}: {category} - {result_name}")

    # Method for Displaying Summary of Vendor Scan Results
    def display_summary(summary: dict):
        """Summarize the Vendor Scan Results"""
        print("\nSummary of Vendor Scan Results:")
        print(f"Malicious: {summary['malicious']}")
        print(f"Undetected: {summary['undetected']}")
        print(f"Type Unsupported: {summary['type-unsupported']}")
