import os
import threading
import subprocess

from hash_retriever import HashRetriever
from metadata_retriever import MetaDataRetriever
from pe_analyzer import PEAnalyzer
from virustotal import VirusTotal
from reporter import Reporter


class FileandURLAnalysisApp:

    # Constructor of FileandURLAnalysisApp Class
    def __init__(self, file_path: str, virustotal_api_key: str):
        self.file_path = file_path
        self.virustotal = VirusTotal(virustotal_api_key)
        self.virustotal_results = None

    # Method for Performing Local File Analysis
    def local_analysis(self):
        """Method for local file analysis"""

        # Retrieve MetaData of File
        metadata = MetaDataRetriever(self.file_path).get_file_info()

        # Retrieve Hash Values
        hash_values = HashRetriever(self.file_path).compute_hash_values()

        # Retrieve PE Analysis Results if Provided file is PE type file
        pe_analysis_result = PEAnalyzer(self.file_path).analyze_pe_file()

        # Display MetaData and PE Analysis Results
        Reporter.display_metadata(metadata, hash_values)
        Reporter.display_pe_analysis(pe_analysis_result)

    # Method for Performing VirusTotal Scan
    def virustotal_scan(self):
        """Perform VirusTotal Scan and Retrieve Results"""
        print("\nSubmitting to VirusTotal for Scanning")

        upload_result = self.virustotal.upload_file(self.file_path)

        # If Analyzed File Results are New in Database, then apply "https://www.virustotal.com/api/v3/analyses/id" endpoint to Fetch Scan Results
        if upload_result["type"] == "analysis":
            analysis_id = upload_result["id"]
            print(f"Analysis ID: {analysis_id}")
            virustotal_scan_results = self.virustotal.get_scan_results(analysis_id)

        # If Results already Exists in Database, then Retrieve the Results
        elif upload_result["type"] == "file":
            print("Retrieving existing file scan results")
            virustotal_scan_results = upload_result["data"]
            self.virustotal_scan_results = virustotal_scan_results

        # Display VirusTotal ScanResults
        Reporter.display_virustotal_results(virustotal_scan_results)

        # Retrieve Summary of Scan and Display it to User
        summary = self.virustotal.summarize_results(virustotal_scan_results)
        Reporter.display_summary(summary)

    # Method for Achieving Multithread Support
    def run(self):
        """Run Method for Enabling Multithread Support"""
        # Start local analysis in its own thread
        local_thread = threading.Thread(target=self.local_analysis)
        local_thread.start()

        # Start VirusTotal scan in seperate thread
        vt_thread = threading.Thread(target=self.virustotal_scan)
        vt_thread.start()

        # Wit for both to complete
        local_thread.join()
        vt_thread.join()


# Method for Retrieving SHA256 Hash of File if User Wants to Analyze the File Using the Hash but do not know the hash value
def get_hash_from_file_powershell(file_path):
    """Retrieve the hash of file if user do not know the hash"""

    # Run Powershell Command Get-FileHash to Retrieve the SHA256 Hash of Provided File
    try:
        result = subprocess.run(
            [
                "powershell",
                "-Command",
                f"(Get-FileHash -Path '{file_path}' -Algorithm SHA256).Hash",
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        # Retreive Hash Value
        hash_value = result.stdout.strip()
        return hash_value if hash_value else None

    # Catch Exception if Calculation of Hash Fails
    except subprocess.CalledProcessError as e:
        print(f"Failed to calculate hash value: {e}")
    return None


# Method for Scanning Provided File
def scan_by_file(virustotal_api_key):
    """Upload and Scan the File"""

    # Retrieve File Path From User
    file_path = input("\nPlease Enter full path to the file: ").strip()

    # Notify User if File do not Exist
    if not os.path.isfile(file_path):
        print("\nFile does not exist. Please make sure that provided path is correct")
        return

    # Run the Application with provided File Path and VirusTotal API Key
    app = FileandURLAnalysisApp(file_path, virustotal_api_key)
    app.run()


# Method for Scanning Files Based on Hash Value
def scan_by_hash(virustotal_api_key, file_hash):
    """Upload and Scan the Hash Value"""

    virus_total = VirusTotal(virustotal_api_key)
    print("\nQuerying VirusTotal with provided hash")

    # Query VirusTotal based on Provided Hash Value and Retrieve the Response
    response = virus_total.query_by_hash(file_hash)

    # If Response Successfully Returns, display VirusTotal Scan Results and Summary Information
    if response:
        # Retrieve metadata from VirusTotal response and print
        attributes = response.get("attributes", {})
        file_name = attributes.get("meaningful_name", "Unknown")
        file_size = attributes.get("size", "Unknown")
        md5 = attributes.get("md5", "Unknown")
        sha1 = attributes.get("sha1", "Unknown")
        sha256 = attributes.get("sha256", "Unknown")

        print("\nFile Metadata Information:")
        print(f"File Name: {file_name}")
        print(f"File Size: {file_size} bytes")
        print("\nFile Hashes:")
        print(f"MD5: {md5}")
        print(f"SHA1: {sha1}")
        print(f"SHA256: {sha256}")

        Reporter.display_virustotal_results(response)
        summary = virus_total.summarize_results(response)
        Reporter.display_summary(summary)

    # Notify User if Nothing Found after Scanning
    else:
        print("\nNo scan results found for the provided hash")


# Method for Scanning URL
def scan_by_url(virustotal_api_key, url_input=None):
    """Scan the URL"""
    virus_total = VirusTotal(virustotal_api_key)

    # Ask user to provide URL to analyze
    if url_input is None:
        url_input = input("\nPlease Enter the URL to analyze: ").strip()

    # Notify User if empty value Entered for URL
    if not url_input:
        print("\nURL cannot be empty")
        return

    # Continue to Process Entered URL if correct URL is entered and Print Analysis ID
    print("\nSubmitting URL to VirusTotal")
    analysis_id = virus_total.submit_url(url_input)
    print(f"\nAnalysis ID: {analysis_id}")

    # Notify User When Program Fails to Retrieve Analysis ID
    if not analysis_id:
        print("\nFailed to retrieve analysis ID")
        return

    # Retrieve VirusTotal Scan Results for Provided URL
    virustotal_results = virus_total.get_scan_results(analysis_id)

    # Display Scan Results If Results Successfully Returns
    if virustotal_results:
        Reporter.display_virustotal_results(virustotal_results)
        summary = virus_total.summarize_results(virustotal_results)
        Reporter.display_summary(summary)
    else:
        print("\nFailed to retrieve URL scan results")


def scan_by_ip(virustotal_api_key, ip_address=None):
    """Scan an IP address using VirusTotal"""
    virus_total = VirusTotal(virustotal_api_key)

    if ip_address is None:
        ip_address = input("\nPlease Enter the IP address to analyze: ").strip()
    if not ip_address:
        print("\nIP address cannot be empty")
        return

    print(f"\nQuerying VirusTotal for IP: {ip_address}")
    ip_data = virus_total.query_ip_address(ip_address)

    if ip_data:
        attributes = ip_data.get("attributes", {})
        last_analysis_stats = attributes.get("last_analysis_stats", {})
        country = attributes.get("country", "Unknown")
        as_owner = attributes.get("as_owner", "Unknown")

        print("\nIP Address Report:")
        print(f"IP: {ip_address}")
        print(f"Country: {country}")
        print(f"AS Owner: {as_owner}")

        # Display vendor-specific results if available
        Reporter.display_virustotal_results(ip_data)

        print("\nDetection Summary:")
        for k, v in last_analysis_stats.items():
            print(f"{k.capitalize()}: {v}")

    else:
        print("\nNo scan results found for the provided IP address")


# Main Entrypoint of Application
def main():
    print("\nWelcome to File, Hash and URL Analyzer Application")

    # Retrieve Stored VirusTotal API Key from Environment Variables for Achieving Secure API Key Handling and not Exposing API Key in Source Code
    virustotal_api_key = os.getenv("VirusTotal_API_KEY")

    # Notify User if VirusTotal API Key is not Set in Environment Variables
    if not virustotal_api_key:
        raise EnvironmentError("VirusTotal_API_KEY not set in environment variables")

    # Continuously Run the Menu of Application in CLI
    while True:
        print("\nWhat would you like to do?")
        print("1. Analyze a file")
        print("2. Analyze a file using the hash")
        print("3. Analyze a URL")
        print("4. Analyze an IP address")
        print("5. Exit the Application")

        # Ask User to Choose an Option
        choice = input("Please Enter your choice (1/2/3/4/5): ").strip()

        # Move to scan_by_file Method if User Selects Option 1
        if choice == "1":
            scan_by_file(virustotal_api_key)

        # Move to scan_by_hash Method if User Selects Option 2
        elif choice == "2":
            while True:
                # Ask Whether User Knows the Hash value or not
                hash_response = (
                    input("\nDo you know the hash value? (yes/no/exit): ")
                    .strip()
                    .lower()
                )

                # If User Knows the Hash, ask User to Provide the Hash and Scan the Hash
                if hash_response == "yes":
                    hash_value = input("\nPlease Enter the hash value: ").strip()
                    scan_by_hash(virustotal_api_key, hash_value)
                    break

                # If User do not know the Hash value, ask User to Enter the Path of File for Calculating its Hash Value
                elif hash_response == "no":
                    file_path = input(
                        "\nEnter full path to the file to retrieve its hash: "
                    ).strip()

                    # Inform User If Entered File Path do not Exist
                    if not os.path.isfile(file_path):
                        print("\nFile not found! Please Enter Correct File Path\n")
                        continue

                    # Retrieve Hash Value of File by Using Get-FileHash Command in Powershell
                    hash_value = get_hash_from_file_powershell(file_path)
                    if hash_value:
                        print(f"\nComputed Hash Value: {hash_value}")
                        scan_by_hash(virustotal_api_key, hash_value)
                    else:
                        print("\nFailed to compute hash value")
                    break

                # Exit the Application if user Enters exit
                elif hash_response == "exit":
                    break

                # Notify User if Wrong Input is Provided
                else:
                    print("\nInvalid input. Please answer with 'yes', 'no', or 'exit'")

        # Move to scan_by_url Method if User Selects Option 3
        elif choice == "3":
            scan_by_url(virustotal_api_key)

        elif choice == "4":
            scan_by_ip(virustotal_api_key)

        # Terminate the Execution of Application if User Selects Option 4
        elif choice == "5":
            print("\nTerminating the Application")
            break
        # Inform User to Provide Correct Option
        else:
            print("\nInvalid choice. Please enter 1, 2, 3 or 4")


if __name__ == "__main__":
    main()
