import os
import time
import requests
import hashlib


class VirusTotal:

    # Constructor of VirusTotal Class
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    # Method for API rate limit handling
    def handle_rate_limit(self, response):
        """Handle rate limit case when user send many requests to API"""

        # Retrieve the Value of Retry-After Header to Achieve the value of wait_time. Default value of wait_time will be 60 if nothing returns from response.
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            wait_time = int(retry_after) if retry_after else 60

            # Wait for Specified wait_time
            print(f"Rate limit hit. Waiting for {wait_time} seconds...")
            time.sleep(wait_time)
            return True
        return False

    # Method for Handling File Upload in VirusTotal by using "https://www.virustotal.com/api/v3/files" Endpoint and Receiving Analysis ID
    def upload_file(self, file_path):
        """Upload the file to VirusTotal and Receive Analysis ID"""
        url = f"{self.base_url}/files"
        headers = {"x-apikey": self.api_key}

        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(url, headers=headers, files=files)

        # Handle case when file already exists
        if response.status_code == 409:
            print("\nFile already exists in VirusTotal database")

            # In case of conflict, retrieve and return the value of SHA256 hash
            sha256_hash = self._get_sha256(file_path)

            existing_file = self.query_by_hash(sha256_hash)
            return {"type": "file", "data": existing_file}

        # Return Response
        response.raise_for_status()
        return {"type": "analysis", "id": response.json()["data"]["id"]}

    # Method for Retrieving sha256 hash value
    def _get_sha256(self, file_path):
        """Retrieve SHA256 hash value of file"""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    # Method for Handling URL Submission to VirusTotal for Scanning URL by using "https://www.virustotal.com/api/v3/urls" Endpoint and Receiving Analysis ID
    def submit_url(self, url_to_scan: str) -> str:
        """Submit the URL to VirusTotal and receive Analysis ID"""

        # Retrieve Response from "https://www.virustotal.com/api/v3/urls" endpoint
        submit_url = f"{self.base_url}/urls"
        response = requests.post(
            submit_url, headers=self.headers, data={"url": url_to_scan}
        )

        # Retrieve Response if Response Status Code is 200 or 202
        if response.status_code in (200, 202):
            return response.json().get("data", {}).get("id")

        # Else, handle rate limit and Submit URL Again
        elif self.handle_rate_limit(response):
            return self.submit_url(url_to_scan)

        # Print Other Error Message and Status Code if URL Submission Fails
        else:
            print(f"\nFailed to submit URL with Status Code: {response.status_code}")
            print(f"\nError Message: {response.text}")
            return None

    # Method for Receiving Scan Results through "https://www.virustotal.com/api/v3/analyses/id" endpoint
    def get_scan_results(self, analysis_id: str) -> dict:
        """Retrieve scan results based on analysis id"""
        url = f"{self.base_url}/analyses/{analysis_id}"
        while True:
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
            data = response.json()["data"]
            if data["attributes"]["status"] == "completed":
                return data
            print("Waiting for scan to complete...")
            time.sleep(30)

    # Method for Summarizing Scan Results
    def summarize_results(self, results: dict) -> dict:
        """Summarize the Vendor scan results for user"""

        # Group Scan Results Based on 3 groups namely malicious, undetected and type-unsupported
        counts = {"malicious": 0, "undetected": 0, "type-unsupported": 0}

        # Retrieve the Scan Results
        vendor_scan_results = results.get("attributes", {}).get("results")

        # If nothing Resturns as Scan Result, Retrieve Last Analysis Results
        if vendor_scan_results is None:
            vendor_scan_results = results.get("attributes", {}).get(
                "last_analysis_results"
            )

        # If no Scan Result Found, Notify User That There are no Analysis Results to Summarize
        if vendor_scan_results is None:
            print("No analysis results to summarize.")
            return counts

        # Count the Scan Results for Each Category (malicious, undetected and type-unsupported)
        for result in vendor_scan_results.values():
            category = result.get("category")
            if category in counts:
                counts[category] += 1

        return counts

    # Method for Scanning Files Based on Hash Value
    def query_by_hash(self, file_hash: str) -> dict:
        """Scan file based on provided Hash Value"""
        url = f"{self.base_url}/files/{file_hash}"
        response = requests.get(url, headers=self.headers)

        # Return Data if Response is correctly Received
        if response.status_code == 200:
            json_data = response.json()
            return json_data["data"]

        # Else, handle rate limit and Submit Hash Value Again
        elif self.handle_rate_limit(response):
            return self.query_by_hash(file_hash)

        # Notify User that Scan Results can't be Received and Print Response
        else:
            print(f"Failed to get results: {response.status_code}")
            print(f"Response body: {response.text}")
        return None

    # Method for Scanning IP Address
    def query_ip_address(self, ip_address: str) -> dict:
        """Query VirusTotal Based on IP Address"""
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        response = requests.get(url, headers=self.headers)

        if response.status_code == 200:
            return response.json().get("data", {})

        elif self.handle_rate_limit(response):
            return self.query_ip_address(ip_address)

        else:
            print(f"Failed to get IP address results: {response.status_code}")
            print(f"Response body: {response.text}")
            return None
