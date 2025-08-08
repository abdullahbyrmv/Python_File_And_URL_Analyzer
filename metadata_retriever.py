import os


class MetaDataRetriever:

    # Constructor of MetaDataRetriever Class
    def __init__(self, file_path: str):
        self.file_path = file_path

    # Method For Retrieving File Name and File Size
    def get_file_info(self):
        """Retrieve Metadata of file including file name and file size"""
        return {
            "file_name": os.path.basename(self.file_path),
            "file_size": os.path.getsize(self.file_path),
        }
