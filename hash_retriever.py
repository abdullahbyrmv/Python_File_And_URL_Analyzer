import hashlib


class HashRetriever:

    # Constructor of HashRetriever Class
    def __init__(self, file_path: str):
        self.file_path = file_path

    # Method for Computing and Returning the md5, sha1 and sha256 Hash Values
    def compute_hash_values(self):
        """Compute the MD5, SHA1 and SHA256 hash values of file"""
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()

        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }
