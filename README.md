# Python File and URL Analyzer #

## Instructions on How to Set Up and Run the Application ##

1. Make sure that ``python`` is already installed on your machine and added to ``Environment Variables``. If ``python`` is not installed, you can download latest version of ``python`` from [here](https://www.python.org/downloads/release/python-3136/).

2. Make sure that your VirusTotal API Key is set in environment variables with name ``VirusTotal_API_KEY``. In order to do this through powershell, you can use ``setx VirusTotal_API_KEY "your_VirusTotal_API_Key"`` command or add new user variable in environment variables.

3. Clone the repository using command ``git clone https://github.com/abdullahbyrmv/Python_File_And_URL_Analyzer.git`` or download the zip version of repository.

4. Open the folder in your ``IDE`` or navigate to folder through ``cmd``.

5. Run ``main.py`` in ``IDE`` or use ``python3 main.py`` command in ``cmd`` to run the application.

## Main Functionalities of Application ##
The application allows users to analyze based on ``file``, ``hash`` and ``URL``. After providing the proper value for one of these options, user receives detailed scan results. Users are also able to terminate the execution of the program by using ``Exit the Applicaiton`` option. Otherwise, program will continue to run until users explicitly wants to terminate the program. The application displays scan results based on ``vendors``, ``MD5``, ``SHA1`` and ``SHA256`` hash values of file and also displays PE file information by utilizing ``pefile`` if the provided file is PE type of file.

## Additional Functionalities of Application ##

### Secure API key handling ###
Application retrieves API Key of VirusTotal from environment variables. By this way, user will not need to type their VirusTotal API Key as plaintext in python code. Instead, setting API Key in environment variables and retrieving API Key from environment variables by using ``virustotal_api_key = os.getenv("VirusTotal_API_KEY")`` is utilized which is safe method.

### MultiThread Support ###
Application achieves the Multithread support and runs local file analysis and VirusTotal scan in seperate threads.

```
# Method for Achieving Multithread Support
    def run(self):
        # Start local analysis in its own thread
        local_thread = threading.Thread(target=self.local_analysis)
        local_thread.start()

        # Start VirusTotal scan in seperate thread
        vt_thread = threading.Thread(target=self.virustotal_scan)
        vt_thread.start()

        # Wit for both to complete
        local_thread.join()
        vt_thread.join()
```
Inside of this ``run`` method, local analysis is run on main thread but VirusTotal scan runs in another thread and multithread support is achieved.


### API rate limit handling ###
API rate limit handling is achieved by using ``handle_rate_limit`` method. When too many requests are sent to server, wait time occurs and after wait time ends, user will be able to send requests.
```
def handle_rate_limit(self, response):

    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After")
        wait_time = int(retry_after) if retry_after else 60

        # Wait for Specified wait_time
        print(f"Rate limit hit. Waiting for {wait_time} seconds...")
        time.sleep(wait_time)
        return True
    return False
```

## Demo Video of Application ##
[Demo Video](https://youtu.be/HeP9cjeP-eQ)