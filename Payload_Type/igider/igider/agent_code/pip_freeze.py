    def pip_freeze(self, task_id):
        """
        Get list of installed packages using multiple fallback methods
        Optimized for Nuitka compilation
        """
        out = ""
        
        # Method 1: Check if running in compiled mode
        import sys
        is_compiled = getattr(sys, 'frozen', False) or hasattr(sys, '_MEIPASS')
        
        if is_compiled:
            out += "[*] Running in compiled mode - package detection limited.\n"
        
        # Method 1: importlib.metadata (Python 3.8+, most reliable)
        try:
            from importlib.metadata import distributions
            installed_packages_list = sorted(
                f"{dist.name}=={dist.version}" for dist in distributions()
            )
            if installed_packages_list:
                return "\n".join(installed_packages_list)
            else:
                out += "[*] importlib.metadata returned empty list.\n"
        except ImportError:
            out += "[*] importlib.metadata not available.\n"
        except Exception as e:
            out += f"[*] Error with importlib.metadata: {e}\n"
        
        # Method 2: subprocess call to pip freeze (safer than pip internals)
        try:
            import subprocess
            import sys
            import shutil
            
            # Find Python executable (not the compiled exe)
            python_exe = None
            
            # Try common Python executable names
            for py_name in ['python', 'python3', 'python.exe', 'python3.exe']:
                python_path = shutil.which(py_name)
                if python_path:
                    python_exe = python_path
                    break
            
            # Fallback: try extracting Python path from sys.executable if it's a .exe
            if not python_exe and sys.executable.endswith('.exe'):
                # Try to find python in the same environment
                import os
                possible_paths = [
                    os.path.join(os.path.dirname(sys.executable), 'python.exe'),
                    'python',  # Hope it's in PATH
                ]
                for path in possible_paths:
                    if shutil.which(path if not os.path.isabs(path) else path):
                        python_exe = path
                        break
            
            if not python_exe:
                python_exe = 'python'  # Last resort
            
            result = subprocess.run(
                [python_exe, '-m', 'pip', 'freeze'], 
                capture_output=True, 
                text=True, 
                timeout=30,
                check=True
            )
            if result.stdout.strip():
                return result.stdout.strip()
            else:
                out += "[*] pip freeze returned empty output.\n"
        except subprocess.TimeoutExpired:
            out += "[*] pip freeze command timed out.\n"
        except subprocess.CalledProcessError as e:
            out += f"[*] pip freeze command failed: {e}\n"
        except FileNotFoundError:
            out += "[*] pip command not found in PATH.\n"
        except Exception as e:
            out += f"[*] Error with subprocess pip freeze: {e}\n"
        
        # Method 3: pkg_resources (legacy fallback)
        try:
            import pkg_resources
            installed_packages_list = sorted(
                f"{dist.project_name}=={dist.version}" 
                for dist in pkg_resources.working_set
            )
            if installed_packages_list:
                return "\n".join(installed_packages_list)
            else:
                out += "[*] pkg_resources returned empty list.\n"
        except ImportError:
            out += "[*] pkg_resources not available.\n"
        except Exception as e:
            out += f"[*] Error with pkg_resources: {e}\n"
        
        # Method 4: pkgutil (only shows module names, no versions)
        try:
            import pkgutil
            installed_modules = sorted(
                name for _, name, _ in pkgutil.iter_modules()
            )
            if installed_modules:
                out += "[*] Falling back to module names only (no versions):\n"
                return out + "\n".join(installed_modules)
            else:
                out += "[*] pkgutil returned empty list.\n"
        except Exception as e:
            out += f"[*] Error with pkgutil: {e}\n"
        
        return out + "[!] No methods available to list installed packages."