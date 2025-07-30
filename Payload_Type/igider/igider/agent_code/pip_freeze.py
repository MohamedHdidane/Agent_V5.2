    def pip_freeze(self, task_id):
        out = ""
        try:
            from importlib.metadata import distributions
            installed_packages_list = sorted(
                f"{dist.name}=={dist.version}" for dist in distributions()
            )
            return "\n".join(installed_packages_list)
        except ImportError:
            out += "[*] importlib.metadata not available.\n"
        except Exception as e:
            out += f"[*] Error with importlib.metadata: {e}\n"
        
        try:
            from pip._internal.operations.freeze import freeze
            installed_packages_list = list(freeze(local_only=True))
            return "\n".join(installed_packages_list)
        except ImportError:
            out += "[*] pip module not installed.\n"
        except Exception as e:
            out += f"[*] Error with pip freeze: {e}\n"
        
        try:
            import pkgutil
            installed_packages_list = [name for _, name, _ in pkgutil.iter_modules()]
            return "\n".join(installed_packages_list)
        except Exception as e:
            out += f"[*] Error with pkgutil: {e}\n"
        
        return out + "[!] No modules available to list installed packages."