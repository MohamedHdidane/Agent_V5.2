    def pip_freeze(self, task_id):
        out = ""

        # Try importlib.metadata (Python 3.8+ or with importlib-metadata backport)
        try:
            try:
                from importlib.metadata import distributions
            except ImportError:
                from importlib_metadata import distributions  # backport

            installed_packages = sorted(
                f"{dist.metadata['Name']}=={dist.version}"
                for dist in distributions()
                if 'Name' in dist.metadata
            )
            return "\n".join(installed_packages)

        except Exception as e:
            out += f"[*] Error using importlib.metadata: {e}\n"

        # Fallback: Try pkg_resources from setuptools
        try:
            import pkg_resources
            installed_packages = sorted(
                f"{dist.project_name}=={dist.version}"
                for dist in pkg_resources.working_set
            )
            return "\n".join(installed_packages)

        except Exception as e:
            out += f"[*] Error using pkg_resources: {e}\n"

        # Last resort: list module names (not versions)
        try:
            import pkgutil
            installed_packages = sorted(name for _, name, _ in pkgutil.iter_modules())
            return "\n".join(installed_packages)

        except Exception as e:
            out += f"[*] Error using pkgutil: {e}\n"

        return out + "[!] Could not retrieve installed package list."