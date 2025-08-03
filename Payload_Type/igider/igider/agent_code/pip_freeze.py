    def pip_freeze(self, task_id):
        from importlib.metadata import distributions
        import pkgutil
        out = ""

        # Try importlib.metadata
        try:
            installed_packages = sorted(
                f"{dist.metadata['Name']}=={dist.version}"
                for dist in distributions()
                if dist.metadata and 'Name' in dist.metadata
            )
            return "\n".join(installed_packages)

        except Exception as e:
            out += f"[*] Error using importlib.metadata: {e}\n"

        # Fallback: list module names (no versions)
        try:
            installed_packages = sorted(name for _, name, _ in pkgutil.iter_modules())
            return "\n".join(installed_packages)

        except Exception as e:
            out += f"[*] Error using pkgutil: {e}\n"

        return out + "[!] Could not retrieve installed package list."