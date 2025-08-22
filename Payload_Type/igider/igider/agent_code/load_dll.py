    def load_dll(self, task_id, dllpath, dllexport):
        import ctypes
        import os
        dll_file_path = dllpath if dllpath[0] == os.sep \
                else os.path.join(self.current_directory,dllpath)
        loaded_dll = ctypes.WinDLL(dll_file_path)
        eval("{}.{}()".format("loaded_dll",dllexport))
        return "[*] {} Loaded.".format(dllpath)
