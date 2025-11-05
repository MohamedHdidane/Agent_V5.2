# 📖 `unload` Command – Unload a Loaded Command from the Agent

The `unload` command removes an existing **command function** from the agent at runtime. This is used to dynamically disable capabilities previously loaded into the agent without restarting it.

---

## 🧾 Arguments

| Argument   | Type               | Description                                         | Required |
|------------|--------------------|-----------------------------------------------------|----------|
| `command`  | `ChooseOne`        | The name of the command to unload (must be loaded)  | ✅ Yes   |

- The argument UI lists commands that are available and currently loaded so the operator can pick one.

---

## 💻 Usage Examples

```bash
unload ls
unload {"command":"screenshot"}
```

- Accepts either a raw argument or a JSON object.
- The UI will typically present a dropdown of loaded commands for convenience.

---

## 🔁 Behavior

- Verifies the named command exists as an attribute on the agent (here referenced as `igider` in the implementation).
- If the command is loaded:
  - Deletes the attribute from the agent (`delattr(igider, command)`), effectively disabling the function.
  - Constructs a post-response that instructs the operator UI to remove the command from the command list (action `"remove"`).
  - Sends a response back to the operator indicating success: `Unloaded command: <command>`.
- If the command is not present, returns a message: `"<command> not currently loaded."`.

> ⚠️ Removing a command is immediate and affects all future tasking that would have used that command.

---

## 🧩 MITRE ATT&CK Mapping

| Technique ID | Name                                  |
|--------------|---------------------------------------|
| T1030        | Data Transfer Size Limits (context)   |
| T1129        | Execution through Module Load/Unload |

---

## ✅ Supported Platforms

- ✅ Linux  
- ✅ Windows  
- ✅ macOS  

Compatible with:  
- Python 3.8 only (per command attributes)

---

## 🔐 Permissions

- Does **not** require administrative privileges.
- The operator must have the ability to send tasking to the agent and the agent must be running and responsive.
- Only commands currently loaded into the agent can be unloaded.

---

## 🛡️ Legal & Ethical Use

This command is part of an offensive security toolkit and must be used **only in environments where you have explicit authorization**. Unauthorized use is illegal and unethical.

---

## 👨‍💻 Author

- Developed by `@Med`