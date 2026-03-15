from utils.parser import yaml_parse


def loader(test, host=None):
    """Load tools from YAML configuration."""
    tools_list = []
    arsenal = yaml_parse("configs/arsenal.yaml")
    for tool_group in arsenal.get("arsenal", []):
        if tool_group.get("kind") == test:
            for t in tool_group.get("tools", []):
                for cmd_entry in t.get("commands", []):
                    cmd_str = None
                    if isinstance(cmd_entry, dict):
                        if "cmd" in cmd_entry:
                            cmd_str = cmd_entry["cmd"]
                        else:
                            for k, v in cmd_entry.items():
                                if isinstance(v, dict) and "cmd" in v:
                                    cmd_str = v["cmd"]
                                    break
                                elif isinstance(v, str):
                                    cmd_str = v
                                    break
                    elif isinstance(cmd_entry, str):
                        cmd_str = cmd_entry

                    if cmd_str:
                        # Replace {{host}} with actual host
                        if host:
                            cmd_str = cmd_str.replace("{{host}}", host)
                        tools_list.append({
                            "name": t.get("name"),
                            "description": t.get("description"),
                            "command": cmd_str
                        })
    
    if not tools_list:
        print("[!] No tools found. Select a correct test: 'web' or 'network'")
    
    return tools_list

# ------------------ DISPLAY TOOLS ------------------ #
def formater(orch = None):
    all_tools = loader(orch.test, host=orch.host)
    tool_info = []
    cmd_list = []
    for t in all_tools:
        cmd_list.append(t["command"])
        tool_info.append(f"{t['name']} - {t['description']} (command: {t['command']})")
    return "\n".join(tool_info)
