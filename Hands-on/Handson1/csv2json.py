import csv
import pprint
import json

with open('Sysmon_no_bom.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row["id"] != "1":
            continue
        logText = row["log"]
        logLines = logText.split("\n")
        cim_template = {
            "@timestamp": "",
            "hash": {},
            "agent": {
                "hostname": "DESKTOP-HOGE",
                "ephemeral_id": "00000000-b056-4107-aa49-000000000000",
                "id": "00000000-9227-49e8-96dc-000000000000",
                "name": "DESKTOP-HOGE",
                "type": "winlogbeat",
                "version": "7.8.1"
            },
            "message": "",
            "winlog": {
                "computer_name": "DESKTOP-HOGE",
                "opcode": "情報",
                "user": {
                    "identifier": "",
                    "name": "",
                    "domain": "",
                    "type": ""
                },
                "event_data": {
                    "Company": "",
                    "RuleName": "-",
                    "IntegrityLevel": "",
                    "LogonGuid": "",
                    "Description": "",
                    "FileVersion": "",
                    "TerminalSessionId": "0",
                    "LogonId": "",
                    "Product": "Microsoft® Windows® Operating System",
                    "OriginalFileName": ""
                },
                "process": {
                    "pid": 0,
                    "thread": {
                        "id": 0
                    }
                },
                "provider_name": "Microsoft-Windows-Sysmon",
                "provider_guid": "{00000000-c22a-43e0-bf4c-000000000000}",
                "event_id": 1,
                "record_id": 0,
                "task": "Process Create (rule: ProcessCreate)",
                "api": "wineventlog",
                "version": 5,
                "channel": "Microsoft-Windows-Sysmon/Operational"
            },
            "event": {
                "created": "",
                "module": "sysmon",
                "category": ["process"],
                "type": ["start", "process_start"],
                "kind": "event",
                "code": 1,
                "provider": "Microsoft-Windows-Sysmon",
                "action": "Process Create (rule: ProcessCreate)"
            },
            "log": {
                "level": "情報"
            },
            "process": {
                "command_line": "",
                "working_directory": "",
                "parent": {
                    "entity_id": "",
                    "pid": 0,
                    "executable": "",
                    "command_line": "",
                    "name": "",
                    "args": []
                },
                "args": [],
                "entity_id": "",
                "pid": 0,
                "executable": "",
                "name": "",
                "hash": {},
                "pe": {}
            },
            "host": {
                "os": {
                    "family": "windows",
                    "name": "Windows 10 Pro",
                    "kernel": "10.0.18362.1016 (WinBuild.160101.0800)",
                    "build": "18363.1016",
                    "platform": "windows",
                    "version": "10.0"
                },
                "id": "00000000-721a-4007-86f6-000000000000",
                "ip": [],
                "mac": [],
                "name": "DESKTOP-HOGE",
                "hostname": "DESKTOP-HOGE",
                "architecture": "x86_64"
            },
            "user": {
                "domain": "",
                "name": ""
            },
            "related": {
                "hash": [],
                "user": ""
            },
            "ecs": {
                "version": "1.5.0"
            }
        }
        for logLine in logLines:
            log_kv = logLine.split(":", 1)
            if len(log_kv) > 1 and log_kv[1]:
                k = log_kv[0]
                v = log_kv[1].strip()
                if k == "UtcTime":
                    v = v.replace(" ", "T", 1) + "Z"
                    cim_template["@timestamp"] = v
                    cim_template["event"]["created"] = v
                elif k == "ProcessGuid":
                    cim_template["process"]["entity_id"] = v
                elif k == "ProcessId":
                    cim_template["process"]["pid"] = int(v)
                elif k == "Image":
                    cim_template["process"]["executable"] = v
                    elms = v.split("\\")
                    cim_template["process"]["name"] = elms[len(elms) - 1]
                elif k == "CommandLine":
                    cim_template["process"]["command_line"] = v
                elif k == "CurrentDirectory":
                    cim_template["process"]["working_directory"] = v
                elif k == "User":
                    userInfo = v.split("\\")
                    cim_template["winlog"]["user"]["domain"] = userInfo[0]
                    cim_template["user"]["domain"] = userInfo[0]
                    if len(userInfo) > 1:
                        cim_template["winlog"]["user"]["name"] = userInfo[1]
                        cim_template["user"]["name"] = userInfo[1]
                elif k == "LogonGuid":
                    cim_template["winlog"]["event_data"]["LogonGuid"] = v
                elif k == "LogonId":
                    cim_template["winlog"]["event_data"]["LogonId"] = v
                elif k == "TerminalSessionId":
                    cim_template["winlog"]["event_data"]["TerminalSessionId"] = v
                elif k == "IntegrityLevel":
                    cim_template["winlog"]["event_data"]["IntegrityLevel"] = v
                elif k == "ParentProcessGuid":
                    cim_template["process"]["parent"]["entity_id"] = v
                elif k == "ParentProcessId":
                    cim_template["process"]["parent"]["pid"] = int(v)
                elif k == "ParentImage":
                    cim_template["process"]["parent"]["executable"] = v
                    elms = v.split("\\")
                    cim_template["process"]["parent"]["name"] = elms[len(elms) - 1]
                elif k == "ParentCommandLine":
                    cim_template["process"]["parent"]["command_line"] = v
                elif k == "Hashes":
                    hashes = v.split(",")
                    for hash in hashes:
                        hash_kv = hash.split("=")
                        cim_template["hash"][hash_kv[0].lower()] = hash_kv[1]
                        if hash_kv[0] == "IMPHASH":
                            cim_template["process"]["pe"][hash_kv[0].lower()] = hash_kv[1]
                        else:
                            cim_template["process"]["hash"][hash_kv[0].lower()] = hash_kv[1]
        cim_template["message"] = logText.replace("\\n","\\\\n")
        index = {
            "index" : {
                "_index" : "jpcertcc-log-analysis-training-handson1"
            }
        }
        print(json.dumps(index))
        print(json.dumps(cim_template))
