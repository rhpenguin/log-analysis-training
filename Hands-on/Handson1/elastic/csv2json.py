# -*- coding: utf-8 -*-
import csv
import pprint
import json
import datetime
import shlex

host = "Win7_64JP_01"
ip = "192.168.16.1"
index = {
    "index" : {
        "_index" : "jpcertcc-log-analysis-training-handson1"
    }
}

with open('Sysmon_no_bom.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row["id"] != "1":
            continue
        log_text = row["log"]
        log_lines = log_text.split("\n")
        cim_template = {
            "@timestamp": "",
            "hash": {},
            "agent": {
                "hostname": host,
                "ephemeral_id": "00000000-b056-4107-aa49-000000000000",
                "id": "00000000-9227-49e8-96dc-000000000000",
                "name": host,
                "type": "winlogbeat",
                "version": "7.8.1"
            },
            "message": "",
            "winlog": {
                "computer_name": host,
                "opcode": row["level"],
                "user": {
                    "identifier": "",
                    "name": "",
                    "domain": "",
                    "type": ""
                },
                "event_data": {
                    "Company": "",
                    "RuleName": "",
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
                "level": row["level"]
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
                    "name": "Windows",
                    "kernel": "",
                    "build": "",
                    "platform": "windows",
                    "version": ""
                },
                "id": "00000000-721a-4007-86f6-000000000000",
                "ip": [ip],
                "mac": [],
                "name": host,
                "hostname": host,
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
        for log_line in log_lines:
            log_kv = log_line.split(":", 1)
            if len(log_kv) > 1 and log_kv[1]:
                k = log_kv[0].strip()
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
                    try:
                        cim_template["process"]["args"] = shlex.split(v)
                    except:
                        pass
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
                    try:
                        cim_template["process"]["parent"]["args"] = shlex.split(v)
                    except:
                        pass
                elif k == "Hashes":
                    hashes = v.split(",")
                    for hash in hashes:
                        hash_kv = hash.split("=")
                        cim_template["hash"][hash_kv[0].lower()] = hash_kv[1]
                        if hash_kv[0] == "IMPHASH":
                            cim_template["process"]["pe"][hash_kv[0].lower()] = hash_kv[1]
                        else:
                            cim_template["process"]["hash"][hash_kv[0].lower()] = hash_kv[1]

        cim_template["message"] = log_text.replace("\\n","\\\\n")
        print(json.dumps(index))
        print(json.dumps(cim_template))

with open('Security_no_bom.csv') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row["id"] != "5156" and row["id"] != "5140":
            continue
        log_text = row["log"]
        log_lines = log_text.split("\n")
        cim_template = {
            "@timestamp": "",
            "log": {
                "level": row["level"]
            },
            "destination": {
                "ip": "0.0.0.0",
                "domain": "",
                "port": 0
            },
            "user": {
                "domain": "",
                "name": ""
            },
            "winlog": {
                "event_data": {
                    "RuleName": ""
                },
                "channel": "Microsoft-Windows-Security-Auditing",
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "process": {
                    "pid": 0,
                    "thread": {
                        "id": 0
                    }
                },
                "task": "Network connection detected",
                "api": "wineventlog",
                "version": 5,
                "provider_guid": "{00000000-c22a-43e0-bf4c-000000000000}",
                "event_id": int(row["id"]),
                "record_id": 0,
                "user": {
                    "identifier": "",
                    "name": "",
                    "domain": "",
                    "type": ""
                },
                "computer_name": host,
                "opcode": row["level"]
            },
            "event": {
                "category": ["network"],
                "type": ["connection", "start", "protocol"],
                "kind": "event",
                "code": int(row["id"]),
                "provider": "Microsoft-Windows-Security-Auditing",
                "action": "",
                "created": "2020-08-14T19:04:15.914Z",
                "module": "security"
            },
            "host": {
                "os": {
                    "family": "windows",
                    "name": "Windows",
                    "kernel": "",
                    "build": "",
                    "platform": "windows",
                    "version": ""
                },
                "id": "00000000-721a-4007-86e6-000000000000",
                "ip": [ip],
                "mac": [],
                "name": host,
                "hostname": host,
                "architecture": "x86_64"
            },
            "message": "",
            "process": {
                "entity_id": "",
                "pid": 0,
                "executable": "",
                "name": ""
            },
            "network": {
                "transport": "",
                "protocol": "",
                "direction": "",
                "type": "",
                "community_id": ""
            },
            "source": {
                "ip": "0.0.0.0",
                "domain": "",
                "port": 0
            },
            "related": {
                "user": "",
                "ip": []
            },
            "ecs": {
                "version": "1.5.0"
            },
            "agent": {
                "hostname": host,
                "ephemeral_id": "00000000-b056-4107-aa49-000000000000",
                "id": "00000000-9227-49e8-96dc-000000000000",
                "name": host,
                "type": "winlogbeat",
                "version": "7.8.1"
            }
        }
        log_time = datetime.datetime.strptime(row["time"], '%Y/%m/%d %H:%M:%S').astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        cim_template["@timestamp"] = log_time
        cim_template["event"]["created"] = log_time
        cim_template["event"]["action"] = row["category"]
        for log_line in log_lines:
            log_kv = log_line.split(":", 1)
            if len(log_kv) > 1 and log_kv[1]:
                k = log_kv[0].strip()
                v = log_kv[1].strip()
                if k == "プロセス ID":
                    cim_template["process"]["pid"] = int(v)
                elif k == "アプリケーション名":
                    cim_template["process"]["executable"] = v
                    elms = v.split("\\")
                    cim_template["process"]["name"] = elms[len(elms) - 1]
                elif k == "方向":
                    if v == "送信":
                        cim_template["network"]["direction"] = "outbound"
                    else:
                        cim_template["network"]["direction"] = "inbound"
                elif k == "送信元アドレス":
                    cim_template["source"]["ip"] = v
                elif k == "ソース ポート":
                    cim_template["source"]["port"] = int(v)
                elif k == "宛先アドレス":
                    cim_template["destination"]["ip"] = v
                elif k == "宛先ポート":
                    cim_template["destination"]["port"] = int(v)
                elif k == "プロトコル":
                    cim_template["network"]["iana_number"] = v
                    if v == "1":
                        cim_template["network"]["transport"] = "icmp"
                    elif v == "2":
                        cim_template["network"]["transport"] = "igmp"
                    elif v == "6":
                        cim_template["network"]["transport"] = "tcp"
                    elif v == "17":
                        cim_template["network"]["transport"] = "udp"
                    elif v == "58":
                        cim_template["network"]["transport"] = "ipv6-icmp"
                    else:
                        cim_template["network"]["transport"] = "unknown"
                elif k == "フィルターの実行時 ID":
                    cim_template["winlog"]["event_data"]["filter_exec_id"] = v
                elif k == "レイヤー名":
                    cim_template["winlog"]["event_data"]["layer_name"] = v
                elif k == "レイヤーの実行時 ID":
                    cim_template["winlog"]["event_data"]["layer_exec_id"] = v
                elif k == "セキュリティ ID":
                    cim_template["winlog"]["user"]["identifier"] = v
                elif k == "アカウント名":
                    cim_template["winlog"]["user"]["name"] = v
                    cim_template["user"]["name"] = v
                elif k == "アカウント ドメイン":
                    cim_template["winlog"]["user"]["domain"] = v
                    cim_template["user"]["domain"] = v
                elif k == "ログオン ID":
                    cim_template["winlog"]["event_data"]["LogonId"] = v
                elif k == "オブジェクトの種類":
                    cim_template["winlog"]["event_data"]["object_type"] = v
                elif k == "共有名":
                    cim_template["winlog"]["event_data"]["shared_name"] = v
                elif k == "共有パス":
                    cim_template["winlog"]["event_data"]["shared_path"] = v
                elif k == "アクセス マスク":
                    cim_template["winlog"]["event_data"]["access_mask"] = v
                elif k == "アクセス":
                    cim_template["winlog"]["event_data"]["access"] = v

        cim_template["message"] = log_text.replace("\\n","\\\\n").replace("\\t","")
        print(json.dumps(index))
        print(json.dumps(cim_template))

