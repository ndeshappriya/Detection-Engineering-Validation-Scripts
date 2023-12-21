import requests

url = "http://10.0.2.15/api/detection_engine/rules"  # Updated endpoint for creating rules
api_key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
headers = {
    'Content-type': 'application/json',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

data = {
    "rule_id": "process_started_by_ms_office_program",
    "risk_score": 50,
    "description": "Process started by MS Office program - possible payload",
    "interval": "1h",
    "name": "MS Office child process",
    "severity": "low",
    "tags": ["child process", "ms office"],
    "type": "query",
    "from": "now-70m",
    "query": "process.parent.name:EXCEL.EXE or process.parent.name:MSPUB.EXE or process.parent.name:OUTLOOK.EXE or process.parent.name:POWERPNT.EXE or process.parent.name:VISIO.EXE or process.parent.name:WINWORD.EXE",
    "language": "kuery",
    "filters": [
        {
            "query": {
                "match": {
                    "event.action": {
                        "query": "Process Create (rule: ProcessCreate)",
                        "type": "phrase"
                    }
                }
            }
        }
    ],
    "enabled": True
}

response = requests.post(url, headers=headers, json=data, verify=False).json()  # Use json parameter instead of data

print(response)
