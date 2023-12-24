import requests
import os
import json
import tomllib

url = "http://10.0.2.15/api/detection_engine/rules"
api_key = "b3psLWc0d0JfMkhIN3BjcXVMbE86T0JDS2YzRnlSWW1sLXdGYzNmS1gzdw=="
headers = {
    'Content-type': 'application/json',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

for root, dirs, files in os.walk("/detections"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)

                if alert['rule']['type'] == "query":
                    required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query','threat']
                elif alert['rule']['type'] == "eql":
                    required_fields = ['author', 'description', 'name', 'rule_id', 'risk_score', 'severity', 'type', 'query', 'language','threat']
                elif alert['rule']['type'] == "threshold":
                    required_fields = ['author', 'description', 'name', 'rule_id','risk_score', 'severity', 'type', 'query', 'threshold','threat']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break

                data_dict = {field: alert['rule'][field] for field in required_fields if field in alert['rule']}
                data_dict['enabled'] = True

                data_json = json.dumps(data_dict)

                print(data_json)

                response = requests.post(url, headers=headers, json=json.loads(data_json), verify=False).json()

                print(response)
