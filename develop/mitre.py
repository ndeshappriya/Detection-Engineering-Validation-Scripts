import requests
import tomllib
import os

url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
headers = {
    'accept': 'application/json'
}

mitreData = requests.get(url, headers=headers).json()
mitreMapped = {}

for obj in mitreData['objects']:
    tactics = []
    if obj['type'] == 'attack-pattern':
        if 'external_references' in obj:
            for reference in obj['external_references']:
                if 'external_id' in reference:
                    if reference['external_id'].startswith('T'):
                        if 'kill_chain_phases' in obj:
                            for tactic in obj['kill_chain_phases']:
                                tactics.append(tactic['phase_name'])
                        technique = reference['external_id']
                        name = obj['name']
                        url = reference['url']

                        if 'x_mitre_deprecated' in obj:
                            deprecated = obj['x_mitre_deprecated']
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated}
                            mitreMapped[technique] = filtered_object
                        else:
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': "false"}
                            mitreMapped[technique] = filtered_object

alert_data = {}
filtered_object_array = []

for root, dirs, files in os.walk("/detections"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path, "rb") as toml:
                alert = tomllib.load(toml)
                filtered_object_array = []

                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                    for threat in alert['rule']['threat']:
                        technique_id = "none"
                        technique_name = "none"

                        if 'technique' in threat:
                            technique_id = threat['technique'][0]['id']
                            technique_name = threat['technique'][0]['name']

                        tactic = "none"
                        if 'tactic' in threat:
                            tactic = threat['tactic']['name'].lower()

                        subtechnique_id = "none"
                        subtechnique_name = "none"
                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']

                        filtered_object = {'tactic': tactic, 'technique_id': technique_id, 'technique_name': technique_name,
                                           'url': url, 'subtechnique_id': subtechnique_id, "subtechnique_name": subtechnique_name}
                        filtered_object_array.append(filtered_object)
                        alert_data[file] = filtered_object_array

mitre_tactic_list = ['none', 'reconnaissance', 'resource development', 'initial access', 'execution', 'persistence',
                     'privilege escalation', 'defense evasion', 'credential access', 'discovery', 'lateral movement',
                     'collection', 'command and control', 'exfiltration', 'impact']

for file in alert_data:
    for line in alert_data[file]:
        tactic = line['tactic'].lower()
        technique_id = line['technique_id']
        subtechnique_id = line['subtechnique_id']

        # Check to ensure MITRE tactics exist
        if tactic not in mitre_tactic_list:
            print("The MITRE Tactic supplied does not exist: " + "\"" + tactic + "\"" + " in " + file)

        # Check to make sure MITRE technique ID is valid
        if technique_id not in mitreMapped:
            print("The MITRE Technique ID supplied does not exist: " + "\"" + technique_id + "\"" + " in " + file)

        # Check to see if MITRE ID + name combination is valid
        try:
            mitre_name = mitreMapped[technique_id]['name']
            alert_name = line['technique_name']
            if alert_name != mitre_name:
                print("MITRE Technique ID and Name mismatch in " + file + " Expected: " + "\"" + mitre_name + "\"" + " Given: " + "\"" + alert_name + "\"")
        except KeyError:
            pass
       # Check to see subTID + name combination is valid
        
        try:
            if subtechnique_id != "none":
              mitre_name = mitreMapped[subtechnique_id]['name']
              alert_name = line['subtechnique_name']
              if alert_name != mitre_name:
                   print("MITRE Sub-Technique ID and Name mismatch in " + file + " Expected: " + "\"" + mitre_name + "\"" + " Given: " + "\"" + alert_name + "\"")
        except KeyError:
             pass
        # Check to see if the technique is deprecated. 

        try: 
             if mitreMapped[technique_id]['deprecated'] == True:
                   print("Deprecated MITRE Technique ID: " + "\"" + technique_id + "\"" + "  in  " + file)
        except KeyError:
             pass