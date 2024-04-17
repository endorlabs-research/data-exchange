import json as jsonlib
import hashlib
import sys


def say(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


json_filename = sys.argv[1]
json_root = 'all_findings' if len(sys.argv) <=2 else sys.argv[2]

try:
    say(f"loading {json_filename} using root location {json_root}")
    with open(json_filename, 'rb') as json_file:
        json = jsonlib.load(json_file)
    json = json[json_root]
except KeyError as e:
    say(f"ERROR could not find key {e} in '{json_filename}', aborting")
    sys.exit(2)
except Exception as e:
    say(f"ERROR {e.__class__.__name__}: {e}, quitting")
    sys.exit(1)

# json holds the list of findings to convert
# sarif holds the sarif document we're building
sarif_results = []
sarif_rules = []

for finding in json:
    rule_id = hashlib.sha256(finding['meta']['description'].encode('utf8')).hexdigest()
    sarif_finding = {
        "ruleId": rule_id,
        "level": finding['spec']['level'].replace('FINDING_LEVEL_',''),
        "message": finding['meta']['description'],
        "locations": []
    }
    
    sarif_rule = {
        "id": rule_id,
        "name": finding['meta']['description'],
        "fullDescription": {
            "text": finding['spec']['explanation']
        },
        "help": {
            "text": finding['spec']['remediation']
        },
        "shortDescription": {
            "text": finding['spec']['summary']
        },
        "properties": {
            "security-severity": finding['spec'].get('finding_metadata',{}).get('vulnerability',{}).get('spec',{}).get('cvss_v3_severity',{}).get('score', 0),
            "tags": [ x.replace('FINDING_TAGS_','') for x in finding['spec'].get('finding_tags',[]) ]
        }
    }

    sarif_rules.append(sarif_rule)

    fp_index=0
    for fp in finding['spec']['dependency_file_paths']:
        sarif_finding["locations"].append(
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": f"{fp}",
                  "index": fp_index,
                },
                "region": {
                  "startLine": 1,
                  "startColumn": 1
                }
              }
            }
        )
        fp_index += 1

    sarif_results.append(sarif_finding)

sarif_run = {
    "tool": {
        "driver": {
            "name": "Endor Labs",
            "informationUri": "https://endorlabs.com",
            "rules": sarif_rules,
        }
    },
    "results": sarif_results,
}
sarif = {
    "version": "2.1.0",
    "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
    "runs": [sarif_run]
}

print(jsonlib.dumps(sarif, indent=2))