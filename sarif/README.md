# SARIF Format

SARIF is used to exchange logs of security scanner events (e.g. detections), and is championed by Microsoft

## This repository

### [json2sarif.py](json2sarif.py)

a simple, minimal converter for Endor Labs findings in our native JSON format, to SARIF that can be imported by GHAS and ADO. This is provided as an example of the simplicity of post-processing Endor Labs findings JSON data

**NOTE:** Endor Labs has native SARIF support through the `--sarif-file` flag for `endorctl` and `with: sarif_file:` stanza in the GitHub Action.

```sh
python3 json2sarif.py path/to/findings.json [all_findings|warning_findings|blocking_findings] > path/to/sarif_file.sarif
```

Reads a file generated from output from an `endorctl scan` command (or scan operation using the Endor Labs GitHub Action) in JSON format (`-o json`, which is default for the Action), and converts it to a SARIF 2.1.0 log for ingestion into GHAS or other tools. Note that `endorctl` also has an official `--sarif-file` option -- this tool is meant for "after the fact" conversions and other cases where the default output may be not what's wanted.

The second argument is optional, and defaults to `all_findings` -- this is the finding category of the top-level structure for the findings output. This lets you, for example, only produce SARIF for issues that have violated a warn or block policy.

There's an example of a [GitHub Workflow YAML file](example/endorlabs_warnings_sarif.yml) that shows how to use this in lieu of the native SARIF support in Endor Labs.

## Resources

* [Microsoft SARIF Validator](https://sarifweb.azurewebsites.net/Validation) -- includes validation rules for SARIF files as ingested for GitHub Advanced Security and Azure DevOps
