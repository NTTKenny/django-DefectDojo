import json

#from cvss.cvss3 import CVSS3
from dojo.models import Finding


class SnykCodeParser(object):

    def get_scan_types(self):
        return ["Snyk Code Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Snyk output file (snyk code test --json > snyk.json) can be imported in JSON format."

    def get_findings(self, json_output, test):
        lst = []
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")

        for run in tree['runs']:
            for result in run['results']:
                findings = {'title': None, 'test': None, 'severity': None, 'severity_justification': None, 'description': None, 'mitigation': None, 'component_name': None, 'component_version': None, 'false_p': None, 'duplicate': None, 'out_of_scope': None, 'impact': None, 'static_finding': None, 'dynamic_finding': None, 'file_path': None, 'vuln_id_from_tool': None,}
                findings['title'] = result.get('ruleId', None)
                findings['test'] = test
                if isinstance(result['properties']['priorityScore'], int):
                    findings['severity'] = self.calculate_severity(result['properties']['priorityScore'])
                else:
                    findings['severity'] = 0
                findings['severity_justification'] = "Priority score: {score}".format(score=result['properties']['priorityScore'])
                findings['description'] = result['message']['text'] + "\n" + result["message"]['markdown'] + "\n\nLocation:\n" + self.locationstring(result)

                finding = Finding(title=findings['title'], test=findings['test'], severity=findings['severity'], severity_justification=findings['severity_justification'], description=findings['description'])
                lst.append(finding)
        return lst
    

    def calculate_severity(self, score):
        if score > 699:
            severity = "High"
        elif 400 < score <= 699:
            severity = "Medium"
        elif score <= 400:
            severity = "Low"
        return severity


    def locationstring(self, result):
        string = ""
        for i in result["codeFlows"][0]["threadFlows"][0]["locations"]:
            string += f"Path: {i['location']['physicalLocation']['artifactLocation']['uri']}\n"
            string += f"Start line: {i['location']['physicalLocation']['region']['startLine']}\n"
            string += f"End line: {i['location']['physicalLocation']['region']['endLine']}\n\n"
        return string