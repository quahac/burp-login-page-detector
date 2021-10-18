import re
from array import array
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Login Page Detector")
        callbacks.registerScannerCheck(self)
        print("Login Page Detector loaded successfully")

        return

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

    def doPassiveScan(self, baseRequestResponse):
        scan_issues = []
        issues = []
        offset = array('i', [0, 0])

        matches = re.compile(r"type\s*=\s*['\"]\s*password\s*['\"]", flags=re.IGNORECASE).findall(    
            self._helpers.bytesToString(
                baseRequestResponse.getResponse()
            )
        )

        for match in matches:
            offsets = []
            start = self._helpers.indexOf(baseRequestResponse.getResponse(
            ), match, True, 0, len(baseRequestResponse.getResponse()))
            offset[0] = start
            offset[1] = start + len(match)
            offsets.append(offset)

            return [CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, offsets)],
                    'Login page detected',
                    "The response contains the string: <b>" + match + "</b>. <br>This can be a login, register or a script page that handles password.",
                    'Information')]

        if len(scan_issues) > 0:
            return scan_issues
        else:
            return None


class CustomScanIssue (IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
