# coding=utf-8
from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
import re


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        # This method is used to obtain an IExtensionHelpers object, which can be used by the extension to perform numerous useful tasks.
        self._helper = callbacks.getHelpers()  # analyze and encode request/response
        self._callbacks.setExtensionName('path_shadow_scanner')

        stdout = PrintWriter(callbacks.getStdout(), True)
        stdout.println("by j1anFen")

        callbacks.registerHttpListener(self)

    def get_suffix(self, path):
        suffix_file = path.split('/')[-1]

        filter_suffix = re.search('(\.(\w+)!)|(\.(\w+)\?)|(\.(\w+)$)', suffix_file)  # .png!smail | .js?version=1.1.1.1

        suffix = ''

        if filter_suffix:
            filter_name = filter_suffix.group()
            suffix = re.split('[?!]', filter_name)[0][1:]
        return suffix

    def getshadowinfo(self, url, mesinfo, reqinfo, req_type):

        datainfo = self._helper.bytesToString(mesinfo[reqinfo.getBodyOffset():])

        # https://github.com/GerbenJavado/LinkFinder
        regex_js = r"""

          (?:"|')                               # Start newline delimiter

          (
            ((?:[a-zA-Z]{1,10}://|//)           # Match a scheme [a-Z]*1-10 or //
            [^"'/]{1,}\.                        # Match a domainname (any character + dot)
            [a-zA-Z]{2,}[^"']{0,})              # The domainextension and/or path

            |

            ((?:/|\.\./|\./)                    # Start with /,../,./
            [^"'><,;| *()(%%$^/\\\[\]]          # Next character can't be...
            [^"'><,;|()]{1,})                   # Rest of the characters can't be

            |

            ([a-zA-Z0-9_\-/]{1,}/               # Relative endpoint with /
            [a-zA-Z0-9_\-/]{1,}                 # Resource name
            \.(?:[a-zA-Z]{1,4}|action)          # Rest + extension (length 1-4 or action)
            (?:[\?|/][^"|']{0,}|))              # ? mark with parameters

            |

            ([a-zA-Z0-9_\-]{1,}                 # filename
            \.(?:php|asp|aspx|jsp|json|
                 action|do|html|js|txt|xml)             # . + extension
            (?:\?[^"|']{0,}|))                  # ? mark with parameters

          )

          (?:"|')                               # End newline delimiter

        """

        # Match HTML for regular crawling
        # print req_type
        if req_type.lower().startswith('h'):
            datainfo = ''.join([m.group(1) for m in re.finditer(r"<script[\s\S]*?>([\s\S]*?)<\/script>", datainfo)])

        regex = re.compile(regex_js, re.VERBOSE)

        items = set([m.group(1) for m in re.finditer(regex, datainfo)])

        if items:

            asset_suffix = ['css', 'gif', 'png', 'jpg', 'jpeg', 'tpl', 'swf', 'bmp', 'mpeg', 'ico', 'mp3', '.mp4',
                            'svg', 'ttf', 'woff', 'woff2']

            filter_content = ['www.w3.org']

            print '----------------->>>>regex info<<<<------------------'
            print 'Url: {}'.format(url)
            for i in items:
                i_suffix = self.get_suffix(i)
                if i_suffix not in asset_suffix :
                    print '[+] {}'.format(i)
            print '----------------->>>>regex info<<<<------------------'

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if toolFlag == 4:
            if not messageIsRequest:
                # get Host
                iHttpService = messageInfo.getHttpService()
                requestinfo = self._helper.analyzeRequest(messageInfo)

                # fileter assets domains
                host = iHttpService.getHost()
                filter_host = re.search(
                    '(\w+\.bdstatic.com$)|(\w+\.baidustatic\.com$)|(\w+\.baidu\.com$)|(\w+\.sogou\.com$)|(\w+\.mozilla\.com$)|(\w+\.google-analytics\.com$)|(\w+\.google\.com$)|(\w+\.cnzz\.com$)|(\w+\.bing\.com$)',
                    host)

                if filter_host:
                    return

                # get request URL
                url = str(requestinfo.getUrl())

                # get response
                getresponse = messageInfo.getResponse()
                # Analyze the return packet to remove the mime return header information for filtering
                responseinfo = self._helper.analyzeResponse(getresponse)

                mime_header = responseinfo.getStatedMimeType()

                mime_search = ['HTML', 'script']

                query_search = ['html', 'htm', 'js']

                # get url suffix
                suffix = self.get_suffix(url)

                if suffix:
                    if suffix in query_search:
                        self.getshadowinfo(url, getresponse, requestinfo, suffix)
                else:
                    # MIME matching crawl HTML/JS
                    if mime_header in mime_search:
                        self.getshadowinfo(url, getresponse, requestinfo, mime_header)