//----------------------------------------------------------------------------
// Object Printer Function (for debug)

function objprint(a,name)
{
  document.write("<table border='1' bgcolor='#EEEEEE' border='1' cellpadding='2' cellspacing='0' bordercolorlight='#000000'>");
  _objprint(a,name);  
  document.write("</table>");
};

function _objprint(obj,name)
{
  if(typeof obj == "object") // all objects in here
  { 
    if (obj && obj.constructor) // detect specific objects for special handling here
    {
      if (obj.constructor == Array) _parray(obj,name);
      else if (obj.constructor == String) _pstring(obj,name);
      else _pgeneric(obj,name);
    }  
    else _pgeneric(obj,name);
  }
  else _pbase(obj,name);
}

function _parray(a,name) // array object
{
  if (a.length==0) _pempty("array",name)
  for(var i=0; i < a.length; i++)  
    _objprint(a[i],name+"["+i+"]");
};

function _pstring(obj,prefix) // string object
{
  document.write("<tr><td>",prefix,"</td><td>\"",obj,"\" (String object)</td></tr>");
}

function _pgeneric(obj, name) // generic object
{
  if (!_listprops(obj,name)) _pempty("object",name);
};

function _pempty(type,prefix) // object with no properties
{
  document.write("<tr><td>",prefix,"</td><td>[empty "+type+"]</td></tr>");
};

function _pbase(obj,prefix) // base type
{
  document.write("<tr><td>",prefix,"</td><td>",obj," (",typeof obj,")</td></tr>");
  _listprops(obj,prefix);
};

function _listprops(obj,name)
{
  var hasprops = false;
  for (var i in obj)
  { 
    hasprops = true;
    _objprint(obj[i],name+"."+i);
  }
  return hasprops;  
 /* 
  var _extraprops = ["prototype","__proto__"];
  if (typeof obj != "undefined")
  for (var i=0; i < _extraprops.length; i++)
  if (typeof obj[_extraprops[i]] != "undefined")
  {
    hasprops = true;
    //_objprint(obj[_extraprops[i]],name+"."+_extraprops[i]);
    document.write("<tr><td>",name,".",_extraprops[i],"</td><td>",obj[_extraprops[i]],"(",typeof obj[_extraprops[i]],")</td></tr>");
  }
  {
    hasprops = true;
    document.write("<tr><td>",name,".constructor</td><td>",obj.constructor," (",typeof obj.constructor,")</td></tr>");
  } */
};
