<!-- Written by Rune Darrud -->
<!--     For Icinga         -->
function replaceCGIString(string,status_cgi,cmd_cgi)
{ 
	sInString = string.replace( status_cgi, cmd_cgi ); 
	return sInString;
}
function replaceArgString(string)
{ 
	ToBeStripped = location.search; 
	sInString = string.replace( ToBeStripped, '' ); 
	return sInString;
}
function cmd_submit(form)
{
	if( form=='' || !form){form='tableform';}
	command_arguments = get_check_value(form);
	cmd_typ = 'cmd_typ=' + document.tableform.hiddencmdfield.value
	if (document.tableform.hiddenforcefield.value == 'yes')
	{
			arguments = cmd_typ + command_arguments + '&force_check';
	}
	else
	{
			arguments = cmd_typ + command_arguments;
	}
	bazinga = '?' + arguments;
	fullurl = replaceCGIString(location.href,'status.cgi','cmd.cgi'); 
        fullurl = replaceCGIString(fullurl,'extinfo.cgi','cmd.cgi'); //This is OK, it will only replace the one matching
	fullurl = replaceArgString(fullurl);
        fullurl = fullurl + bazinga;
        self.location.assign(fullurl);
	// Remove comment below for debugging of the URL
	alert(fullurl);
        return fullurl;
}
function isValidForSubmit(form)
{
        var group = document.getElementById(form);
        var x, len = group.length;
        for(x=0; x<len; x++)
        {
                if(group[x].checked)
                {
                        break;
                }
        }
        if(x < len)
        {
                if ((document.tableform) && (document.tableform.serviceTotalsCommandsButton))
                        {
                                document.tableform.buttonCheckboxChecked.value='true';
                        }
                if ((document.tableform) && (document.tableform.hostTotalsCommandsButton))
                        {
                                document.tableform.buttonCheckboxChecked.value='true';
                        }
                if ((document.tableformservice) && (document.tableformservice.serviceDownTimeCommandButton))
                        {
                                document.tableformservice.buttonCheckboxChecked.value='true';
                        }
                if ((document.tableformhost) && (document.tableformhost.hostDownTimeCommandButton))
                        {
                                document.tableformhost.buttonCheckboxChecked.value='true';
                        }
                enableDisableButton();
        }
        else
        {
                if ((document.tableform) && (document.tableform.serviceTotalsCommandsButton))
                        {
                                document.tableform.buttonCheckboxChecked.value='false';
                        }
                if ((document.tableform) && (document.tableform.hostTotalsCommandsButton))
                        {
                                document.tableform.buttonCheckboxChecked.value='false';
                        }
                if ((document.tableformservice) && (document.tableformservice.serviceDownTimeCommandButton))
                        {
                                document.tableformservice.buttonCheckboxChecked.value='false';
                        }
                if ((document.tableformhost) && (document.tableformhost.hostDownTimeCommandButton))
                        {
                                document.tableformhost.buttonCheckboxChecked.value='false';
                	}
                enableDisableButton();
                return false;
        }
        return true;
}
function enableDisableButton()
{
        if ((document.tableform) && (document.tableform.buttonValidChoice.value=='true')){
                if (document.tableform.buttonCheckboxChecked.value=='true'){
                        if (document.tableform.serviceTotalsCommandsButton){
                                document.tableform.serviceTotalsCommandsButton.disabled=false;
                        }
                        if (document.tableform.hostTotalsCommandsButton){
                                document.tableform.hostTotalsCommandsButton.disabled=false;
                        }
                } else {
                        if (document.tableform.serviceTotalsCommandsButton){
                                document.tableform.serviceTotalsCommandsButton.disabled=true;
                        }
                        if (document.tableform.hostTotalsCommandsButton){
                                document.tableform.hostTotalsCommandsButton.disabled=true;
                        }
                }
	}
        if ((document.tableform) && (document.tableform.buttonCheckboxChecked) && (document.tableform.buttonCheckboxChecked.value=='true')){
		if (document.tableform.buttonValidChoice){
	                if (document.tableform.buttonValidChoice.value=='true'){
                	        if (document.tableform.serviceTotalsCommandsButton){
        	                        document.tableform.serviceTotalsCommandsButton.disabled=false;
	                        }
                        	if (document.tableform.hostTotalsCommandsButton){
                	                document.tableform.hostTotalsCommandsButton.disabled=false;
        	                }
	                } else {
                        	if (document.tableform.serviceTotalsCommandsButton){
                	                document.tableform.serviceTotalsCommandsButton.disabled=true;
        	                }
	                        if (document.tableform.hostTotalsCommandsButton){
                                	document.tableform.hostTotalsCommandsButton.disabled=true;
                        	}
                	}
		}
        }
	if ((document.tableformservice) && (document.tableformservice.buttonCheckboxChecked.value=='true')){
		if (document.tableform.buttonValidChoice.value=='true'){
                        if (document.tableformservice.serviceDownTimeCommandButton){
                                document.tableformservice.serviceDownTimeCommandButton.disabled=false;
                        }
		} else {
                        if (document.tableformservice.serviceDownTimeCommandButton){
                                document.tableformservice.serviceDownTimeCommandButton.disabled=true;
                        }
		}
	}
        if ((document.tableformhost) && (document.tableformhost.buttonCheckboxChecked.value=='true')){
                if (document.tableform.buttonValidChoice.value=='true'){
                        if (document.tableformhost.hostDownTimeCommandButton){
                                document.tableformhost.hostDownTimeCommandButton.disabled=false;
                        }
                } else {
                        if (document.tableformhost.serviceDownTimeCommandButton){
                                document.tableformhost.hostDownTimeCommandButton.disabled=true;
                        }
                }
        }
}
