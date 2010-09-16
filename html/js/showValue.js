function showValue(arg,schedule_host_check,schedule_host_svc_check,form) {
	if (arg!='nothing'){
		if (form=='tableform'){document.tableform.hiddencmdfield.value = arg;}
		if (form=='tableformhost'){document.tableformhost.hiddencmdfield.value = arg;}
		if (form=='tableformservice'){document.tableformservice.hiddencmdfield.value = arg;}
		// Set the value to true.
        	if (form=='tableform'){document.tableform.buttonValidChoice.value = 'true';}
		if (form=='tableformhost'){document.tableformhost.buttonValidChoice.value = 'true';}
		if (form=='tableformservice'){document.tableformservice.buttonValidChoice.value = 'true';}

		if (arg==schedule_host_check || arg==schedule_host_svc_check) {
			if (form=='tableform'){document.tableform.hiddenforcefield.value = 'yes';}
			if (form=='tableformhost'){document.tableformhost.hiddenforcefield.value = 'yes';}
			if (form=='tableformservice'){document.tableformservice.hiddenforcefield.value = 'yes';}
		} else {
			if (form=='tableform'){document.tableform.hiddenforcefield.value = 'no';}
			if (form=='tableformhost'){document.tableform.hiddenforcefield.value = 'no';}
			if (form=='tableformservice'){document.tableform.hiddenforcefield.value = 'no';}
        	}
		enableDisableButton();
	} else {
		// Set the value to false, cant submit
		if (form=='tableform'){document.tableform.buttonValidChoice.value = 'false';}
		if (form=='tableformhost'){document.tableformhost.buttonValidChoice.value = 'false';}
		if (form=='tableformservice'){document.tableformservice.buttonValidChoice.value = 'false';}
		enableDisableButton();
	}
}
