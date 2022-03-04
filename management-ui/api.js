/*
 * Copyright 2020 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * api.js: Javascript AJAX API handlers.
 */


/*
 * Takes a list of machines and resources. Sends AJAX 
 * request for each machine listed with each resource listed.
 * Refreshes measurements table on request return.
 */
function schedule(machines, resources) {
    bucket = document.getElementById("schedule-bucket");
    for (machine in machines) {
	for (resource in resources) {
	    list_item = document.createElement('span');
	    list_item.setAttribute('class', 'list');
	    list_item.innerHTML = "Measurement Pending... "
//	    list_item.innerHTML = "Using "+resources[resource] + " to measure " + machines[machine] + "...";
	    bucket.appendChild(list_item);
	    $.ajax({
		type: "POST",
		url: "mq_ui_test_driver.py",
		data: {'machine':machines[machine], 'resource':resources[resource]},
		success: function(response){
		    if (response['status'] != "ok") {
			alert("Error: " + response['message']);
			empty_bucket("schedule-bucket");
		    } else {
			build_measurements_table();
		    }
		}
	    });
	}
    }
}

/*
 * Returns the ids of all of the selected rows in a table
 * with id table_id
 */
function get_selected_ids(table_id) {
    table = document.getElementById(table_id);
    return $.map(table.getElementsByClassName('selected'), function(n, i) { 
	return n.id; 
    });
}

/*
 * Calls the appropriate functions to gather all selected machines
 * and resources and schedule every possible pair. 
 * Clears the selected class from all table entries.
 */
function schedule_gatherer() {
    document.activeElement.blur();
    selected_machine_ids = get_selected_ids('machine-table');
    selected_resource_ids = get_selected_ids('resource-table');

    if (selected_machine_ids.length == 0 || selected_resource_ids.length == 0) {
	alert("Please select at least one machine and resource");
	return;
    }
    
    schedule(selected_machine_ids, selected_resource_ids);
    
    $('.selected').removeClass('selected');
}

/*
 * Function to make JSON output for measurement data (and any other JSON lists)
 * slightly prettier in table.
 * Only alternatives seem to be installing an external plugin
 */
function pretty_print_json_list(cell) {
    pretty_cell = '';
    for ( i in cell ) {		    
	pretty_cell += JSON.stringify(cell[i]) + '</br>';
    }
    return pretty_cell;
}

function openErrors() {
    var list = document.getElementsByClassName("elcontent");

    for (e in list) {
        if (list[e].style.display == "none"){
                list[e].style.display = "block";
        }else{
                list[e].style.display = "none";
        }
    }
}

function openWarns() {
    var list = document.getElementsByClassName("wlcontent");

    for (e in list) {
        if (list[e].style.display == "none"){
                list[e].style.display = "block";
        }else{
                list[e].style.display = "none";
        }
    }
}
function openInfos() {
    var list = document.getElementsByClassName("ilcontent");

    for (e in list) {
        if (list[e].style.display == "none"){
                list[e].style.display = "block";
        }else{
                list[e].style.display = "none";
        }
    }
}
function openDebug() {
    var list = document.getElementsByClassName("dlcontent");

    for (e in list) {
        if (list[e].style.display == "none"){
                list[e].style.display = "block";
        }else{
                list[e].style.display = "none";
        }
    }
}


function pretty_print_results(cell) {
    return pretty_print_json_list(cell);
    //TODO: fix pretty printing (used to sort out collapsible report types )
/*
    var div = document.createElement('div');
    
    var outer_ul = document.createElement('ul');
    var error_li = document.createElement('li');
    var warn_li  = document.createElement('li');
    var info_li  = document.createElement('li');
    var debug_li = document.createElement('li');

    var elist = [];
    var wlist = [];
    var ilist = [];
    var dlist = [];

    for ( i in cell ) {
        //alert(cell[i].value);
	if(!cell[i] || !cell[i].value){
	    continue;
	} else if (cell[i].value.startsWith("[0]")) {
            elist.push(cell[i].key + " : " + cell[i].value.slice(3));
        } else if (cell[i].value.startsWith("[1]")) {
            wlist.push(cell[i].key + " : " + cell[i].value.slice(3));
        } else if (cell[i].value.startsWith("[2]")) {
            ilist.push(cell[i].key + " : " + cell[i].value.slice(3));
        } else if (cell[i].value.startsWith("[3]")) {
            dlist.push(cell[i].key + " : " + cell[i].value.slice(3));
        }
    }


    eul = document.createElement('ul')
    eul.setAttribute("style", "display: block;");
    eul.setAttribute("class", "elcontent");
    for (e in elist) {
            eli = document.createElement('li');
            eli.textContent = elist[e]
            eul.appendChild(eli);
    }

    wul = document.createElement('ul')
    wul.setAttribute("style", "display: none;");
    wul.setAttribute("class", "wlcontent");
    for (e in wlist) {
            eli = document.createElement('li');
            eli.textContent = wlist[e]
            wul.appendChild(eli);
    }

    iul = document.createElement('ul')
    iul.setAttribute("style", "display: none;");
    iul.setAttribute("class", "ilcontent");
    for (e in ilist) {
            eli = document.createElement('li');
            eli.textContent = ilist[e]
            iul.appendChild(eli);
    }

    dul = document.createElement('ul')
    dul.setAttribute("style", "display: none;");
    dul.setAttribute("class", "dlcontent");
    for (e in elist) {
            eli = document.createElement('li');
            eli.textContent = dlist[e]
            dul.appendChild(eli);
    }

    error_li.setAttribute("id", "errorlist");
    error_li.textContent = "ERROR (" + elist.length + ")";
    error_li.setAttribute("onclick", "openErrors()");
    error_li.appendChild(eul);
    warn_li.setAttribute("id", "warnlist");
    warn_li.textContent = "WARNINGS (" + wlist.length + ")";
    warn_li.setAttribute("onclick", "openWarns()");
    warn_li.appendChild(wul);
    info_li.setAttribute("id", "infolist");
    info_li.textContent = "INFO (" + ilist.length + ")";
    info_li.setAttribute("onclick", "openInfos()");
    info_li.appendChild(iul);
    debug_li.setAttribute("id", "debuglist");
    debug_li.textContent = "DEBUG (" + dlist.length + ")";
    debug_li.setAttribute("onclick", "openDebug()");
    debug_li.appendChild(dul);

    outer_ul.appendChild(error_li);
    outer_ul.appendChild(warn_li);
    outer_ul.appendChild(info_li);
    outer_ul.appendChild(debug_li);

    div.appendChild(outer_ul);

    return div*/
}

/*
 * Returns a table with the given title, id, preset headers, and content.
 *
 * headers is a list of table headers that should appear on the table in the
 * given order regardless of content.
 * If additional attributes are present in the content, they will be added to
 * the table header in order of appearance.
 * clickable is a boolean signifying whether the table contents should become 
 * selected when clicked on.
 */
function build_table(title, table_id, headers, content, clickable) {

    if (headers == null) { headers = []; }
    div = document.createElement('div');

    header = document.createElement('h3');
    header.innerHTML = title;
    div.appendChild(header);
    
    update_tag = document.createElement('span');
    update_tag.setAttribute('class', 'update');
    update_tag.innerHTML = " (Last Updated "+ Date() +")";
    header.appendChild(update_tag);

    table = document.createElement('table');
    table.setAttribute("id", table_id);
    
    header_row = document.createElement('tr');
    for (header in headers) {
	header_col = document.createElement('th');
	header_col.innerHTML = headers[header];
	header_row.appendChild(header_col);
    }
    table.appendChild(header_row);
    for (r in content) {
	row = content[r]
	entry_row = document.createElement('tr');
	if (typeof(row['_id']) == "object") { 
	    // Assume it's an objectID object XXX: is this a safe assumption?
	    entry_row.setAttribute("id", row['_id']['$oid']);
	} else {
	    alert("Invalid ID field from database. May be unable to schedule measurements.");
	}

	if (clickable) { entry_row.setAttribute('class', 'clickable'); }

	//Do existing columns in order
	for (i in headers) {
	    col = headers[i];
	    cell = row[col];
	    	    
	    entry_col = document.createElement('td');

	    if (cell == null) { cell = ""; }
	    if(col == "Result") {
	        if(cell == false) { 
		    cell = "FAIL";		    
		    entry_row.className += "failure";
		} else if (cell == true) {
		    cell = "PASS";
		    entry_row.className += "pass";
		}
		
		entry_col.innerHTML = cell;		
		entry_col.setAttribute("style", "text-align: left;");
	    }
	    else if (col == "Time") {
		entry_col.innerHTML = cell.split(".")[0];
	    } else {
		if(typeof(cell) == "object") {
		    cell = pretty_print_results(cell);
		    entry_col.innerHTML = cell;
		} else {
		    entry_col.innerHTML = cell;
		}
	    }
	    
	    entry_row.appendChild(entry_col);
	}
	
	// Search for potential new columns
	for (a in row) {
	    if ((a != '_id') && (a != 'request_id') && (headers.indexOf(a) < 0)) {
		// Add new attribute to table header
		headers.push(a);
		header_col = document.createElement('th');
		header_col.innerHTML = a;
		header_row.appendChild(header_col);

		// Make entry
		cell = row[a];
                entry_col = document.createElement('td');
		if (typeof(cell) == "object") { 
                        cell = pretty_print_results(cell)
                        entry_col.innerHTML = cell;
                } else {
                        entry_col.innerHTML = cell;
                }
		//entry_col = document.createElement('td');
		//entry_col.innerHTML = cell;
		entry_row.appendChild(entry_col);
	    } 
	}

	table.appendChild(entry_row);
    }	 

    div.appendChild(table);
    return div;
}

/*
 * Returns a table with the given title, id, preset headers, and content.
 *
 * headers is a list of table headers that should appear on the table in the
 * given order regardless of content.
 * If additional attributes are present in the content, they will be added to
 * the table header in order of appearance.
 * clickable is a boolean signifying whether the table contents should become 
 * selected when clicked on.
 */
function build_simple_table(title, table_id, content, clickable) {
    div = document.createElement('div');

    table = document.createElement('table');
    table.setAttribute("id", table_id);
    
    header_row = document.createElement('tr');
    header_col = document.createElement('th');
    header_col.innerHTML = title;
    header_row.appendChild(header_col);

    table.appendChild(header_row);

    for (r in content) {
	row = content[r]
	entry_row = document.createElement('tr');
	if (typeof(row['_id']) == "object") { 
	    // Assume it's an objectID object XXX: is this a safe assumption?
	    entry_row.setAttribute("id", row['_id']['$oid']);
	} else {
	    alert("Invalid ID field from database. May be unable to schedule measurements.");
	}

	if (clickable) { entry_row.setAttribute('class', 'clickable'); }

	// Just do the 'name' column under the 'title' header
	col = "name";
	cell = row[col];

        entry_col = document.createElement('td');
	
	if (cell == null) { cell = ""; }
	entry_col.innerHTML = cell;
	entry_row.appendChild(entry_col);

	table.appendChild(entry_row);
    }	 

    div.appendChild(table);   

    return div;
}

/* 
 * Empties the machine-bucket, queries for all the machines, and creates the
 * machines table
 */
function build_machine_table() {
    var callback = function(response) {
	if (response['status'] == 'ok') {
	    bucket = document.getElementById("machine-bucket");
	    table = build_simple_table("Machines", "machine-table", response['machines'], true);
	    
	    empty_bucket("machine-bucket");
	    bucket.appendChild(table);
	} else {
	    alert("build_machine_table error: "+response['message']);
	}
    }

    var request = {
	url: 'db_querier.py',
	type: 'POST',
	data: {'what':'all_machines'},
	success: callback,
    }; 
    return $.ajax(request);    
}

/* 
 * Empties the resource-bucket, queries for all of the resources in the database, 
 * and builds the resources table
 */
function build_resource_table() {
    var callback = function(response) {
	if (response['status'] == 'ok') {
	    bucket = document.getElementById("resource-bucket");
	    table = build_simple_table("Resources", "resource-table", response['resources'], true);

	    empty_bucket("resource-bucket");
	    bucket.appendChild(table);
	} else {
	    alert("build_resource_table error: "+response['message']);
	}
    }

    var request = {
	url:  'db_querier.py',
	type: 'POST',
	data: {'what': 'all_resources'},
	success: callback,
    }; 
    return $.ajax(request);    
}

/*
 * Empties the measurement-bucket and queries the database for the most recent 
 * measurements taken
 */
function build_measurements_table() {
    var callback = function(response) {
	if (response['status'] == 'ok') {
	    bucket = document.getElementById("measurement-bucket");
	    table = build_table("Measurements", "measurement-table", ['Time', 'Result'], response['measurements'], false);
	    
	    empty_bucket("measurement-bucket");
	    empty_bucket("schedule-bucket");
	    bucket.appendChild(table);

	} else {
	    alert("build_measurements_table error: "+response['message']);
	}
    }

    var request = {
	url:  'db_querier.py',
	type: 'POST',
	data: {'what':'recent_measurements'},
	success: callback,
    }; 
    return $.ajax(request);
}

/*
 * Remove all the children nodes in a given bucket
 */
function empty_bucket(bucket) {
    bucket = document.getElementById(bucket);
    while (bucket.hasChildNodes()) {
	bucket.removeChild(bucket.lastChild);
    }
}

/*
 * Gathers user entries and adds machine to database
 */ 
function add_machine() {
    document.activeElement.blur();

    name        = document.getElementsByName("machine-name")[0].value;
    fingerprint = document.getElementsByName("machine-fingerprint")[0].value;
    ip          = document.getElementsByName("machine-ip")[0].value;
    port        = document.getElementsByName("machine-port")[0].value;
   
    $.ajax({
	type: "POST",
	url: "addMachineConnector.py",
	data: {
	    "name"       :name, 
	    "fingerprint":fingerprint,
	    "ip"         :ip, 
	    "port"       :port, 
	},
	success: function(response) {
	    alert(response['message']);
	    if (response['status'] == "ok"){
		$(".machine-input").val('');
		location.reload()
	    }
	}
    });
}

/*
 * Gathers user entries and adds resource to database 
 */
function add_resource() {
    document.activeElement.blur();
    
    name  = document.getElementsByName("resource-name")[0].value;

    $.ajax({
	type: "POST",
	url: "addResourceConnector.py",
	data: {
	    "name" :name, 
	},
	success: function(response) {
	    alert(response['message']);
	    if (response['status'] == "ok"){
		$(".resource-input").val('');
		location.reload()
	    }
	}
    });
}
