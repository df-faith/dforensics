var streaming_interval = null;

/* === FUNCTION CALLS === */

function functionCall(mode, analyser, cmd) {
    /* The function call triggers a command either on the monitor or the workstation.
     * Furthermore, the loading animation is triggered.
     * mode = analyse | acquisition
     * analyser = rekall | sleuthkit
     * cmd = [cmd, arg1, arg2, ...]*/

    var xhr = new XMLHttpRequest();
    xhr.open('POST', '/cmd');
    xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
    jsn = JSON.stringify({"mode":mode, "analyser":analyser, "command":cmd});
    console.log(jsn);
    xhr.send(jsn);
    var headTitle = document.getElementsByClassName("loading-headline")[0];
    headTitle.setAttribute("active", "true");
}

function changeVM(vm, profile) {
    /* Change the vm by sending command to monitor */

    d = document.getElementById("vm-name");
    d.innerHTML = "(" + vm + ")";
    functionCall('acquisition','rekall', ['change_vm', vm, profile]);
}

function changeDump(e, tool) {
    /* Change the dump which is analysed by sending command to workstation */

    var filename = e.innerHTML;
    var d = null;
    if (tool == "sleuthkit") {
        d = document.getElementById("sdump");
        document.getElementById("filesystemButton").style.backgroundColor = "";
    } else if (tool == "rekall") {
        d = document.getElementById("mdump");
    }
    d.innerHTML = "(" + filename + ")";
    functionCall('analysis', tool, ['change_dump',filename]);
}

function get_filesystem(offset) {
    functionCall('analysis', 'sleuthkit', ['get_filesytem',offset]);
    document.getElementById("filesystemButton").style.backgroundColor = "lightgreen";
    filesystemModal.style.display = "none";
}

function tskListDir() {
    var path = document.getElementById('listDirPath').value;
    functionCall('analysis', 'sleuthkit', ['get_listdir', path]);
    getListDirPathModal.style.display = "none";
}

function tskGetFile() {
    var path = document.getElementById('getFilePath').value;
    var outPath = document.getElementById('getFileOutPath').value;
    functionCall('analysis', 'sleuthkit', ['cat_file', path, outPath]);
    getFilePathModal.style.display = "none";
}

function tskMmcat() {
    var offset = document.getElementById('mmcatOffset').value;
    var size = document.getElementById('mmcatSize').value;
    var outPath = document.getElementById('mmcatOutPath').value;
    functionCall('analysis', 'sleuthkit', ['mmcat', offset, size, outPath]);
    mmcatModal.style.display = "none";
}

function rklMemmapAnalysis() {
    var pid = document.getElementById('memmapPidAnalysis').value;
    functionCall('analysis', 'rekall', ['get_memmap', pid]);
    memmapModalAnalysis.style.display = "none";
}

function rklMemmapAcquisition() {
    var pid = document.getElementById('memmapPidAcquisition').value;
    functionCall('acquisition', 'rekall', ['get_memmap', pid]);
    memmapModalAcquisition.style.display = "none";
}
function rklMemdumpAnalysis() {
    var pid = document.getElementById('memdumpPidAnalysis').value;
    var path = document.getElementById('memdumpPathAnalysis').value;
    functionCall('analysis', 'rekall', ['get_memdump', pid, path]);
    memdumpModalAnalysis.style.display = "none";
}

function rklMemdumpAcquisition() {
    var pid = document.getElementById('memdumpPidAcquisition').value;
    var path = document.getElementById('memdumpPathAcquisition').value;
    functionCall('acquisition', 'rekall', ['get_memdump', pid, path]);
    memdumpModalAcquisition.style.display = "none";
}

/* === GUI GENERAL === */

function toggleSidebar() {
    /* Switches between acquisition and analysis sidebar */

    var acquisition = document.getElementById('acquisition');
    var analysis = document.getElementById('analysis');
    if (acquisition.style.display === "none") {
        analysis.style.display = "none";
        acquisition.style.display = "block";
    } else {
        analysis.style.display = "block";
        acquisition.style.display = "none";
    }
}

function showMModal(id) {
    /* Open a modal on button click */
    
    var modal = document.getElementById(id);
    modal.style.display = "block";

    // The close button
    var close = modal.childNodes[3].childNodes[1]
    close.onclick = function() {
        modal.style.display = "none";
    }

    // Load partition list when opening corresponding modal
    if (id == "filesystemModal") {
        loadPartitionsList();
    }
}

function loadPartitionsList() {
    /* Request current partitions list from server to add it to the filesytem modal */

    var dumpXhr = new XMLHttpRequest();
    dumpXhr.responseType = 'json';
    dumpXhr.open('GET', '/partitions');
    dumpXhr.send()
    dumpXhr.onreadystatechange = (e) => {
        if(dumpXhr.readyState === 4 && dumpXhr.status === 200) {
            partitionList = document.getElementById("partitionList")
            partitionList.innerHTML = "";
            content = dumpXhr.response;
            console.log(content);
            for (var key in content) {
                partitionList.innerHTML += '<div class="button"'
                    + 'onclick="get_filesystem(' + content[key] + ');">'
                    + key + " (" + content[key] + ")"+ '</div>';
            }
        }
    }
}

function refreshDumpList() {
    /* Refresh the list of dumps by requesting current list from server */

    var dumpXhr = new XMLHttpRequest();
    dumpXhr.responseType = 'json';
    dumpXhr.open('GET', '/dumps/list');
    dumpXhr.send()
    dumpXhr.onreadystatechange = (e) => {
        if(dumpXhr.readyState === 4 && dumpXhr.status === 200) {
            blockM = document.getElementById("mdump-block");
            blockM.innerHTML = '<div class="dropdown-button"'
                             + 'onclick="changeDump(this, \'rekall\');">'
                             + 'nothing</div>';
            blockS = document.getElementById("sdump-block")
            blockS.innerHTML = '<div class="dropdown-button"'
                             + 'onclick="changeDump(this, \'sleuthkit\');">'
                             + 'nothing</div>';
            content = dumpXhr.response;
            content["memory"].forEach(function(item) {
                blockM.innerHTML += '<div class="dropdown-button"'
                             + 'onclick="changeDump(this, \'rekall\');">'
                             + item + '</div>';
            });
            content["storage"].forEach(function(item) {
                blockS.innerHTML += '<div class="dropdown-button"'
                             + 'onclick="changeDump(this, \'sleuthkit\');">'
                             + item + '</div>';
            });
        }
    };
}

/* === GUI FUNCITONS === */

function removeLog(logId) {
    /* remove a logfile */

    var dumpXhr = new XMLHttpRequest();
    dumpXhr.open('GET', '/log/remove/' + logId);
    dumpXhr.send()
    var elements = document.getElementsByClassName("log-" + logId);
    while(elements.length > 0) elements[0].remove();
}

function resetSession() {
    /* reset the session in backend and clear frontend */

    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/log/reset');
    xhr.onreadystatechange = function() {
        if (xhr.readyState === 4 && xhr.response == "ok") {
            var sd = document.getElementById("sdump");
            var md = document.getElementById("mdump");
            sd.innerHTML = "(nothing)";
            md.innerHTML = "(nothing)";
            document.getElementById("filesystemButton").style.backgroundColor = "";

            clearInterval(streaming_interval);
            streaming_interval = null;

            var output = document.getElementById("streaming");
            output.textContent = "";
            var headTitle = document.getElementsByClassName("loading-headline")[0];
            headTitle.setAttribute("active", "false");

            streaming();
        }
    }
    xhr.send()
}

function streaming() {
    /* Send request to /stream_kafka to receive messages and display them */
    
    var output = document.getElementById("streaming");
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '/stream_kafka');
    xhr.send();

    streaming_interval = setInterval(function() {
        var res = xhr.responseText;
        if (output.textContent != res) {
            var headTitle = document.getElementsByClassName("loading-headline")[0];
            // deactivate title loading animation
            headTitle.setAttribute("active", "false");
            output.textContent = xhr.responseText;
        }
    }, 1000);
}

/* === INIT === */

window.onload = function () {
    // When the user clicks anywhere outside of the modal, close it
    window.onclick = function(event) {
        if(event.target.classList.contains("modal")) {
            event.target.style.display = "none";
        }
    }

    // Prepar title animation
    var title = "DForensics"; 
    var headTitle = document.getElementsByClassName("loading-headline")[0];
    headTitle.removeChild(headTitle.childNodes[0]);
    for (var i = 0; i < title.length; i++) {
        var span = document.createElement("span");
        span.innerHTML = title[i];
        headTitle.appendChild(span);
    }

    streaming();
    refreshDumpList();
}
