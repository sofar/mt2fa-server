
var urlParams;
(window.onpopstate = function () {
	var match,
		pl     = /\+/g,  // Regex for replacing addition symbol with a space
		search = /([^&=]+)=?([^&]*)/g,
		decode = function (s) { return decodeURIComponent(s.replace(pl, " ")); },
		query  = window.location.search.substring(1);

	urlParams = {};
	while (match = search.exec(query))
		urlParams[decode(match[1])] = decode(match[2]);
})();

// Let the user know JS is working by removing the "JS is needed" text
document.getElementById("c").innerHTML = "Submitting confirmation data...";

// Create JSON data to post
var data = {};
data["token"] = urlParams["t"];
data["request_type"] = "CONFIRM";

// POST it
var xhr = new XMLHttpRequest();
xhr.open("POST", "/mt2fa", true);
xhr.setRequestHeader("Content-Type", 'application/json');
xhr.send(JSON.stringify(data))

xhr.onreadystatechange = function() {
	if (xhr.readyState === XMLHttpRequest.DONE && xhr.status == 200) {
		// Parse reply and display msg to user
		var data = JSON.parse(xhr.responseText);
		if (data.result == "CONFIRMOK") {
			document.getElementById("c").innerHTML = "OK: " + data.info;
		} else {
			document.getElementById("c").innerHTML = "ERROR: " + data.result + " - " + data.info;
		}
	}
};
