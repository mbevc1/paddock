// Ask before submitting a form that carries data-confirm; without script the form submits as is.
document.addEventListener("submit", function (ev) {
  "use strict";
  var message = ev.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    ev.preventDefault();
  }
}, true);

// Copy a data-copy value to the clipboard. The buttons stay hidden where the clipboard API is
// missing, which includes pages not served over HTTPS.
if (navigator.clipboard) {
  document.querySelectorAll("button[data-copy]").forEach(function (button) {
    "use strict";
    var label = button.textContent;
    button.hidden = false;
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(button.getAttribute("data-copy")).then(function () {
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = label; }, 1500);
      });
    });
  });
}

// Live notifications: count new ones in the header and list them on the notifications page.
(function () {
  "use strict";
  var badge = document.getElementById("unread");
  if (!badge || !window.EventSource) {
    return;
  }
  var source = new EventSource(badge.getAttribute("data-stream"));
  source.addEventListener("notification", function (ev) {
    var n = JSON.parse(ev.data);
    badge.textContent = String((parseInt(badge.textContent, 10) || 0) + 1);
    var list = document.getElementById("notifications");
    if (list) {
      var item = document.createElement("li");
      item.className = "unread";
      item.textContent = n.time + " · " + n.message;
      list.insertBefore(item, list.firstChild);
    }
  });
})();
