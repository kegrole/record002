import { query, readParam } from "./config.js";

function renderInto(element, html) {
  element.innerHTML = html;
}

const panel = document.getElementById("profile-panel");
const nickname = readParam("nickname");
renderInto(panel, nickname);
// Constant assignment must not be reported.
panel.dataset.label = "static";
// Tainted navigation sink reached through URLSearchParams.
const next = new URLSearchParams(location.hash.slice(1)).get("next");
location.href = next;
void query;
