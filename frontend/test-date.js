const jsdom = require("jsdom");
const { JSDOM } = jsdom;
const dom = new JSDOM(`<!DOCTYPE html><input type="date" id="d" max="9999-12-31" value="20025-06-20">`);
console.log(dom.window.document.getElementById("d").value);
