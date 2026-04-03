const _ = require("lodash");

function render(name) {
  return _.template("hello <%= user %>")({ user: name });
}

console.log(render("fixture"));
