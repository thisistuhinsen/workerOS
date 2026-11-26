"use strict";

const { openInherited } = require("workeros");

const input = openInherited("INPUT", { ownership: "owned" });
const bytes = Buffer.alloc(64);
let count;
try {
    count = input.readAt(bytes, 0);
} finally {
    input.close();
}
process.stdout.write(bytes.subarray(0, count));
