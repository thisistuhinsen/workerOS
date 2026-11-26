"use strict";

const fs = require("node:fs");

function main() {
    const value = process.env.WORKER_HANDOFF_FD_INPUT;
    const fd = Number(value);
    if (process.env.WORKER_HANDOFF_ABI !== "1" || !Number.isInteger(fd)
        || fd < 3 || fd > 0x7fffffff || String(fd) !== value) {
        return 2;
    }

    const byte = Buffer.alloc(1);
    try {
        try {
            const count = fs.readSync(fd, byte, 0, 1, 0);
            return count === 1 && byte[0] === 0x57 ? 0 : 1;
        } finally {
            fs.closeSync(fd);
        }
    } catch (error) {
        console.error(error.message);
        return 1;
    }
}

process.exitCode = main();
