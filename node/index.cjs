"use strict";

const fs = require("node:fs");

// Linux UAPI open flags and the procfs filesystem type.
const O_ACCMODE = 0o3;
const O_PATH = 0o10000000;
const PROC_SUPER_MAGIC = 0x9fa0;
const MAX_FD = 0x7fffffffn;
const MAX_ID = (1n << 64n) - 1n;
const MAX_POSITION = (1n << 63n) - 1n;
const activeDescriptors = new Set();

class HandoffError extends Error {
    constructor(code, message, options) {
        super(message, options);
        this.name = "HandoffError";
        this.code = `ERR_WORKER_HANDOFF_${code}`;
    }
}

function decimal(value, name, min, max) {
    if (typeof value === "string" && value.length <= 20 && /^[0-9]+$/.test(value)) {
        const number = BigInt(value);
        if (String(number) === value && number >= min && number <= max) {
            return number;
        }
    }
    throw new HandoffError("ENV", `${name} must be a canonical decimal from ${min} to ${max}`);
}

function descriptorFacts(fd, expected) {
    const fdinfoPath = `/proc/self/fdinfo/${fd}`;
    let stats;
    let fdinfo;
    try {
        stats = fs.fstatSync(fd, { bigint: true });
        if (stats.isFile() && fs.statfsSync(fdinfoPath).type === PROC_SUPER_MAGIC) {
            fdinfo = fs.readFileSync(fdinfoPath, "utf8");
        }
    } catch (cause) {
        throw new HandoffError("FD", `Cannot inspect inherited descriptor ${fd} and its Linux fdinfo`, { cause });
    }
    if (!stats.isFile()) {
        throw new HandoffError("FD", `Descriptor ${fd} is not a regular file`);
    }
    if (fdinfo === undefined) {
        throw new HandoffError("FD", `Descriptor ${fd} requires Linux procfs fdinfo`);
    }

    const flagsText = /^flags:[\t ]+([0-7]{1,11})$/m.exec(fdinfo)?.[1];
    const inodeText = /^ino:[\t ]+([0-9]{1,20})$/m.exec(fdinfo)?.[1];
    if (flagsText === undefined || inodeText === undefined) {
        throw new HandoffError("FD", `Missing kernel flags or inode for descriptor ${fd}`);
    }

    const device = BigInt.asUintN(64, stats.dev);
    const inode = BigInt.asUintN(64, stats.ino);
    if (device !== expected.device || inode !== expected.inode || BigInt(inodeText) !== inode) {
        throw new HandoffError("IDENTITY", `Descriptor ${fd} does not match the declared device and inode`);
    }

    const flags = Number.parseInt(flagsText, 8);
    const accessMode = flags & O_ACCMODE;
    const access = accessMode === fs.constants.O_RDONLY ? "read"
        : accessMode === fs.constants.O_RDWR ? "read-write" : undefined;
    if ((flags & O_PATH) !== 0 || access === undefined || access !== expected.access) {
        throw new HandoffError("ACCESS", `Descriptor ${fd} is not readable with the declared access mode`);
    }
    return { device, inode, access };
}

function openInherited(binding, options = {}) {
    if (process.platform !== "linux" || !["x64", "arm64"].includes(process.arch)
        || Number(process.versions.node.split(".")[0]) < 22) {
        throw new HandoffError("PLATFORM", "Inherited descriptors require Node.js 22+ on Linux x64 or ARM64");
    }
    if (typeof binding !== "string" || !/^[A-Z]/.test(binding) || /[^A-Z0-9_]/.test(binding)) {
        throw new TypeError("binding must start with an uppercase ASCII letter and use only uppercase ASCII letters, digits, and underscores");
    }
    if (options === null || typeof options !== "object" || Array.isArray(options)
        || Object.keys(options).some((key) => key !== "ownership")) {
        throw new TypeError("The only supported option is ownership");
    }
    const { ownership = "borrowed" } = options;
    if (ownership !== "borrowed" && ownership !== "owned") {
        throw new TypeError('ownership must be "borrowed" or "owned"');
    }
    if (process.env.WORKER_HANDOFF_ABI !== "1") {
        throw new HandoffError("ABI", "WORKER_HANDOFF_ABI must be exactly 1");
    }

    const fdName = `WORKER_HANDOFF_FD_${binding}`;
    const devName = `WORKER_HANDOFF_DEV_${binding}`;
    const inoName = `WORKER_HANDOFF_INO_${binding}`;
    const accessName = `WORKER_HANDOFF_ACCESS_${binding}`;
    const fd = Number(decimal(process.env[fdName], fdName, 3n, MAX_FD));
    const device = decimal(process.env[devName], devName, 0n, MAX_ID);
    const inode = decimal(process.env[inoName], inoName, 0n, MAX_ID);
    const access = process.env[accessName];
    if (access !== "read" && access !== "read-write") {
        throw new HandoffError("ACCESS", `${accessName} must be read or read-write`);
    }
    if (activeDescriptors.has(fd)) {
        throw new HandoffError("IN_USE", `Descriptor ${fd} already has an open workeros handle`);
    }

    const actual = descriptorFacts(fd, { device, inode, access });
    activeDescriptors.add(fd);
    let closed = false;

    return Object.freeze({
        binding,
        ownership,
        ...actual,
        readAt(buffer, position) {
            if (closed) {
                throw new HandoffError("CLOSED", `The ${binding} handle is closed`);
            }
            if (!Buffer.isBuffer(buffer)) {
                throw new TypeError("The read buffer must be a Buffer");
            }
            if (typeof position === "bigint"
                ? position < 0n || position > MAX_POSITION
                : !Number.isSafeInteger(position) || position < 0) {
                throw new RangeError("The file position must be a nonnegative safe integer or 64-bit signed bigint");
            }
            descriptorFacts(fd, actual);
            return fs.readSync(fd, buffer, 0, buffer.length, position);
        },
        close() {
            if (closed) {
                return;
            }
            closed = true;
            activeDescriptors.delete(fd);
            if (ownership === "owned") {
                // Refuse a detected stale/rebound slot and never retry close.
                descriptorFacts(fd, actual);
                fs.closeSync(fd);
            }
        },
    });
}

module.exports = { HandoffError, openInherited };
