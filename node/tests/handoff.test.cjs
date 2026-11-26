"use strict";

const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const fs = require("node:fs");
const { tmpdir } = require("node:os");
const { join, resolve } = require("node:path");
const { test } = require("node:test");
const { HandoffError, openInherited } = require("workeros");

function setEnvironment(t, values) {
    const entries = Object.entries(values);
    const prior = entries.map(([key]) => [key, process.env[key]]);
    for (const [key, value] of entries) {
        process.env[key] = value;
    }
    t.after(() => {
        for (const [key, value] of prior) {
            if (value === undefined) {
                delete process.env[key];
            } else {
                process.env[key] = value;
            }
        }
    });
}

function bind(t, fd, key = "INPUT", access = "read") {
    const { dev, ino } = fs.fstatSync(fd, { bigint: true });
    setEnvironment(t, {
        WORKER_HANDOFF_ABI: "1",
        [`WORKER_HANDOFF_FD_${key}`]: String(fd),
        [`WORKER_HANDOFF_DEV_${key}`]: String(BigInt.asUintN(64, dev)),
        [`WORKER_HANDOFF_INO_${key}`]: String(BigInt.asUintN(64, ino)),
        [`WORKER_HANDOFF_ACCESS_${key}`]: access,
    });
}

function fixture(t, mode = "r", access = "read", key = "INPUT") {
    const directory = fs.mkdtempSync(join(tmpdir(), "workeros-node-"));
    const file = join(directory, "original");
    fs.writeFileSync(file, "abcdef");
    const fd = fs.openSync(file, mode);
    let cleanupFd = fd;
    t.after(() => {
        if (cleanupFd !== undefined) fs.closeSync(cleanupFd);
        fs.rmSync(directory, { recursive: true });
    });
    bind(t, fd, key, access);
    return { fd, file, directory, relinquish() { cleanupFd = undefined; } };
}

function expectCode(action, code) {
    assert.throws(action, { name: "HandoffError", code: `ERR_WORKER_HANDOFF_${code}` });
}

test("CommonJS and ESM use one public implementation", async () => {
    const esm = await import("workeros");
    assert.equal(esm.openInherited, openInherited);
    assert.equal(esm.HandoffError, HandoffError);
});

test("accepts only the named binding, ABI version, and canonical descriptor metadata", (t) => {
    const { fd } = fixture(t, "r", "read", "INPUT_2");
    delete process.env.WORKER_HANDOFF_FD_INPUT;
    expectCode(() => openInherited("INPUT"), "ENV");
    for (const binding of ["", "input_2", "2INPUT", "INPUT_2\n", "IN-PUT", null]) {
        assert.throws(() => openInherited(binding), TypeError);
    }
    assert.throws(() => openInherited("INPUT_2", { owned: true }), TypeError);
    assert.throws(() => openInherited("INPUT_2", { ownership: "shared" }), TypeError);
    process.env.WORKER_HANDOFF_ABI = "01";
    expectCode(() => openInherited("INPUT_2"), "ABI");
    process.env.WORKER_HANDOFF_ABI = "1";
    for (const fdText of ["", "0", "1", "2", `0${fd}`, `+${fd}`, `${fd}\n`, "0xff", "2147483648"]) {
        process.env.WORKER_HANDOFF_FD_INPUT_2 = fdText;
        expectCode(() => openInherited("INPUT_2", { ownership: "owned" }), "ENV");
    }
    process.env.WORKER_HANDOFF_FD_INPUT_2 = String(fd);
    const { WORKER_HANDOFF_DEV_INPUT_2: device, WORKER_HANDOFF_INO_INPUT_2: inode } = process.env;
    for (const dev of ["-1", `0${device}`, "18446744073709551616", "2.0"]) {
        process.env.WORKER_HANDOFF_DEV_INPUT_2 = dev;
        expectCode(() => openInherited("INPUT_2", { ownership: "owned" }), "ENV");
    }
    process.env.WORKER_HANDOFF_DEV_INPUT_2 = device;
    process.env.WORKER_HANDOFF_INO_INPUT_2 = String(BigInt(inode) + 1n);
    expectCode(() => openInherited("INPUT_2", { ownership: "owned" }), "IDENTITY");
    process.env.WORKER_HANDOFF_INO_INPUT_2 = inode;
    const input = openInherited("INPUT_2");
    assert.deepEqual([input.binding, input.device, input.inode], ["INPUT_2", BigInt(device), BigInt(inode)]);
    input.close();
    assert.equal(fs.fstatSync(fd).isFile(), true);
});

test("positional reads return actual byte counts and preserve the shared offset", (t) => {
    const { fd } = fixture(t);
    const starter = Buffer.alloc(1);
    assert.equal(fs.readSync(fd, starter, 0, 1, null), 1);
    assert.equal(starter.toString(), "a");
    const input = openInherited("INPUT");
    t.after(() => input.close());
    assert.equal(input.ownership, "borrowed");
    assert.equal(input.access, "read");
    assert.equal("fd" in input, false);
    const buffer = Buffer.alloc(3);
    assert.equal(input.readAt(buffer, 0n), 3);
    assert.equal(buffer.toString(), "abc");
    assert.equal(input.readAt(buffer, 5), 1);
    assert.equal(buffer[0], "f".charCodeAt(0));
    assert.equal(input.readAt(buffer, 6), 0);
    assert.equal(input.readAt(Buffer.alloc(0), 0), 0);
    for (const position of [undefined, null, -1, -1n, "0", 0.5, Infinity, 2 ** 53, 1n << 63n]) {
        assert.throws(() => input.readAt(buffer, position), RangeError);
    }
    assert.throws(() => input.readAt(new Uint8Array(1), 0), TypeError);
    assert.equal(fs.readSync(fd, starter, 0, 1, null), 1);
    assert.equal(starter.toString(), "b");
});

test("borrowed close releases the wrapper; owned close releases the exact FD once", (t) => {
    const file = fixture(t);
    bind(t, file.fd, "ALIAS");
    const borrowed = openInherited("INPUT");
    expectCode(() => openInherited("ALIAS", { ownership: "owned" }), "IN_USE");
    borrowed.close();
    borrowed.close();
    expectCode(() => borrowed.readAt(Buffer.alloc(1), 0), "CLOSED");
    assert.equal(fs.fstatSync(file.fd).isFile(), true);

    const owned = openInherited("ALIAS", { ownership: "owned" });
    assert.equal(owned.ownership, "owned");
    owned.close();
    file.relinquish();
    assert.throws(() => fs.fstatSync(file.fd), { code: "EBADF" });
    const next = fs.openSync(file.file, "r");
    try {
        assert.equal(next, file.fd);
        owned.close();
        assert.equal(fs.fstatSync(next).isFile(), true);
    } finally {
        fs.closeSync(next);
    }
});

test("checks actual open mode, including read-write and O_PATH", (t) => {
    const original = fixture(t, "r+", "read-write");
    const accessKey = "WORKER_HANDOFF_ACCESS_INPUT";
    process.env[accessKey] = "read";
    expectCode(() => openInherited("INPUT", { ownership: "owned" }), "ACCESS");
    process.env[accessKey] = "read-write";
    const input = openInherited("INPUT");
    try {
        assert.equal(input.access, "read-write");
        assert.equal("write" in input, false);
        assert.equal(input.readAt(Buffer.alloc(1), 0), 1);
    } finally {
        input.close();
    }

    for (const [key, mode] of [["WRITE_ONLY", fs.constants.O_WRONLY], ["PATH_ONLY", 0o10000000]]) {
        const fd = fs.openSync(original.file, mode);
        t.after(() => fs.closeSync(fd));
        bind(t, fd, key);
        expectCode(() => openInherited(key, { ownership: "owned" }), "ACCESS");
        assert.equal(fs.fstatSync(fd).isFile(), true);
    }
});

test("rejects non-regular, closed, or uninspectable descriptors without closing valid slots", (t) => {
    const original = fixture(t);
    const directoryFd = fs.openSync(original.directory, "r");
    t.after(() => fs.closeSync(directoryFd));
    bind(t, directoryFd, "DIRECTORY");
    expectCode(() => openInherited("DIRECTORY", { ownership: "owned" }), "FD");
    assert.equal(fs.fstatSync(directoryFd).isDirectory(), true);

    const gone = fs.openSync(original.file, "r");
    bind(t, gone, "GONE");
    fs.closeSync(gone);
    expectCode(() => openInherited("GONE", { ownership: "owned" }), "FD");

    t.mock.method(fs, "statfsSync", () => ({ type: 0 }));
    expectCode(() => openInherited("INPUT", { ownership: "owned" }), "FD");
    assert.equal(fs.fstatSync(original.fd).isFile(), true);
});

test("refuses to read or close a descriptor reused for a different file", (t) => {
    const original = fixture(t);
    const replacement = join(original.directory, "replacement");
    fs.writeFileSync(replacement, "replacement bytes");
    const input = openInherited("INPUT", { ownership: "owned" });
    fs.closeSync(original.fd);
    original.relinquish();
    const reused = fs.openSync(replacement, "r");
    t.after(() => fs.closeSync(reused));
    assert.equal(reused, original.fd);
    expectCode(() => input.readAt(Buffer.alloc(1), 0), "IDENTITY");
    expectCode(() => input.close(), "IDENTITY");
    input.close();
    assert.equal(fs.fstatSync(reused).isFile(), true);
});

test("Python WorkerRoster transfers the input FD to the Node package", () => {
    const root = resolve(__dirname, "../..");
    const run = spawnSync(process.env.PYTHON || "python3", [
        resolve(__dirname, "launch-example.py"), process.execPath,
        resolve(__dirname, "../examples/read-input.cjs"),
    ], { env: { ...process.env, PYTHONPATH: join(root, "src"), PYTHONDONTWRITEBYTECODE: "1" },
        encoding: "utf8", timeout: 30_000 });
    assert.ifError(run.error);
    assert.equal(run.status, 0, run.stderr);
    assert.equal(run.stdout, "Worker input\n");
});
