# Terminal animation transcripts

These are the text versions of the WorkerOS comics. Nothing plays on this page.

## Everything is green

An office joke about mistaking a status label for an observed outcome.

```text
lead       All three workers are green.
dashboard  I colored the labels.
renderer   I finished.
sync       I timed out.
auditor    Nobody started me. Uptime: flawless.
lead       Promote Audit.
```

## Report handoff

The shell renames an open file. A reader with an inherited descriptor still
reads the same file at offset zero.

```text
$ mv report.txt report-final-FINAL.txt
pathname  Please update my contact card.
reader    FD 7 reads 'W' at offset 0.
pathname  You saved me as a number?
reader    It's how we met.
```

## Strict custody

The writer tries to supply its own witness. The release requires independent
evidence and stops before any write or dispatch.

```text
writer    I brought a character witness.
release   Who?
writer    Me, wearing a lanyard.
release   Evidence absent.
result    Write skipped. Dispatch skipped.
```

[Back to the workerOS README](../../README.md).
