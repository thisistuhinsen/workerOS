# Terminal animation transcripts

## One small ticket

A joke about making infrastructure for a single job. The terminal lines are
a cartoon, not literal workerOS output.

```text
ticket   Run one thumbnail worker.
meeting  Obviously, Redis.
meeting  And a dashboard for Redis.
meeting  The dashboard needs a worker.
worker   thumbnail: exit 0
ticket   Can we put the thumbnail in charge?
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
