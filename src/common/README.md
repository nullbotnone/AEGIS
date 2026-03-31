# Legacy Simulation Primitives

`src/common/` holds the older simulation model used by several paper experiment runners.

## Why It Still Exists

The files here are not part of the real-cluster deployment path, but they are still required by:
- the synthetic attack suite
- the false-positive study
- the older baseline-comparison workflow
- some measured framework-path evaluation helpers

For new control-plane logic, use `src/framework/` instead.
