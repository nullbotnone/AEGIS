# Service Wrappers

`src/services/` contains long-running service processes built around the framework.

## Current Service

- `verifierd.py`: centralized verifier daemon with:
  - profile registration
  - evidence submission
  - audit access
  - local Unix-socket administration
  - optional TCP bootstrap listener for collector submission

This is the process you run on the verifier host during real-cluster deployment.
