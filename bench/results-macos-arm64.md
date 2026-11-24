| Command | Mean Wall Time [ms] | Change | Factor |
|:---|---:|---:|:---|
| `version (cold start)` | 5.3 ± 4.9 |  |  |
| `get --reveal (1 of 100)` | 5.7 ± 1.0 | +6.7% |  |
| `run --only -- true` | 9.4 ± 3.2 | +77.0% | (1.8x slower) |
| `ls (100 secrets)` | 7.9 ± 1.2 | +48.5% | (1.5x slower) |
| `search (100 secrets)` | 7.9 ± 1.4 | +47.4% | (1.5x slower) |
