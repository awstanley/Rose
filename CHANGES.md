# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [0.1.1] - 2016-04-02

This release comes from testing the original target project (`ermor-pretender`) on AMD64 and discovering various oversights not seen in the original testing done to the ported code (which was ported to Windows).  Rewrites and attempts to create clarity have caused issues which have since been fixed.

### Added
- Significant number of `__ROSE_LOUD__` debug print outs for debugging.
- Missing includes to `Rose.cpp`.

### Changed
- Added `-page` to the SetProtection Linux command (fixing the segfaults caused by bad protection settings).

## [0.1.0] - 2016-04-02

### Added
- Example data, documentation, change logs, etc..

## [0.0.x] - 2016-04-01

The library code has been liberated from external project (`ermor-pretender`), with the aim of being useful beyond the scope of that proof of concept.

### Added
- Initial code.

### Changes (from pre-release embedded)
- Licence is now BSD to match Capstone and to keep life simple;
- Library now has a name (`Rose`).