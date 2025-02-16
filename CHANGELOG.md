# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Fixed

### Changed

### Removed

## [1.0.1] - 2025-02-11

### Added

- V1.0.1 Folders for YARA, Snort, and Sigma rules
- V1.0.1 Added YARA detection rule for Matanbuchus
- V1.0.1 Added YARA detection rule for QBOT
- V1.0.1 Added YARA detection rule for AsyncRAT
- V1.0.1 Added YARA detection rule for DarkGate
- V1.0.1 Added YARA detection rule for Latrodectus
- V1.0.1 Added YARA detection rule for Pikabot
- V1.0.1 Added YARA detection rule for IcedID
- v1.0.1 Added Snort rules file
- v1.0.1 Added linux folder inside Sigma 
- v1.0.1 Added Windows folder inside Sigma
- v1.0.1 Added Sigma rule to detect suspicious use of mshta using javascript for Windows
- v1.0.1 Added Sigma rule to detect suspicious use of 'find' on linux
- v1.0.1 Added Sigma rule to detect suspicious use of 'awk' on linux
- v1.0.1 Added Scripts folder 
- v1.0.1 Added post-process python script to ensure correct fields and rule formatting.
- v1.0.1 Added Workflow to automatically validate Sigma rules when changes are pushed to a branch that isnt main or a PR with base main is opened or updated.

### Changed

- Corrected version mismatch inside CHANGELOG.md
- Updated Sigma_template to include a blank rule template for reference