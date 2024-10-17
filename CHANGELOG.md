# Changelog

## [2.0-1] - 2024-10-17
### Added
- Extended place support for arbitrary Copland place attributes
- Introduced support for PhotonOS 5.0
- Developed process memory mapping appraisal ASP
- Developed file hash value appraisal ASP
- Updated Copland Compiler to generate APB code using basic Copland phrases expressing single place attestations
- Created documentation which guides integrators through creating new Maat APBs and ASP
- Altered measurement contract format to represent TPM signatures and quotes
- Addressed interoperability bugs between TPM enabled and TPM disabled Maat instances
- Addressed bugs in Maat’s XML parsing

## [1.7-1] - 2024-05-17
### Added
- Addition of APBs, ASPs, and supporting policy files to represent a basic integration of existing measurement tools into Maat
- Official support for Debian 11 and Ubuntu 23.10
- Added new ELF file attribute appraisal ASP
- Resolved RHEL 9 package build errors
- Resolved SELinux policy issues
- Increased verbosity of unit tests
- Added more content to the layered attestation use case documentation

## [1.6-1] - 2024-03-21
### Added
- Introduction of full OpenSSL v3 support within Maat
- Resolved system information ASP information collection error on some platforms
- Resolved bug in system information appraisal ASP configuration parsing
- Resolved input parsing error within the graph-shell utility
- Resolved correctness bug related to improper variable initialization in the memory mapping ASP

## [1.5-1] - 2023-12-08
### Added
- Updated the system information appraisal ASP to support dynamic reconfiguration
- Improved logical flow of documentation through changes to wording and section ordering
- Fixed to documentation rendering of code, diagrams, etc.
- Inclusion of section on complex attestation use-case into documentation
- Resolved build warnings raised by compilers on various platforms
- Introduced signal for ASPs to indicate that a measurement was unable to be taken, integrated into GOT measurement
- Changed ASP error signaling, allowing for more fine grained error status to be returned to the calling APB
- Developed ASP to perform appraisal of GOT/PLT measurer results, which was formerly handled in the Userspace Appraiser APB
- Remediated measurement issues leading to false positive detection of GOT/PLT errors
- Resolved memory corruption issues within TPM code
- Integrated Valgrind analysis into CI and resolved memory leaks that were identified
- Incorporate more testing platforms into CI, including Ubuntu 22 and RHEL8 with TPM support
- Added code coverage reports to CI
- Introduced numerous CI and unit test fixes

## [1.4-1] - 2023-04-04
### Added
- TPM2 support
- Removed ROADMAP.md
- Addressed isses from static analysis
- Fixed some memory leaks and Valgrind issues
- Quality improvements to RPM packaging, SELinux integration
- Added layered attestation demo

## [1.3-1] - 2022-02-28
### Added
- Carry nonce through scenarios with multiple negotiations
- Sequence diagram based user interface for observing attestation manager interactions
- Passport use case demonstration
- IoT Assurance work to contributions
- CentOS 8 support
- Notion of Copland 'place' in selection/negotiation policy

## [1.2-1] - 2020-03-12
### Added
- Initial Open Source Release



