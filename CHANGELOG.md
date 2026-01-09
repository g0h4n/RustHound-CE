# Changelog

## 2.4.7 - 2026-01-09

Add [obfstr](https://docs.rs/obfstr/latest/obfstr/) for string obfuscation support, required by other projects.

## 2.4.6 - 2026-01-09

Update Zip Compression Method. Currently the zip is in stored format, opting to change to deflated to save disk space.
Special thanks to [Spyr0](https://github.com/spyr0-sec) for pull request [#28](https://github.com/g0h4n/RustHound-CE/commit/0b33a16eb77044c8f68b6643c542c70b1e455afc).

## 2.4.5 - 2025-12-01

Testing the GitHub Workflow Action for Rust compilation. Special thanks to [@aancw](https://github.com/aancw) for providing the GitHub workflow action.

## 2.4.4 - 2025-11-18

Fix issues where group imports contained members with null ObjectIdentifiers, and improve shortest-path resolution from users to Domain Admins involving accounts such as `ADCSESC1`, `ADCSESC4`, etc. 

## 2.4.3 - 2025-11-04

Fix issue [#15](https://github.com/g0h4n/RustHound-CE/issues/15) by removing object with no Object Identifier.
Thanks a lot for [IppSec](https://github.com/IppSec) for your contribution! More information about the fix directly from the pull request [#20](https://github.com/g0h4n/RustHound-CE/pull/20)

## 2.4.2 - 2025-10-30

Fix issue [#18](https://github.com/g0h4n/RustHound-CE/issues/18) regarding ACL issues. [acl.rs](https://github.com/g0h4n/RustHound-CE/blob/main/src/enums/acl.rs) 
Thanks a lot for [0xdf223](https://github.com/0xdf223) for your contribution! More information about ACL fixing directly from the pull request [#19](https://github.com/g0h4n/RustHound-CE/pull/19)

Issues Fixed:

- `AddMember` rights on groups were not being detected;
- `ForceChangePassword` rights were missing for inherited ACEs;
- `WriteSPN` and other property-specific write rights were not captured;
- Any ACEs with property GUIDs when inherited object type filtering was present.

## 2.4.1 - 2025-10-21

Fix issue [#16](https://github.com/g0h4n/RustHound-CE/issues/16) the [users.rs](https://github.com/g0h4n/RustHound-CE/blob/main/src/objects/user.rs#L186) code panic when trying to split on "/" if not present.
Now fix in version 2.4.1 in main branch.

**Rollback to version 2.4.0** and push PTH version into specific branch: [feat/ntlm-support](https://github.com/g0h4n/RustHound-CE/tree/feat/ntlm-support) I can't validate the pull request in the main branch because I can't publish it on [crates.io](crates.io) if ldap3 don't implement the feature ntlm create by [z-jxy](https://github.com/z-jxy).

The branch [feat/ntlm-support](https://github.com/g0h4n/RustHound-CE/tree/feat/ntlm-support) introduces the new `-H`,`--ldapntlmhash` options, enabling NTLM authentication using NT hash for pass the hash.
All information regarding the code changes can be found in the original pull request: [#17](https://github.com/g0h4n/RustHound-CE/pull/17)
Big thanks to [z-jxy](https://github.com/z-jxy) for the excellent work and for implementing this much-needed feature, as requested in issue [#5](https://github.com/g0h4n/RustHound-CE/issues/5)

## 2.4.0 - 2025-06-27

This release introduces the new `--cache`,`--cache-buffer`,`--resume` features, allowing LDAP dump results to be store and load from disk instead of in memory, making it possible to handle much larger datasets with significantly lower RAM usage (saving approximately 70% of memory at peak usage). More informations how to use disk intead of memory in the help section here: [Using disk instead of memory](https://github.com/g0h4n/RustHound-CE/blob/main/HELP.md#using-disk-instead-of-memory)

All information regarding the code changes can be found in the original pull request: [#14](https://github.com/g0h4n/RustHound-CE/pull/14)

Big thanks to [z-jxy](https://github.com/z-jxy) for the excellent work and for implementing this much-needed feature, as requested in issue #[7](https://github.com/g0h4n/RustHound-CE/issues/7)

## 2.3.7 - 2025-06-24

Issue #[13](https://github.com/g0h4n/RustHound-CE/issues/13) fixed.
"Group members are no longer collected correctly."
Fixed a logic error: used `if value.is_empty()` instead of `if !value.is_empty()`

## 2.3.6 - 2025-06-23

This version includes a complete code review to apply improvements suggested by [Clippy](https://doc.rust-lang.org/clippy/usage.html) and contributions from [z-jxy](https://github.com/z-jxy). It addresses potential logic issues, removes dead code, and resolves an infinite recursion bug in the Debug implementation.

## 2.3.5 - 2025-06-19

Issue #[10](https://github.com/g0h4n/RustHound-CE/issues/10) fixed.

The problem was caused by the ACEs from `msDS-GroupMSAMembership` overwriting those from `nTSecurityDescriptor`, due to a reassignment of `self.aces` instead of appending to it on gMSA users.

The fix ensures that ACEs from both attributes are now properly merged. As a result, users and groups with `ReadGMSAPassword` permissions on gMSA accounts are correctly captured and included in the final output. Thanks to [0xdf223](https://github.com/0xdf223) for reporting.

## 2.3.4 - 2025-02-13

Merge pull request #[8](https://github.com/g0h4n/RustHound-CE/pull/8) to add a couple more computer node attributes. Thanks [spyr0](https://github.com/spyr0-sec)

## 2.3.3 - 2025-01-28

Merge pull request #[6](https://github.com/g0h4n/RustHound-CE/pull/6) to add argument `--ldap-filter` to change the ldap-filter to use instead of the default `(objectClass=*)`. Thanks [Mayfly277](https://github.com/Mayfly277)

## 2.3.2 - 2025-01-14

The issue where a group had `ActiveDirectoryRights:Self` with a SID mapped to it, theoretically allowing a user to add themselves to the group, has been fixed. Thanks to @shyam0904a for identifying and fixing this issue! https://github.com/g0h4n/RustHound-CE/pull/4

## 2.3.1 - 2025-01-05

This version fixes the issue of the lack of [WriteGPLink](https://support.bloodhoundenterprise.io/hc/en-us/articles/29117665141915-WriteGPLink) for Organization Units and [WriteSPN](https://support.bloodhoundenterprise.io/hc/en-us/articles/17222775975195-WriteSPN) for Computers.

## 2.3.0 -  2024-12-28

The latest update introduces enhanced functionality and optimizations for handling Active Directory objects. It includes support for [IssuancePolicies](https://support.bloodhoundenterprise.io/hc/en-us/articles/26194070577691-IssuancePolicy). Fixing unconstrained delegation issues where FQDNs were replaced with SIDs to ensure compatibility with BloodHound CE. GUIDs are now properly parsed in the Windows Active Directory format, adhering to the little-endian structure, this allow to fixe all issues related to ACEs permissions. Password policy attributes from Active Directory are retrieved and associated with the domain object in domain.json. Additionally, Kerberos service ticket encryption algorithms are now extracted via the `msDS-SupportedEncryptionTypes` attribute. Finally, the code has been optimized to improve object type verification and streamline offline value replacements in `src/json/checker/common.rs`, enhancing performance and maintainability.

### Examples

*The tests were conducted on Mayfly's GOAD lab environment.*

> Shortest paths to systems trusted for unconstrained delegation

```cypher
MATCH p=shortestPath((n)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|Contains|GPLink|AllowedToDelegate|TrustedBy|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC5|ADCSESC6a|ADCSESC6b|ADCSESC7|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|DCFor|SyncedToEntraUser*1..]->(m:Computer))
WHERE m.unconstraineddelegation = true AND n<>m
RETURN p
LIMIT 1000
```

#### RustHound-CE - v2.3.0

```bash
rusthound-ce.exe -c All -d ESSOS.local -u vagrant -p vagrant -z
```

![rusthound-ce-shortest-path-example](./img/demo/RUSTHOUND_ESSOS_LOCAL_SHORTEST_PATH_EXAMPLE_24122024.png)

#### SharpHound - v2.5.9.0

```bash
SharpHound.exe -c All -d ESSOS.local --ldapusername vagrant --ldappassword vagrant
```

![sharphound-shortest-path-example](./img/demo/SHARPHOUND_ESSOS_LOCAL_SHORTEST_PATH_EXAMPLE_24122024.png)

