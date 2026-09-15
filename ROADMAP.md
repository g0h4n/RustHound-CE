# Roadmap

- [Limitations](#limitations)
    - [Compatibility with SharpHound](#compatibility-with-sharphound)
- [Authentification](#authentification)
- [Outputs](#outputs)
- [Modules](#modules)
- [List of attributes](#list-of-attributes)
    - [Domain](#domain)
    - [Computer](#computer)
    - [User](#user)
    - [Group](#group)
    - [OU](#ou)
    - [Gpo](#gpo)
    - [Container](#container)
    - [IssuancePolicies](#issuancepolicies)
    - [NtAuthStore](#ntauthstore)
    - [AIACA](#aiaca)
    - [RootCA](#rootca)
    - [EnterpriseCA](#enterpriseca)
    - [CertTemplate](#certtemplate)
- [ACE right names (edges)](#ace-right-names-edges)
- [Divergences to review](#divergences-to-review)

## Limitations

> Not all [SharpHound](https://github.com/BloodHoundAD/SharpHound) features have been implemented. Some exist in `rusthound-ce` and not in [SharpHound](https://github.com/BloodHoundAD/SharpHound) or [BloodHound-Python](https://github.com/fox-it/BloodHound.py). Please refer to the [roadmap](./ROADMAP.md) for more information.

### Compatibility with SharpHound

Attribute-by-attribute comparison between `rusthound-ce v2.5.13` and `SharpHound v2.16.0.0`,
measured on the same domain on `2026-09-15`. Counts every checkbox of the [List of attributes](#list-of-attributes) section, including nested sub-fields.

Attribute-by-attribute comparison between `rusthound-ce` and `SharpHound v2.16.0.0`,
measured on the same domain on `2026-09-15`, `rusthound-ce` side updated after the
ESC8 fix ([#67](https://github.com/g0h4n/RustHound-CE/issues/67)). Counts every
checkbox of the [List of attributes](#list-of-attributes) section, including nested
sub-fields.

| Object | Attributes | :white_check_mark: Implemented | :red_circle: Missing | Compatibility |
| :--- | ---: | ---: | ---: | :--- |
| CertTemplate | 47 | 40 | 7 | `█████████░` 85.1% |
| Domain | 55 | 46 | 9 | `████████░░` 83.6% |
| OU | 34 | 28 | 6 | `████████░░` 82.4% |
| RootCA | 28 | 23 | 5 | `████████░░` 82.1% |
| User | 70 | 56 | 14 | `████████░░` 80.0% |
| Gpo | 25 | 20 | 5 | `████████░░` 80.0% |
| AIACA | 30 | 24 | 6 | `████████░░` 80.0% |
| NtAuthStore | 24 | 19 | 5 | `████████░░` 79.2% |
| Container | 26 | 20 | 6 | `████████░░` 76.9% |
| Group | 32 | 22 | 10 | `███████░░░` 68.8% |
| EnterpriseCA | 70 | 45 | 25 | `██████░░░░` 64.3% |
| IssuancePolicies | 27 | 17 | 10 | `██████░░░░` 63.0% |
| Computer | 119 | 59 | 60 | `█████░░░░░` 49.6% |
| **Total** | **587** | **419** | **168** | **`███████░░░` 71.4%** |

> The lowest scores come from remote collection rather than LDAP parsing.
> `Computer` is pulled down by `LocalGroups`, `NTLMRegistryData`, `SmbInfo`,
> `IsWebClientRunning` and `DCRegistryData`; `EnterpriseCA` by `CARegistryData`.
> Those 55 attributes are all unimplemented and require RPC/SMB access to the
> hosts; excluding them, coverage rises

## Authentification
  - [x] LDAP (389) :white_check_mark:
  - [x] LDAPS (636) :white_check_mark:
  - [x] `BIND` :white_check_mark:
  - [x] `NTLM`  Pass-The-Hash :white_check_mark:
  - [x] `Kerberos` :white_check_mark:
  - [x] `PFX`,`PEM` Pass-The-Certificate :white_check_mark:
  - [x] Prompt for password :white_check_mark:

## Outputs
  - [x] users.json :white_check_mark:
  - [x] groups.json :white_check_mark:
  - [x] computers.json :white_check_mark:
  - [x] ous.json :white_check_mark:
  - [x] gpos.json :white_check_mark:
  - [x] containers.json :white_check_mark:
  - [x] domains.json :white_check_mark:
  - [x] aiacas.json :white_check_mark:
  - [x] rootcas.json :white_check_mark:
  - [x] enterprisecas.json :white_check_mark:
  - [x] certtemplates.json :white_check_mark:
  - [x] issuancepolicies.json :white_check_mark:
  - [x] ntauthstores.json :white_check_mark:
  - [x] all.zip :white_check_mark:

## Modules
- [x] Retreive LAPS password if your user can read them **automatic** :white_check_mark:
- [ ] Retreive LAPSv2 password if your user can read them **automatic** :red_circle:
- [x] Resolve FQDN computers found to IP address **--fqdn-resolver** :white_check_mark:
- [x] Session-collection feature, enumerates active sessions over three native RPC paths (SRVSVC, WKSSVC, WINREG) :white_check_mark:
- [x] GPO-based collection from SYSVOL, reads `GptTmpl.inf` and `Groups.xml`, GPOChanges (LocalAdmins / RemoteDesktopUsers / DcomUsers / PSRemoteUsers) :white_check_mark:
- [ ] Local group enumeration over SAMR/LSAT (`LocalGroups`, feeds `AdminTo` / `CanRDP` / `CanPSRemote` / `ExecuteDCOM`) :red_circle: :new:
- [ ] Remote registry collection (`NTLMRegistryData`, `DCRegistryData`, `CARegistryData`) :red_circle: :new:
- [ ] SMB signing probe (`SmbInfo`) :red_circle: :new:
- [ ] WebClient/WebDAV service probe (`IsWebClientRunning`, prerequisite for ESC8 / coercion paths) :red_circle: :new:
- [x] HTTP enrollment endpoints probe (`HttpEnrollmentEndpoints`, ADCS web enrollment over HTTP/HTTPS/EPA) :red_circle: :new:

## List of attributes

### Domain
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`highvalue` :white_check_mark: (dropped from BloodHound CE, candidate for removal)
- [x] `Properties`:`description` :white_check_mark: (not emitted by SharpHound)
- [x] `Properties`:`whencreated` :white_check_mark:
- [ ] `Properties`:`netbios` :red_circle: :new:
- [x] `Properties`:`expirepasswordsonsmartcardonlyaccounts` :white_check_mark:
- [x] `Properties`:`machineaccountquota` :white_check_mark:
- [x] `Properties`:`minpwdlength` :white_check_mark:
- [x] `Properties`:`pwdproperties` :white_check_mark:
- [x] `Properties`:`pwdhistorylength` :white_check_mark:
- [x] `Properties`:`lockoutthreshold` :white_check_mark:
- [x] `Properties`:`minpwdage` :white_check_mark:
- [x] `Properties`:`maxpwdage` :white_check_mark:
- [x] `Properties`:`lockoutduration` :white_check_mark:
- [x] `Properties`:`lockoutobservationwindow` :white_check_mark:
- [x] `Properties`:`functionallevel` :white_check_mark:
- [x] `Properties`:`dsheuristics` :white_check_mark:
- [x] `Properties`:`collected` :white_check_mark:
- [x] `GPOChanges`:`LocalAdmins` :white_check_mark:
- [x] `GPOChanges`:`RemoteDesktopUsers` :white_check_mark:
- [x] `GPOChanges`:`DcomUsers` :white_check_mark:
- [x] `GPOChanges`:`PSRemoteUsers` :white_check_mark:
- [x] `GPOChanges`:`AffectedComputers` :white_check_mark:
- [x] `ChildObjects`:`ObjectIdentifier` :white_check_mark:
- [x] `ChildObjects`:`ObjectType` :white_check_mark:
- [x] `Trusts`:`TargetDomainSid` :white_check_mark:
- [x] `Trusts`:`TargetDomainName` :white_check_mark:
- [x] `Trusts`:`IsTransitive` :white_check_mark:
- [x] `Trusts`:`SidFilteringEnabled` :white_check_mark:
- [ ] `Trusts`:`TGTDelegationEnabled` :red_circle:
- [x] `Trusts`:`TrustAttributes` :white_check_mark:
- [x] `Trusts`:`TrustDirection` :white_check_mark:
- [x] `Trusts`:`TrustType` :white_check_mark:
- [x] `Links`:`GUID` :white_check_mark:
- [x] `Links`:`IsEnforced` :white_check_mark:
- [ ] `InheritanceHashes` :red_circle: :new:
- [ ] `ForestRootIdentifier` :red_circle: :new:
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy` :white_check_mark: (`null` on the domain root, same as SharpHound)

### Computer
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`highvalue` :white_check_mark: (dropped from BloodHound CE, candidate for removal)
- [x] `Properties`:`description` :white_check_mark:
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`samaccountname` :white_check_mark:
- [x] `Properties`:`haslaps` :white_check_mark:
- [x] `Properties`:`enabled` :white_check_mark:
- [x] `Properties`:`unconstraineddelegation` :white_check_mark:
- [x] `Properties`:`trustedtoauth` :white_check_mark:
- [x] `Properties`:`lastlogon` :white_check_mark:
- [x] `Properties`:`lastlogontimestamp` :white_check_mark:
- [x] `Properties`:`pwdlastset` :white_check_mark:
- [x] `Properties`:`pwdneverexpires` :white_check_mark:
- [x] `Properties`:`passwordnotreqd` :white_check_mark:
- [x] `Properties`:`serviceprincipalnames` :white_check_mark:
- [x] `Properties`:`operatingsystem` :white_check_mark:
- [x] `Properties`:`supportedencryptiontypes` :white_check_mark:
- [x] `Properties`:`sidhistory` :white_check_mark:
- [ ] `Properties`:`useraccountcontrol` :red_circle: :new:
- [ ] `Properties`:`isdc` :red_circle: :new: (`IsDC` is emitted at node level, but not as a property)
- [ ] `Properties`:`isreadonlydc` :red_circle: :new:
- [ ] `Properties`:`admincount` :red_circle: :new:
- [ ] `Properties`:`adminsdholderprotected` :red_circle: :new:
- [ ] `Properties`:`lockedout` :red_circle: :new:
- [ ] `Properties`:`passwordexpired` :red_circle: :new:
- [ ] `Properties`:`usedeskeyonly` :red_circle: :new:
- [ ] `Properties`:`encryptedtextpwdallowed` :red_circle: :new:
- [ ] `Properties`:`logonscriptenabled` :red_circle: :new:
- [ ] `Properties`:`email` :red_circle: :new:
- [ ] `Properties`:`ldapavailable` :red_circle: :new:
- [ ] `Properties`:`ldapsavailable` :red_circle: :new:
- [ ] `Properties`:`ldapsigning` :red_circle: :new:
- [ ] `Properties`:`ldapsepa` :red_circle: :new:
- [x] `PrimaryGroupSID` :white_check_mark:
- [x] `AllowedToDelegate`:`ObjectIdentifier` :white_check_mark:
- [x] `AllowedToDelegate`:`ObjectType` :white_check_mark:
- [x] `AllowedToAct`:`ObjectIdentifier` :white_check_mark:
- [x] `AllowedToAct`:`ObjectType` :white_check_mark:
- [x] `HasSIDHistory`:`ObjectIdentifier` :white_check_mark:
- [x] `HasSIDHistory`:`ObjectType` :white_check_mark:
- [ ] `DumpSMSAPassword` :red_circle: (key is emitted but always empty)
- [x] `Sessions`:`Results`:`UserSID` :white_check_mark:
- [x] `Sessions`:`Results`:`ComputerSID` :white_check_mark:
- [x] `Sessions`:`Collected` :white_check_mark:
- [x] `Sessions`:`FailureReason` :white_check_mark:
- [x] `PrivilegedSessions`:`Results` :white_check_mark:
- [x] `PrivilegedSessions`:`Collected` :white_check_mark:
- [x] `PrivilegedSessions`:`FailureReason` :white_check_mark:
- [x] `RegistrySessions`:`Results` :white_check_mark:
- [x] `RegistrySessions`:`Collected` :white_check_mark:
- [x] `RegistrySessions`:`FailureReason` :white_check_mark:
- [ ] `LocalGroups` :red_circle: (key is emitted but always empty)
    - [ ] `LocalGroups`:`Name` :red_circle: :new:
    - [ ] `LocalGroups`:`ObjectIdentifier` :red_circle: :new:
    - [ ] `LocalGroups`:`Results`:`ObjectIdentifier` :red_circle: :new:
    - [ ] `LocalGroups`:`Results`:`ObjectType` :red_circle: :new:
    - [ ] `LocalGroups`:`LocalNames` :red_circle: :new:
    - [ ] `LocalGroups`:`Collected` :red_circle: :new:
    - [ ] `LocalGroups`:`FailureReason` :red_circle: :new:
- [x] `UserRights`:`Privilege` :white_check_mark:
- [x] `UserRights`:`Results`:`ObjectIdentifier` :white_check_mark:
- [x] `UserRights`:`Results`:`ObjectType` :white_check_mark:
- [x] `UserRights`:`LocalNames` :white_check_mark: (emitted but always empty, rebuilt from `GptTmpl.inf`)
- [x] `UserRights`:`Collected` :white_check_mark:
- [x] `UserRights`:`FailureReason` :white_check_mark:
- [ ] `DCRegistryData` :red_circle: need RPC call and [GetRegistryKeyData src Helper.cs](https://github.com/BloodHoundAD/SharpHoundCommon/blob/v3/src/CommonLib/Helpers.cs#L278) — the keys are emitted as a raw `null` instead of the `{Collected, FailureReason, Value}` wrapper
    - [ ] `CertificateMappingMethods`:`Value` :red_circle:
    - [ ] `CertificateMappingMethods`:`Collected` :red_circle:
    - [ ] `CertificateMappingMethods`:`FailureReason` :red_circle:
    - [ ] `StrongCertificateBindingEnforcement`:`Value` :red_circle:
    - [ ] `StrongCertificateBindingEnforcement`:`Collected` :red_circle:
    - [ ] `StrongCertificateBindingEnforcement`:`FailureReason` :red_circle:
    - [ ] `VulnerableNetlogonSecurityDescriptor`:`Value` :red_circle: :new:
    - [ ] `VulnerableNetlogonSecurityDescriptor`:`Collected` :red_circle: :new:
    - [ ] `VulnerableNetlogonSecurityDescriptor`:`FailureReason` :red_circle: :new:
- [ ] `NTLMRegistryData` :red_circle: :new:
    - [ ] `Result`:`LmCompatibilityLevel` :red_circle: :new:
    - [ ] `Result`:`RestrictSendingNtlmTraffic` :red_circle: :new:
    - [ ] `Result`:`RestrictReceivingNtlmTraffic` :red_circle: :new:
    - [ ] `Result`:`NtlmMinClientSec` :red_circle: :new:
    - [ ] `Result`:`NtlmMinServerSec` :red_circle: :new:
    - [ ] `Result`:`RequireSecuritySignature` :red_circle: :new:
    - [ ] `Result`:`EnableSecuritySignature` :red_circle: :new:
    - [ ] `Result`:`ClientAllowedNTLMServers` :red_circle: :new:
    - [ ] `Result`:`UseMachineId` :red_circle: :new:
    - [ ] `Collected` :red_circle: :new:
    - [ ] `FailureReason` :red_circle: :new:
- [ ] `SmbInfo` :red_circle: :new:
    - [ ] `Result`:`SigningEnabled` :red_circle: :new:
    - [ ] `Collected` :red_circle: :new:
    - [ ] `FailureReason` :red_circle: :new:
- [ ] `IsWebClientRunning` :red_circle: :new:
    - [ ] `Result` :red_circle: :new:
    - [ ] `Collected` :red_circle: :new:
    - [ ] `FailureReason` :red_circle: :new:
- [ ] `NtlmSessions` :red_circle: :new:
- [x] `Status` :white_check_mark:
- [x] `IsDC` :white_check_mark:
- [x] `UnconstrainedDelegation` :white_check_mark:
- [x] `DomainSID` :white_check_mark:
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### User
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`highvalue` :white_check_mark: (dropped from BloodHound CE, candidate for removal)
- [x] `Properties`:`samaccountname` :white_check_mark:
- [x] `Properties`:`description` :white_check_mark:
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`sensitive` :white_check_mark:
- [x] `Properties`:`dontreqpreauth` :white_check_mark:
- [x] `Properties`:`passwordnotreqd` :white_check_mark:
- [x] `Properties`:`unconstraineddelegation` :white_check_mark:
- [x] `Properties`:`pwdneverexpires` :white_check_mark:
- [x] `Properties`:`enabled` :white_check_mark:
- [x] `Properties`:`trustedtoauth` :white_check_mark:
- [x] `Properties`:`lastlogon` :white_check_mark:
- [x] `Properties`:`lastlogontimestamp` :white_check_mark:
- [x] `Properties`:`pwdlastset` :white_check_mark:
- [x] `Properties`:`serviceprincipalnames` :white_check_mark:
- [x] `Properties`:`hasspn` :white_check_mark:
- [x] `Properties`:`displayname` :white_check_mark:
- [x] `Properties`:`email` :white_check_mark:
- [x] `Properties`:`title` :white_check_mark:
- [x] `Properties`:`homedirectory` :white_check_mark:
- [x] `Properties`:`userpassword` :white_check_mark:
- [x] `Properties`:`unixpassword` :white_check_mark:
- [x] `Properties`:`unicodepassword` :white_check_mark:
- [x] `Properties`:`sfupassword` :white_check_mark:
- [x] `Properties`:`logonscript` :white_check_mark:
- [x] `Properties`:`useraccountcontrol` :white_check_mark:
- [x] `Properties`:`profilepath` :white_check_mark:
- [x] `Properties`:`admincount` :white_check_mark:
- [x] `Properties`:`supportedencryptiontypes` :white_check_mark:
- [x] `Properties`:`sidhistory` :white_check_mark:
- [x] `Properties`:`allowedtodelegate` :white_check_mark: (not emitted by SharpHound)
- [ ] `Properties`:`adminsdholderprotected` :red_circle: :new:
- [ ] `Properties`:`lockedout` :red_circle: :new:
- [ ] `Properties`:`passwordexpired` :red_circle: :new:
- [ ] `Properties`:`passwordcantchange` :red_circle: :new:
- [ ] `Properties`:`smartcardrequired` :red_circle: :new:
- [ ] `Properties`:`usedeskeyonly` :red_circle: :new:
- [ ] `Properties`:`encryptedtextpwdallowed` :red_circle: :new:
- [ ] `Properties`:`logonscriptenabled` :red_circle: :new:
- [ ] `Properties`:`reconcile` :red_circle: :new: (emitted by SharpHound on well-known / unresolved principals)
- [x] `PrimaryGroupSID` :white_check_mark:
- [x] `AllowedToDelegate`:`ObjectIdentifier` :white_check_mark:
- [x] `AllowedToDelegate`:`ObjectType` :white_check_mark:
- [x] `UnconstrainedDelegation` :white_check_mark:
- [x] `HasSIDHistory`:`ObjectIdentifier` :white_check_mark:
- [x] `HasSIDHistory`:`ObjectType` :white_check_mark:
- [x] `SPNTargets`:`ComputerSID` :white_check_mark:
- [x] `SPNTargets`:`Port` :white_check_mark:
- [x] `SPNTargets`:`Service` :white_check_mark:
- [x] `DomainSID` :white_check_mark:
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### Group
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`highvalue` :white_check_mark: (dropped from BloodHound CE, candidate for removal)
- [x] `Properties`:`samaccountname` :white_check_mark:
- [x] `Properties`:`description` :white_check_mark:
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`admincount` :white_check_mark:
- [ ] `Properties`:`groupscope` :red_circle: :new:
- [ ] `Properties`:`sidhistory` :red_circle: :new:
- [ ] `Properties`:`adminsdholderprotected` :red_circle: :new:
- [ ] `Properties`:`reconcile` :red_circle: :new: (emitted by SharpHound on well-known / unresolved principals)
- [x] `Members`:`ObjectIdentifier` :white_check_mark:
- [x] `Members`:`ObjectType` :white_check_mark:
- [ ] `HasSIDHistory` :red_circle: :new:
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### OU
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`highvalue` :white_check_mark: (dropped from BloodHound CE, candidate for removal)
- [x] `Properties`:`description` :white_check_mark:
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`blocksinheritance` :white_check_mark:
- [x] `GPOChanges`:`LocalAdmins` :white_check_mark:
- [x] `GPOChanges`:`RemoteDesktopUsers` :white_check_mark:
- [x] `GPOChanges`:`DcomUsers` :white_check_mark:
- [x] `GPOChanges`:`PSRemoteUsers` :white_check_mark:
- [x] `GPOChanges`:`AffectedComputers` :white_check_mark:
- [x] `Links`:`GUID` :white_check_mark:
- [x] `Links`:`IsEnforced` :white_check_mark:
- [x] `ChildObjects`:`ObjectIdentifier` :white_check_mark:
- [x] `ChildObjects`:`ObjectType` :white_check_mark:
- [ ] `InheritanceHashes` :red_circle: :new:
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### Gpo
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`highvalue` :white_check_mark: (dropped from BloodHound CE, candidate for removal)
- [x] `Properties`:`description` :white_check_mark: (not emitted by SharpHound)
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`gpcpath` :white_check_mark:
- [x] `Properties`:`gpostatus` :white_check_mark:
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### Container
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`highvalue` :white_check_mark: (dropped from BloodHound CE, candidate for removal)
- [x] `Properties`:`description` :white_check_mark:
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `ChildObjects`:`ObjectIdentifier` :white_check_mark:
- [x] `ChildObjects`:`ObjectType` :white_check_mark:
- [ ] `InheritanceHashes` :red_circle: :new:
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### IssuancePolicies
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`description` :white_check_mark: (not emitted by SharpHound)
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`displayname` :white_check_mark:
- [x] `Properties`:`certtemplateoid` :white_check_mark:
- [ ] `Properties`:`oidgrouplink` :red_circle: :new:
- [ ] `GroupLink`:`ObjectIdentifier` :red_circle: (structure is emitted, but the value is always `null`)
- [ ] `GroupLink`:`ObjectType` :red_circle: (always `Base`, never resolved to `Group`)
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [ ] `ContainedBy`:`ObjectIdentifier` :red_circle: (emitted as `null`; SharpHound resolves it on all policies)
- [ ] `ContainedBy`:`ObjectType` :red_circle:

### NtAuthStore
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`description` :white_check_mark: (not emitted by SharpHound)
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`certthumbprints` :white_check_mark:
- [x] `DomainSID` :white_check_mark: (not emitted by SharpHound)
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### AIACA
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`description` :white_check_mark: (not emitted by SharpHound)
- [x] `Properties`:`whencreated` :white_check_mark:
- [ ] `Properties`:`crosscertificatepair` :red_circle: What value should be added to the output? (x509 cert)
- [x] `Properties`:`hascrosscertificatepair` :white_check_mark:
- [x] `Properties`:`certthumbprint` :white_check_mark:
- [x] `Properties`:`certname` :white_check_mark:
- [x] `Properties`:`certchain` :white_check_mark:
- [x] `Properties`:`hasbasicconstraints` :white_check_mark:
- [x] `Properties`:`basicconstraintpathlength` :white_check_mark:
- [x] `DomainSID` :white_check_mark: (not emitted by SharpHound)
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### RootCA
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`description` :white_check_mark: (not emitted by SharpHound)
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`certthumbprint` :white_check_mark:
- [x] `Properties`:`certname` :white_check_mark:
- [x] `Properties`:`certchain` :white_check_mark:
- [x] `Properties`:`hasbasicconstraints` :white_check_mark:
- [x] `Properties`:`basicconstraintpathlength` :white_check_mark:
- [x] `DomainSID` :white_check_mark: (not emitted by SharpHound)
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### EnterpriseCA
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`description` :white_check_mark: (not emitted by SharpHound)
- [x] `Properties`:`whencreated` :white_check_mark:
- [ ] `Properties`:`flags` :red_circle: (key is emitted but always an empty string)
- [x] `Properties`:`caname` :white_check_mark:
- [x] `Properties`:`dnshostname` :white_check_mark:
- [x] `Properties`:`certthumbprint` :white_check_mark:
- [x] `Properties`:`certname` :white_check_mark:
- [x] `Properties`:`certchain` :white_check_mark:
- [x] `Properties`:`hasbasicconstraints` :white_check_mark:
- [x] `Properties`:`basicconstraintpathlength` :white_check_mark:
- [ ] `Properties`:`unresolvedpublishedtemplates` :red_circle:
- [x] `Properties`:`casecuritycollected` :white_check_mark:
- [ ] `Properties`:`enrollmentagentrestrictionscollected` :red_circle: linked to RPC for `CARegistryData`:`EnrollmentAgentRestrictions` (currently hardcoded to `false`)
- [ ] `Properties`:`isuserspecifiessanenabledcollected` :red_circle: linked to RPC for `CARegistryData`:`IsUserSpecifiesSanEnabled` (currently hardcoded to `false`)
- [ ] `Properties`:`roleseparationenabledcollected` :red_circle: (currently hardcoded to `false`)
- [x] `HostingComputer` :white_check_mark:
- [x] `EnabledCertTemplates`:`ObjectIdentifier` :white_check_mark:
- [x] `EnabledCertTemplates`:`ObjectType` :white_check_mark:
- [x] `CARegistryData`:`CASecurity` :white_check_mark: (rebuilt from the LDAP DACL instead of the remote registry)
    - [x] `Data`:`PrincipalSID` :white_check_mark:
    - [x] `Data`:`PrincipalType` :white_check_mark:
    - [x] `Data`:`RightName` :white_check_mark:
    - [x] `Data`:`IsInherited` :white_check_mark:
    - [x] `Data`:`InheritanceHash` :white_check_mark:
    - [ ] `Data`:`IsPermissionForOwnerRightsSid` :red_circle:
    - [ ] `Data`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
    - [x] `Collected` :white_check_mark:
    - [x] `FailureReason` :white_check_mark:
- [ ] `CARegistryData`:`EnrollmentAgentRestrictions` :red_circle: src [ObjectProcessors.cs](https://github.com/BloodHoundAD/SharpHound/blob/2.X/src/Runtime/ObjectProcessors.cs#L667C28-L667C38) (emitted as `Collected: true` with an empty list, which hides the fact that nothing was read)
    - [ ] `Restrictions` :red_circle:
    - [ ] `Collected` :red_circle:
    - [ ] `FailureReason` :red_circle:
- [ ] `CARegistryData`:`IsUserSpecifiesSanEnabled` :red_circle: src [ObjectProcessors.cs](https://github.com/BloodHoundAD/SharpHound/blob/2.X/src/Runtime/ObjectProcessors.cs#L667C28-L667C38) (emitted as `Collected: true` / `Value: false`; SharpHound reads `true` on the same CA)
    - [ ] `Value` :red_circle:
    - [ ] `Collected` :red_circle:
    - [ ] `FailureReason` :red_circle:
- [ ] `CARegistryData`:`RoleSeparationEnabled` :red_circle: (emitted as `Collected: true` / `Value: false` without reading the registry)
    - [ ] `Value` :red_circle:
    - [ ] `Collected` :red_circle:
    - [ ] `FailureReason` :red_circle:
- [x] `HttpEnrollmentEndpoints` :white_check_mark:
    - [x] `Result`:`Url` :white_check_mark:
    - [x] `Result`:`Type` :white_check_mark: (always `WebEnrollmentApplication`)
    - [x] `Result`:`Status` :white_check_mark:
    - [x] `Result`:`ADCSWebEnrollmentHTTP` :white_check_mark:
    - [x] `Result`:`ADCSWebEnrollmentHTTPS` :white_check_mark:
    - [x] `Result`:`ADCSWebEnrollmentEPA` :white_check_mark:
    - [x] `Collected` :white_check_mark: (`true` when the port answered or is closed, `false` when the HTTP exchange failed)
    - [x] `FailureReason` :white_check_mark:
    - [ ] CES endpoints, `/{CAName}_CES_Kerberos/service.svc` with `Type`: `EnrollmentWebService` :red_circle: :new: (SharpHound probes 4 URLs per CA, we probe 2)
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

### CertTemplate
- [x] `Properties`:`domain` :white_check_mark:
- [x] `Properties`:`name` :white_check_mark:
- [x] `Properties`:`distinguishedname` :white_check_mark:
- [x] `Properties`:`domainsid` :white_check_mark:
- [ ] `Properties`:`objectguid` :red_circle: :new:
- [ ] `Properties`:`doesanyinheritedacegrantownerrights` :red_circle:
- [ ] `Properties`:`doesanyacegrantownerrights` :red_circle:
- [x] `Properties`:`isaclprotected` :white_check_mark: (this value replaces `IsACLProtected`)
- [x] `Properties`:`description` :white_check_mark: (not emitted by SharpHound)
- [x] `Properties`:`whencreated` :white_check_mark:
- [x] `Properties`:`validityperiod` :white_check_mark:
- [x] `Properties`:`renewalperiod` :white_check_mark:
- [x] `Properties`:`schemaversion` :white_check_mark:
- [x] `Properties`:`displayname` :white_check_mark:
- [x] `Properties`:`oid` :white_check_mark:
- [x] `Properties`:`enrollmentflag` :white_check_mark:
- [x] `Properties`:`requiresmanagerapproval` :white_check_mark:
- [x] `Properties`:`nosecurityextension` :white_check_mark:
- [x] `Properties`:`certificatenameflag` :white_check_mark:
- [x] `Properties`:`enrolleesuppliessubject` :white_check_mark:
- [x] `Properties`:`subjectaltrequireupn` :white_check_mark:
- [x] `Properties`:`ekus` :white_check_mark:
- [x] `Properties`:`certificateapplicationpolicy` :white_check_mark:
- [x] `Properties`:`authorizedsignatures` :white_check_mark:
- [x] `Properties`:`applicationpolicies` :white_check_mark:
- [x] `Properties`:`issuancepolicies` :white_check_mark:
- [x] `Properties`:`effectiveekus` :white_check_mark:
- [x] `Properties`:`authenticationenabled` :white_check_mark:
- [x] `Properties`:`subjectaltrequiredns` :white_check_mark:
- [x] `Properties`:`subjectaltrequiredomaindns` :white_check_mark:
- [x] `Properties`:`subjectaltrequireemail` :white_check_mark:
- [x] `Properties`:`subjectaltrequirespn` :white_check_mark:
- [x] `Properties`:`subjectrequireemail` :white_check_mark:
- [ ] `Properties`:`schannelauthenticationenabled` :red_circle:
- [ ] `Properties`:`certificatepolicy` :red_circle: :new:
- [x] `Aces`:`PrincipalSID` :white_check_mark:
- [x] `Aces`:`PrincipalType` :white_check_mark:
- [x] `Aces`:`RightName` :white_check_mark:
- [x] `Aces`:`IsInherited` :white_check_mark:
- [x] `Aces`:`InheritanceHash` :white_check_mark:
- [ ] `Aces`:`IsPermissionForOwnerRightsSid` :red_circle:
- [ ] `Aces`:`IsInheritedPermissionForOwnerRightsSid` :red_circle:
- [x] `ObjectIdentifier` :white_check_mark:
- [x] `IsDeleted` :white_check_mark:
- [x] `IsACLProtected` :white_check_mark:
- [x] `ContainedBy`:`ObjectIdentifier` :white_check_mark:
- [x] `ContainedBy`:`ObjectType` :white_check_mark:

## ACE right names (edges)

Right names produced in the `Aces` arrays, compared with SharpHound `v2.16.0.0` on the same domain.

- [x] `GenericAll` :white_check_mark:
- [x] `GenericWrite` :white_check_mark:
- [x] `WriteDacl` :white_check_mark:
- [x] `WriteOwner` :white_check_mark:
- [x] `Owns` :white_check_mark:
- [x] `AllExtendedRights` :white_check_mark:
- [x] `AddKeyCredentialLink` :white_check_mark:
- [x] `GetChanges` :white_check_mark:
- [x] `GetChangesAll` :white_check_mark:
- [x] `GetChangesInFilteredSet` :white_check_mark:
- [x] `Enroll` :white_check_mark:
- [x] `AutoEnroll` :white_check_mark: (not emitted by SharpHound `v2.16.0.0`)
- [x] `ManageCA` :white_check_mark:
- [x] `ManageCertificates` :white_check_mark:
- [ ] `WriteAccountRestrictions` :red_circle: :new:

## Divergences to review

Items found while diffing the two collections that are not feature gaps, but are worth a decision.

- Duplicate node: `TESTPTC.ESSOS.LOCAL` is written twice in `computers.json` (4 entries for 3 real machines). This one is an export bug rather than a roadmap item.
- `Properties`:`highvalue` is still emitted on Domain / Computer / User / Group / OU / GPO / Container. The attribute was dropped from BloodHound CE and SharpHound `v2.16.0.0` no longer produces it, so it is a candidate for removal rather than for the roadmap.
- `Properties`:`description` is emitted on object types where SharpHound does not produce it (Domain, AIACA, RootCA, EnterpriseCA, NtAuthStore, CertTemplate, IssuancePolicy). Extra data, harmless for the ingest.
- `DomainSID` is emitted at node level on AIACA / RootCA / NtAuthStore, which SharpHound does not do.
- `Links` is emitted on GPO nodes and is always empty. SharpHound does not emit the key at all on that node type.
- `UserRights` is rebuilt from `GptTmpl.inf` and returns the full privilege set of the applied GPOs (24 privileges on the test DC), while SharpHound only reports `SeRemoteInteractiveLogonRight` read remotely. The two sources are not equivalent and `LocalNames` is always empty on the `rusthound-ce` side.
- Container scope differs: SharpHound also walks `CN=Operations,CN=ForestUpdates,CN=Configuration` (131 extra containers on the test domain), `rusthound-ce` does not. Conversely `rusthound-ce` emits `CN=Deleted Objects` and `CN=MicrosoftDNS` containers that SharpHound skips.
- Well-known principals are not stubbed the same way. SharpHound emits placeholder group nodes carrying `reconcile: false` (`EVERYONE`, `AUTHENTICATED USERS`, `INTERACTIVE`, builtin local groups, ...) and user stubs such as `IUSR` and `NETWORK SERVICE`; `rusthound-ce` emits a different subset (`ENTERPRISE DOMAIN CONTROLLERS`, `THIS ORGANIZATION`, `REPLICATOR`, and a `NT AUTHORITY` user node).
- Attributes that could not be arbitrated on the test domain because both collectors returned an empty value: `Trusts`:* (no trust configured), `AIACA`:`crosscertificatepair`, `EnterpriseCA`:`unresolvedpublishedtemplates`, `User`:`email` / `title` / `homedirectory` / `profilepath` / `logonscript` / `userpassword` / `unixpassword` / `unicodepassword` / `sfupassword`, `sidhistory`, `DumpSMSAPassword`, `AllowedToAct`.