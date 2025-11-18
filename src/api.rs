use std::{collections::HashMap, error::Error};

use indicatif::ProgressBar;
use ldap3::SearchEntry;

use crate::{
    args::Options, banner::progress_bar, enums::{get_type, Type, PARSER_MOD_RE1, PARSER_MOD_RE2}, json::{
        checker::check_all_result,
    }, 
    objects::{
        aiaca::AIACA, certtemplate::CertTemplate, common::parse_unknown, computer::Computer, container::Container, domain::Domain, enterpriseca::EnterpriseCA, fsp::Fsp, gpo::Gpo, group::Group, inssuancepolicie::IssuancePolicie, ntauthstore::NtAuthStore, ou::Ou, rootca::RootCA, trust::Trust, user::User
    }, 
    storage::{EntrySource}
};

#[derive(Default)]
pub struct ADResults {
    pub users: Vec<User>,
    pub groups: Vec<Group>,
    pub computers: Vec<Computer>,
    pub ous: Vec<Ou>,
    pub domains: Vec<Domain>,
    pub gpos: Vec<Gpo>,
    pub fsps: Vec<Fsp>,
    pub containers: Vec<Container>,
    pub trusts: Vec<Trust>,
    pub ntauthstores: Vec<NtAuthStore>,
    pub aiacas: Vec<AIACA>,
    pub rootcas: Vec<RootCA>,
    pub enterprisecas: Vec<EnterpriseCA>,
    pub certtemplates: Vec<CertTemplate>,
    pub issuancepolicies: Vec<IssuancePolicie>,

    pub mappings: DomainMappings,
}

#[derive(Default)]
pub struct DomainMappings {
    /// DN to SID
    pub dn_sid: HashMap<String, String>,
    ///  DN to Type
    pub sid_type: HashMap<String, String>,
    /// FQDN to SID
    pub fqdn_sid: HashMap<String, String>,
    /// fqdn to an ip address
    pub fqdn_ip: HashMap<String, String>,
}

impl ADResults {
    pub fn new() -> Self {
        Self::default()
    }
}

pub async fn prepare_results_from_source<S: EntrySource>(
    source: S,
    options: &Options,
    total_objects: Option<usize>,
) -> Result<ADResults, Box<dyn std::error::Error>> {
    let mut ad_results = parse_result_type_from_source(options, source, total_objects)?;

    // Functions to replace and add missing values
    check_all_result(
        options,
        &mut ad_results.users,
        &mut ad_results.groups,
        &mut ad_results.computers,
        &mut ad_results.ous,
        &mut ad_results.domains,
        &mut ad_results.gpos,
        &mut ad_results.fsps,
        &mut ad_results.containers,
        &mut ad_results.trusts,
        &mut ad_results.ntauthstores,
        &mut ad_results.aiacas,
        &mut ad_results.rootcas,
        &mut ad_results.enterprisecas,
        &mut ad_results.certtemplates,
        &mut ad_results.issuancepolicies,
        &ad_results.mappings.dn_sid,
        &ad_results.mappings.sid_type,
        &ad_results.mappings.fqdn_sid,
        &ad_results.mappings.fqdn_ip,
    )?;

    Ok(ad_results)
}

// for `total_objects`, the total number of objects may not be known if the ldap query was never run
// (e.g run was resumed from cached results)
pub fn parse_result_type_from_source(
    common_args: &Options,
    source: impl EntrySource,
    total_objects: Option<usize>,
) -> Result<ADResults, Box<dyn Error>> {
    let mut results = ADResults::default();
    // Domain name
    let domain = &common_args.domain;

    // Needed for progress bar stats
    let pb = ProgressBar::new(1);
    let mut count = 0;
    let total = total_objects;
    let mut domain_sid: String = "DOMAIN_SID".to_owned();

    log::info!("Starting the LDAP objects parsing...");

    let dn_sid = &mut results.mappings.dn_sid;
    let sid_type = &mut results.mappings.sid_type;
    let fqdn_sid = &mut results.mappings.fqdn_sid;
    let fqdn_ip = &mut results.mappings.fqdn_ip;

    for entry in source.into_entry_iter() {
        let entry: SearchEntry = entry?.into();
        // Start parsing with Type matching
        let atype = get_type(&entry).unwrap_or(Type::Unknown);
        match atype {
            Type::User => {
                let mut user: User = User::new();
                user.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.users.push(user);
            }
            Type::Group => {
                let mut group = Group::new();
                group.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.groups.push(group);
            }
            Type::Computer => {
                let mut computer = Computer::new();
                computer.parse(
                    entry,
                    domain,
                    dn_sid,
                    sid_type,
                    fqdn_sid,
                    fqdn_ip,
                    &domain_sid,
                )?;
                results.computers.push(computer);
            }
            Type::Ou => {
                let mut ou = Ou::new();
                ou.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.ous.push(ou);
            }
            Type::Domain => {
                let mut domain_object = Domain::new();
                let domain_sid_from_domain =
                    domain_object.parse(entry, domain, dn_sid, sid_type)?;
                domain_sid = domain_sid_from_domain;
                // Only add domains with valid ObjectIdentifier (excludes DomainDnsZones, ForestDnsZones, etc.)
                if !domain_object.object_identifier().is_empty() {
                    results.domains.push(domain_object);
                }
            }
            Type::Gpo => {
                let mut gpo = Gpo::new();
                gpo.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.gpos.push(gpo);
            }
            Type::ForeignSecurityPrincipal => {
                let mut security_principal = Fsp::new();
                security_principal.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.fsps.push(security_principal);
            }
            Type::Container => {
                if PARSER_MOD_RE1.is_match(&entry.dn.to_uppercase())
                    || PARSER_MOD_RE2.is_match(&entry.dn.to_uppercase())
                {
                    //trace!("Container not to add: {}",&cloneresult.dn.to_uppercase());
                    continue;
                }

                //trace!("Container: {}",&entry.dn.to_uppercase());
                let mut container = Container::new();
                container.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.containers.push(container);
            }
            Type::Trust => {
                let mut trust = Trust::new();
                trust.parse(entry, domain)?;
                results.trusts.push(trust);
            }
            Type::NtAutStore => {
                let mut nt_auth_store = NtAuthStore::new();
                nt_auth_store.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.ntauthstores.push(nt_auth_store);
            }
            Type::AIACA => {
                let mut aiaca = AIACA::new();
                aiaca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.aiacas.push(aiaca);
            }
            Type::RootCA => {
                let mut root_ca = RootCA::new();
                root_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.rootcas.push(root_ca);
            }
            Type::EnterpriseCA => {
                let mut enterprise_ca = EnterpriseCA::new();
                enterprise_ca.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.enterprisecas.push(enterprise_ca);
            }
            Type::CertTemplate => {
                let mut cert_template = CertTemplate::new();
                cert_template.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.certtemplates.push(cert_template);
            }
            Type::IssuancePolicie => {
                let mut issuance_policie = IssuancePolicie::new();
                issuance_policie.parse(entry, domain, dn_sid, sid_type, &domain_sid)?;
                results.issuancepolicies.push(issuance_policie);
            }
            Type::Unknown => {
                let _unknown = parse_unknown(entry, domain);
            }
        }
        // Manage progress bar
        // Pourcentage (%) = 100 x Valeur partielle/Valeur totale
        if let Some(total) = total {
            count += 1;
            let pourcentage = 100 * count / total;
            progress_bar(
                pb.to_owned(),
                "Parsing LDAP objects".to_string(),
                pourcentage.try_into()?,
                "%".to_string(),
            );
        }
    }

    pb.finish_and_clear();
    log::info!("Parsing LDAP objects finished!");
    Ok(results)
}

