use std::{collections::HashMap, error::Error};

use indicatif::ProgressBar;
use ldap3::SearchEntry;
use rayon::prelude::*;

use crate::{
    args::Options, banner::progress_bar, enums::{PARSER_MOD_RE1, PARSER_MOD_RE2, Type, get_type}, json::checker::check_all_result, 
    objects::{
        aiaca::AIACA,
        certtemplate::CertTemplate,
        common::parse_unknown,
        computer::Computer,
        container::Container,
        domain::Domain,
        enterpriseca::EnterpriseCA,
        fsp::Fsp,
        gpo::Gpo,
        group::Group,
        inssuancepolicie::IssuancePolicie,
        ntauthstore::NtAuthStore,
        ou::Ou,
        rootca::RootCA,
        trust::Trust,
        user::User,
        schema::Schema,
    },
    ldap::LdapSearchEntry,
    storage::{DiskStorageReader, EntrySource},
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
    /// schema guid map
    pub schema_guid_map: HashMap<String, String>,
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
    run_checker(options, &mut ad_results)?;
    Ok(ad_results)
}

/// Like [`prepare_results_from_source`], but reads directly from a disk cache
/// (`--cache` / `--resume`). The heavy bincode decode of each record is done on
/// worker threads instead of the single reader thread, which is the difference
/// between a mostly-idle CPU and a saturated one on large caches.
pub async fn prepare_results_from_disk(
    reader: DiskStorageReader<LdapSearchEntry>,
    options: &Options,
    total_objects: Option<usize>,
) -> Result<ADResults, Box<dyn std::error::Error>> {
    let mut ad_results = parse_result_type_from_disk(options, reader, total_objects)?;
    run_checker(options, &mut ad_results)?;
    Ok(ad_results)
}

/// Post-parse pass: replace and add missing values.
fn run_checker(options: &Options, ad_results: &mut ADResults) -> Result<(), Box<dyn std::error::Error>> {
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
    )
}

/// Number of bulk entries buffered before being parsed as one parallel batch.
///
/// The batch is split across all CPU cores by rayon, then merged sequentially.
/// A larger value amortizes scheduling overhead; keeping it bounded caps the
/// extra memory to one batch of `SearchEntry`s regardless of domain size.
const PARSE_BATCH: usize = 16_384;

/// Map contributions produced by parsing a single object.
///
/// Each `parse()` only ever *inserts* the object's own DN→SID / SID→Type
/// (and, for computers, FQDN→SID / FQDN→IP) entries — it never reads the maps.
/// That makes bulk parsing data-parallel: every thread fills its own
/// `LocalMaps`, which are merged into the global maps afterwards.
#[derive(Default)]
struct LocalMaps {
    dn_sid: HashMap<String, String>,
    sid_type: HashMap<String, String>,
    fqdn_sid: HashMap<String, String>,
    fqdn_ip: HashMap<String, String>,
}

/// A parsed object, tagged by collection so the merge step can route it into
/// the right vector. `Domain` and `Schema` are parsed sequentially (they must
/// run before the bulk), so they never appear here.
enum Parsed {
    User(Box<User>),
    Group(Box<Group>),
    Computer(Box<Computer>),
    Ou(Box<Ou>),
    Gpo(Box<Gpo>),
    Fsp(Box<Fsp>),
    Container(Box<Container>),
    Trust(Box<Trust>),
    NtAuthStore(Box<NtAuthStore>),
    AIACA(Box<AIACA>),
    RootCA(Box<RootCA>),
    EnterpriseCA(Box<EnterpriseCA>),
    CertTemplate(Box<CertTemplate>),
    IssuancePolicie(Box<IssuancePolicie>),
    /// Filtered-out container, unknown/other object — nothing to collect.
    Skip,
}

/// Parse one bulk entry. Runs on a rayon worker thread, so it takes the shared
/// `schema_guid_map`/`domain_sid` by read-only reference and returns its own
/// local map contributions.
fn parse_one(
    entry: SearchEntry,
    domain: &str,
    domain_sid: &str,
    schema_guid_map: &HashMap<String, String>,
) -> Result<(Parsed, LocalMaps), Box<dyn Error>> {
    let mut m = LocalMaps::default();
    let atype = get_type(&entry).unwrap_or(Type::Unknown);

    let parsed = match atype {
        Type::User => {
            let mut user = User::new();
            user.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::User(Box::new(user))
        }
        Type::Group => {
            let mut group = Group::new();
            group.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::Group(Box::new(group))
        }
        Type::Computer => {
            let mut computer = Computer::new();
            computer.parse(
                entry, domain,
                &mut m.dn_sid, &mut m.sid_type, &mut m.fqdn_sid, &mut m.fqdn_ip,
                domain_sid, schema_guid_map,
            )?;
            Parsed::Computer(Box::new(computer))
        }
        Type::Ou => {
            let mut ou = Ou::new();
            ou.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::Ou(Box::new(ou))
        }
        Type::Gpo => {
            let mut gpo = Gpo::new();
            gpo.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::Gpo(Box::new(gpo))
        }
        Type::ForeignSecurityPrincipal => {
            let mut security_principal = Fsp::new();
            security_principal.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid)?;
            Parsed::Fsp(Box::new(security_principal))
        }
        Type::Container => {
            if PARSER_MOD_RE1.is_match(&entry.dn.to_uppercase())
                || PARSER_MOD_RE2.is_match(&entry.dn.to_uppercase())
            {
                Parsed::Skip
            } else {
                let mut container = Container::new();
                container.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
                Parsed::Container(Box::new(container))
            }
        }
        Type::Trust => {
            let mut trust = Trust::new();
            trust.parse(entry, domain)?;
            Parsed::Trust(Box::new(trust))
        }
        Type::NtAutStore => {
            let mut nt_auth_store = NtAuthStore::new();
            nt_auth_store.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::NtAuthStore(Box::new(nt_auth_store))
        }
        Type::AIACA => {
            let mut aiaca = AIACA::new();
            aiaca.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::AIACA(Box::new(aiaca))
        }
        Type::RootCA => {
            let mut root_ca = RootCA::new();
            root_ca.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::RootCA(Box::new(root_ca))
        }
        Type::EnterpriseCA => {
            let mut enterprise_ca = EnterpriseCA::new();
            enterprise_ca.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::EnterpriseCA(Box::new(enterprise_ca))
        }
        Type::CertTemplate => {
            let mut cert_template = CertTemplate::new();
            cert_template.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::CertTemplate(Box::new(cert_template))
        }
        Type::IssuancePolicie => {
            let mut issuance_policie = IssuancePolicie::new();
            issuance_policie.parse(entry, domain, &mut m.dn_sid, &mut m.sid_type, domain_sid, schema_guid_map)?;
            Parsed::IssuancePolicie(Box::new(issuance_policie))
        }
        // Handled sequentially before the bulk; should not reach here.
        Type::Domain | Type::Schema => Parsed::Skip,
        Type::Unknown => {
            let _unknown = parse_unknown(entry, domain);
            Parsed::Skip
        }
    };

    Ok((parsed, m))
}

/// Parse a buffered batch of bulk entries in parallel and merge the results
/// (objects + map contributions) into `results`, preserving input order.
#[allow(clippy::too_many_arguments)]
fn parse_batch(
    buffer: &mut Vec<SearchEntry>,
    results: &mut ADResults,
    domain: &str,
    domain_sid: &str,
    count: &mut usize,
    total: Option<usize>,
    pb: &ProgressBar,
) -> Result<(), Box<dyn Error>> {
    if buffer.is_empty() {
        return Ok(());
    }

    let entries = std::mem::take(buffer);

    // Serialize across all CPU cores. Errors are stringified inside the worker
    // (Box<dyn Error> isn't Send) so fail-fast semantics are preserved.
    let parsed: Vec<Result<(Parsed, LocalMaps), String>> = {
        let schema_guid_map = &results.mappings.schema_guid_map;
        entries
            .into_par_iter()
            .map(|entry| parse_one(entry, domain, domain_sid, schema_guid_map).map_err(|e| e.to_string()))
            .collect()
    };

    // Merge sequentially, in input order, so output ordering matches the
    // single-threaded collector exactly.
    for item in parsed {
        let (obj, maps) = item.map_err(|e| -> Box<dyn Error> { e.into() })?;

        results.mappings.dn_sid.extend(maps.dn_sid);
        results.mappings.sid_type.extend(maps.sid_type);
        results.mappings.fqdn_sid.extend(maps.fqdn_sid);
        results.mappings.fqdn_ip.extend(maps.fqdn_ip);

        match obj {
            Parsed::User(o) => results.users.push(*o),
            Parsed::Group(o) => results.groups.push(*o),
            Parsed::Computer(o) => results.computers.push(*o),
            Parsed::Ou(o) => results.ous.push(*o),
            Parsed::Gpo(o) => results.gpos.push(*o),
            Parsed::Fsp(o) => results.fsps.push(*o),
            Parsed::Container(o) => results.containers.push(*o),
            Parsed::Trust(o) => results.trusts.push(*o),
            Parsed::NtAuthStore(o) => results.ntauthstores.push(*o),
            Parsed::AIACA(o) => results.aiacas.push(*o),
            Parsed::RootCA(o) => results.rootcas.push(*o),
            Parsed::EnterpriseCA(o) => results.enterprisecas.push(*o),
            Parsed::CertTemplate(o) => results.certtemplates.push(*o),
            Parsed::IssuancePolicie(o) => results.issuancepolicies.push(*o),
            Parsed::Skip => {}
        }

        update_progress(count, total, pb)?;
    }

    Ok(())
}

/// Advance the parsing progress bar.
fn update_progress(count: &mut usize, total: Option<usize>, pb: &ProgressBar) -> Result<(), Box<dyn Error>> {
    if let Some(total) = total {
        *count += 1;
        // Percentage (%) = 100 x partial value / total value
        let percentage = 100 * *count / total;
        progress_bar(
            pb.to_owned(),
            "Parsing LDAP objects".to_string(),
            percentage.try_into()?,
            "%".to_string(),
        );
    }
    Ok(())
}

// for `total_objects`, the total number of objects may not be known if the ldap query was never run
// (e.g run was resumed from cached results)
//
// Parsing strategy:
//   * Schema and Domain objects are parsed sequentially as they stream in. The
//     collector guarantees they come first (see the naming-context ordering in
//     `ldap.rs`), and the rest of the parsing reads `schema_guid_map` /
//     `domain_sid` read-only, so they must be complete beforehand.
//   * Every other object is buffered and parsed in parallel batches across all
//     CPU cores, which is the hot path on large domains.
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
    let mut count = 0usize;
    let total = total_objects;
    let mut domain_sid: String = "DOMAIN_SID".to_owned();

    log::info!("Starting the LDAP objects parsing...");

    let mut buffer: Vec<SearchEntry> = Vec::with_capacity(PARSE_BATCH);

    for entry in source.into_entry_iter() {
        let entry: SearchEntry = entry?.into();
        route_entry(entry, &mut results, &mut buffer, domain, &mut domain_sid, &mut count, total, &pb)?;
    }

    // Parse whatever remains in the buffer.
    parse_batch(&mut buffer, &mut results, domain, &domain_sid, &mut count, total, &pb)?;

    pb.finish_and_clear();
    log::info!("Parsing LDAP objects finished!");
    Ok(results)
}

/// Route a single decoded entry: schema and domain are parsed sequentially
/// (they must complete before the bulk), everything else is buffered for
/// parallel batch parsing.
#[allow(clippy::too_many_arguments)]
fn route_entry(
    entry: SearchEntry,
    results: &mut ADResults,
    buffer: &mut Vec<SearchEntry>,
    domain: &str,
    domain_sid: &mut String,
    count: &mut usize,
    total: Option<usize>,
    pb: &ProgressBar,
) -> Result<(), Box<dyn Error>> {
    let atype = get_type(&entry).unwrap_or(Type::Unknown);
    match atype {
        Type::Schema => {
            // Sequential: builds schema_guid_map, read by every ACE parse.
            let schema = Schema::new();
            schema.parse(entry, &mut results.mappings.schema_guid_map)?;
            update_progress(count, total, pb)?;
        }
        Type::Domain => {
            // Flush any already-buffered bulk objects first, so they keep the
            // domain_sid they were collected under (matches the single-threaded
            // ordering). In practice the domain object precedes the bulk, so the
            // buffer is empty here.
            parse_batch(buffer, results, domain, domain_sid.as_str(), count, total, pb)?;

            let mut domain_object = Domain::new();
            let domain_sid_from_domain = domain_object.parse(
                entry,
                domain,
                &mut results.mappings.dn_sid,
                &mut results.mappings.sid_type,
                &results.mappings.schema_guid_map,
            )?;
            // Update only if domain_sid is valid
            if domain_sid_from_domain != "DOMAIN_SID" && !domain_sid_from_domain.is_empty() {
                *domain_sid = domain_sid_from_domain;
            }
            if !domain_object.object_identifier().is_empty() {
                results.domains.push(domain_object);
            }
            update_progress(count, total, pb)?;
        }
        _ => {
            buffer.push(entry);
            if buffer.len() >= PARSE_BATCH {
                parse_batch(buffer, results, domain, domain_sid.as_str(), count, total, pb)?;
            }
        }
    }
    Ok(())
}

// Parse directly from a disk cache, decoding bincode records on worker threads.
//
// The reader thread only does cheap length-prefixed reads; the CPU-heavy
// bincode decode happens inside a rayon batch, alongside the object parsing.
// This keeps all cores busy on `--cache` / `--resume`, where the single-threaded
// decode was previously the bottleneck.
pub fn parse_result_type_from_disk(
    common_args: &Options,
    mut reader: DiskStorageReader<LdapSearchEntry>,
    total_objects: Option<usize>,
) -> Result<ADResults, Box<dyn Error>> {
    let mut results = ADResults::default();
    let domain = &common_args.domain;

    let pb = ProgressBar::new(1);
    let mut count = 0usize;
    let total = total_objects;
    let mut domain_sid: String = "DOMAIN_SID".to_owned();

    log::info!("Starting the LDAP objects parsing...");

    let mut raw_buf: Vec<Vec<u8>> = Vec::with_capacity(PARSE_BATCH);
    let mut buffer: Vec<SearchEntry> = Vec::with_capacity(PARSE_BATCH);

    loop {
        match reader.next_raw() {
            Some(Ok(blob)) => {
                raw_buf.push(blob);
                if raw_buf.len() >= PARSE_BATCH {
                    decode_and_route(&mut raw_buf, &mut results, &mut buffer, domain, &mut domain_sid, &mut count, total, &pb)?;
                }
            }
            Some(Err(e)) => return Err(e.into()),
            None => break,
        }
    }

    // Decode and route any remaining raw records, then parse the last bulk batch.
    decode_and_route(&mut raw_buf, &mut results, &mut buffer, domain, &mut domain_sid, &mut count, total, &pb)?;
    parse_batch(&mut buffer, &mut results, domain, &domain_sid, &mut count, total, &pb)?;

    pb.finish_and_clear();
    log::info!("Parsing LDAP objects finished!");
    Ok(results)
}

/// Decode a batch of raw bincode records in parallel, then route each decoded
/// entry (preserving stream order, so schema/domain are handled before bulk).
#[allow(clippy::too_many_arguments)]
fn decode_and_route(
    raw_buf: &mut Vec<Vec<u8>>,
    results: &mut ADResults,
    buffer: &mut Vec<SearchEntry>,
    domain: &str,
    domain_sid: &mut String,
    count: &mut usize,
    total: Option<usize>,
    pb: &ProgressBar,
) -> Result<(), Box<dyn Error>> {
    if raw_buf.is_empty() {
        return Ok(());
    }

    let blobs = std::mem::take(raw_buf);

    // The CPU-heavy bincode decode, spread across all cores.
    let decoded: Vec<Result<SearchEntry, String>> = blobs
        .into_par_iter()
        .map(|data| {
            bincode::decode_from_slice::<LdapSearchEntry, _>(&data, bincode::config::standard())
                .map(|(entry, _)| SearchEntry::from(entry))
                .map_err(|e| format!("Failed to decode item: {e:?}"))
        })
        .collect();

    for decoded_entry in decoded {
        let entry = decoded_entry.map_err(|e| -> Box<dyn Error> { e.into() })?;
        route_entry(entry, results, buffer, domain, domain_sid, count, total, pb)?;
    }

    Ok(())
}

