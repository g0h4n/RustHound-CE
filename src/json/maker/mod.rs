use std::collections::HashMap;
use std::error::Error;

extern crate zip;
use crate::api::ADResults;
use crate::args::Options;
use crate::utils::date::return_current_fulldate;
pub mod common;

/// This function will create json output and zip output
pub fn make_result(common_args: &Options, ad_results: ADResults) -> Result<String, Box<dyn Error>> {
   // Format domain name
   let filename = common_args.domain.replace(".", "-").to_lowercase();

   // Hashmap for json files
   let mut json_result: HashMap<String, String> = HashMap::new();

   // Datetime for output file
   let datetime = return_current_fulldate();

   // Add all in json files
   common::add_file(
      &datetime,
      "users".to_string(),
		&filename,
      ad_results.users,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "groups".to_string(),
		&filename,
      ad_results.groups,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "computers".to_string(),
		&filename,
      ad_results.computers,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "ous".to_string(),
		&filename,
      ad_results.ous,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "domains".to_string(),
		&filename,
      ad_results.domains,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "gpos".to_string(),
      &filename,
      ad_results.gpos,
      &mut json_result,
      common_args,
   )?;
   // }
   common::add_file(
      &datetime,
      "containers".to_string(),
		&filename,
      ad_results.containers,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "ntauthstores".to_string(),
		&filename,
      ad_results.ntauthstores,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "aiacas".to_string(),
		&filename,
      ad_results.aiacas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "rootcas".to_string(),
		&filename,
      ad_results.rootcas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "enterprisecas".to_string(),
		&filename,
      ad_results.enterprisecas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "certtemplates".to_string(),
		&filename,
      ad_results.certtemplates,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "issuancepolicies".to_string(),
		&filename,
      ad_results.issuancepolicies,
      &mut json_result,
      common_args,
   )?;
   // All in zip file
   if common_args.zip {
      return Ok(common::make_a_zip(
         &datetime,
         &filename,
         &common_args.path,
         &json_result)?)
   }
   Ok(String::from("No zip full path"))
}