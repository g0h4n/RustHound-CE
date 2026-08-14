use std::error::Error;

extern crate zip;
use crate::api::ADResults;
use crate::args::Options;
use crate::utils::date::return_current_fulldate;
pub mod common;

/// This function will create json output and zip output.
///
/// Objects are streamed directly to disk / into the zip archive instead of
/// being fully materialised in memory first, so it stays flat on RAM even for
/// domains with millions of objects.
pub fn make_result(common_args: &Options, ad_results: ADResults) -> Result<String, Box<dyn Error>> {
   // Format domain name
   let filename = common_args.domain.replace('.', "-").to_lowercase();

   // Datetime for output file
   let datetime = return_current_fulldate();

   if common_args.zip {
      return common::make_a_zip(&datetime, &filename, &common_args.path, &ad_results);
   }

   common::write_json_files(&datetime, &filename, common_args, &ad_results)?;
   Ok(String::from("No zip full path"))
}
