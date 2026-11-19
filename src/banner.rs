//! Launch and end banners
use colored::*;
use crate::{args::RUSTHOUND_VERSION, utils::date::{return_current_date,return_current_time}};
use indicatif::{ProgressBar, ProgressStyle};

/// Banner when RustHound-CE start.
pub fn print_banner() {
    // https://docs.rs/colored/2.0.0/x86_64-pc-windows-msvc/colored/control/fn.set_virtual_terminal.html
    #[cfg(windows)]
    control::set_virtual_terminal(true).unwrap();

    // Banner for RustHound-CE
    println!("{}","---------------------------------------------------".clear().bold());
    println!("Initializing {} at {} on {}",
        "RustHound-CE".truecolor(247,76,0,),
        return_current_time(),
        return_current_date()
    );
    println!("Version {} powered by {}",RUSTHOUND_VERSION.bold(),"@g0h4n_0".bold());
    println!("{}\n","---------------------------------------------------".clear().bold());
}

/// Banner when RustHound-CE finish.
pub fn print_end_banner() {
    // End banner for RustHound-CE
    println!("\n{} Enumeration Completed at {} on {}! Happy Graphing!\n",
        "RustHound-CE".truecolor(247,76,0,),
        return_current_time(),
        return_current_date()
    );
}

/// Progress Bar used in RustHound-CE.
pub fn progress_bar(
	pb: ProgressBar,
	message: String,
	count: u64,
    end_message: String,
) {
	pb.set_style(ProgressStyle::with_template("{prefix:.bold.dim}{spinner} {wide_msg}")
		.unwrap()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "));
	pb.inc(count);
	pb.with_message(format!("{}: {}{}",message,count,end_message));
}