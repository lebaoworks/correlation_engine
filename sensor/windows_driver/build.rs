//! Build script — configure the WDK binary image and link FltMgr.
//!
//! `wdk_build::configure_wdk_binary_project()` wires up the include paths, the
//! `ntoskrnl.lib`/`hal.lib` imports and the `/kernel` link flags from the WDK the
//! developer has installed (WDKContentRoot). We additionally link `fltmgr.lib`
//! because this is a minifilter and the `Flt*` imports live there rather than in
//! ntoskrnl — sanctum is a plain WDM driver and so never needs this line.

fn main() -> Result<(), wdk_build::ConfigError> {
    wdk_build::configure_wdk_binary_build()?;

    // Minifilter API (FltRegisterFilter, FltCreateCommunicationPort, Flt* I/O
    // helpers, Mm* mapping helpers used from FltMgr contexts) resolves from
    // fltMgr.lib. Name is lowercase for the case-sensitive `link` search.
    println!("cargo:rustc-link-lib=static=fltMgr");

    Ok(())
}
