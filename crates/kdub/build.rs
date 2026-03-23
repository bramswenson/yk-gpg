fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Emit git SHA via vergen-gitcl
    let git = vergen_gitcl::GitclBuilder::all_git()?;
    vergen_gitcl::Emitter::default()
        .add_instructions(&git)?
        .emit()?;

    // Emit build date using SOURCE_DATE_EPOCH for reproducible builds, else current date
    let build_date = if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        let secs: i64 = epoch.parse().unwrap_or(0);
        // Format as YYYY-MM-DD
        let days = secs / 86400;
        // Use a simple calculation from Unix epoch (1970-01-01)
        epoch_days_to_date(days)
    } else {
        // Use the VERGEN_BUILD_DATE approach: read current date
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let days = now.as_secs() as i64 / 86400;
        epoch_days_to_date(days)
    };
    println!("cargo:rustc-env=KDUB_BUILD_DATE={build_date}");

    // Emit target triple (cargo already sets CARGO_CFG_TARGET_ARCH etc., but not the full triple)
    // TARGET is available as a build script env var
    if let Ok(target) = std::env::var("TARGET") {
        println!("cargo:rustc-env=KDUB_TARGET={target}");
    }

    // Ensure Cargo reruns this script when these env vars change
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    Ok(())
}

/// Convert Unix epoch days to "YYYY-MM-DD" string.
fn epoch_days_to_date(days: i64) -> String {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}
