#[test]
fn trycmd_tests() {
    let pattern = format!("{}/tests/cmd/*.md", env!("CARGO_MANIFEST_DIR"));
    trycmd::TestCases::new().case(pattern);
}
