#[test]
fn trycmd_tests() {
    trycmd::TestCases::new().case("tests/cmd/*.md");
}
