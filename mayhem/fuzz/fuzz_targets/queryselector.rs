#![no_main]
use libfuzzer_sys::fuzz_target;
extern crate tl;

const HTML: &str = r#"
<!DOCTYPE html>
<div>
    <p id="greeting">Hello World</p>
    <img id="img" src="image.png" />
</div>
"#;

// Fuzz the query-selector PARSER with arbitrary `data` as the selector string,
// against a fixed parsed DOM — the mayhemheroes harness this backport reproduces
// (mayhemheroes/tl fuzz/fuzz_targets/queryselector.rs, commit 522ac4c). Upstream's
// own copy at this pinned commit does not compile (it calls .query_selector on the
// Result returned by tl::parse and ignores that query_selector returns an Option),
// so the mayhemheroes run built a fixed copy; this is that copy, with the Result
// and the Option handled instead of unwrapped. We do not edit upstream.
//
// The selector grammar recurses (parser.rs Parser::selector <-> parse_combinator)
// once per combinator with no depth limit, so a long enough selector exhausts the
// thread stack before the input runs out — the bug. Nothing here bounds the stack:
// the recursion runs on libFuzzer's own (8 MiB) main stack, exactly as it did in
// the original run. What restores the original geometry is the UNOPTIMIZED build
// mayhem/build.sh does, matching the `cargo fuzz build` the mayhemheroes image ran.
fuzz_target!(|data: &str| {
    let dom = match tl::parse(HTML, tl::ParserOptions::default()) {
        Ok(dom) => dom,
        Err(_) => return,
    };
    if let Some(iter) = dom.query_selector(data) {
        for _ in iter {
            // do nothing
        }
    }
});
