fn main() -> lxmf_examples::ExampleResult {
    let packed = std::env::args().nth(1);
    lxmf_examples::receiver(packed.as_deref())
}
