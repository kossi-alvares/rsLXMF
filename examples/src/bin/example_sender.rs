fn main() -> lxmf_examples::ExampleResult {
    let recipient = std::env::args().nth(1);
    lxmf_examples::sender(recipient.as_deref())
}
