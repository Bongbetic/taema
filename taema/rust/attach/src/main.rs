fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let layout = taema_attach::Layout::load();
    match taema_attach::run(&argv, &layout) {
        Ok(()) => {}
        Err(message) => {
            eprintln!("taema-attach: {}", message);
            std::process::exit(1);
        }
    }
}
