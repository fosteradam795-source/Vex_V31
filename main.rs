use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: vex_rs <script.vx> (vex file)");
        return;
    }
    if let Ok(content) = fs::read_to_string(&args[1]) {
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(msg) = trimmed.strip_prefix("write.") {
                println!("{}", msg);
            }
        }
    }
}
