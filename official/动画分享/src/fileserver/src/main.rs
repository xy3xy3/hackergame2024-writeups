use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;

fn main() -> std::io::Result<()> {
    let address = "127.0.0.1:8000";
    let listener = TcpListener::bind(address)?;

    println!("Serving HTTP on {}", address);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_connection(stream);
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_connection(mut stream: TcpStream) {
    let mut buffer = [0; 1024];
    match stream.read(&mut buffer) {
        Ok(_) => {
            let request = String::from_utf8_lossy(&buffer[..]);

            println!("Received request: {}", request.lines().next().unwrap_or(""));

            let request_line = request.lines().next().unwrap_or("");
            let parts: Vec<&str> = request_line.split_whitespace().collect();

            if parts.len() < 2 {
                send_response(&mut stream, 400, "Bad Request", "Invalid HTTP request.");
                return;
            }

            let method = parts[0];
            let path = parts[1];

            if method != "GET" {
                send_response(&mut stream, 405, "Method Not Allowed", "Only GET method is supported.");
                return;
            }

            let file_path = &path[1..];

            if file_path.contains("..") {
                send_response(&mut stream, 400, "Bad Request", "Invalid file path.");
                return;
            }

            if Path::new(file_path).is_file() {
                match fs::read(file_path) {
                    Ok(contents) => {
                        let status_line = "HTTP/1.1 200 OK\r\n";

                        let headers = format!(
                            "Content-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n",
                            contents.len(),
                        );

                        if let Err(e) = stream.write_all(status_line.as_bytes()) {
                            eprintln!("Failed to write status line: {}", e);
                        }
                        if let Err(e) = stream.write_all(headers.as_bytes()) {
                            eprintln!("Failed to write headers: {}", e);
                        }
                        if let Err(e) = stream.write_all(&contents) {
                            eprintln!("Failed to write file contents: {}", e);
                        }
                    }
                    Err(_) => {
                        send_response(&mut stream, 500, "Internal Server Error", "Failed to read the file.");
                    }
                }
            } else {
                send_response(&mut stream, 404, "Not Found", "File not found.");
            }
        }
        Err(e) => {
            eprintln!("Failed to read from connection: {}", e);
        }
    }
}

fn send_response(stream: &mut TcpStream, status_code: u16, status_text: &str, body: &str) {
    let status_line = format!("HTTP/1.1 {} {}\r\n", status_code, status_text);
    let headers = format!(
        "Content-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
        body.len()
    );
    let response = format!("{}{}{}", status_line, headers, body);

    if let Err(e) = stream.write_all(response.as_bytes()) {
        eprintln!("Failed to send response: {}", e);
    }
}
