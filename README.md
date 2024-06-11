# confido

# server
cd ./server
cargo build
RUSTLOG=debug target/debug/confido_server [host:port] [atls-certs-folder] 

# client 
cd ./client
cargo build
RUSTLOG=debug target/debug/confido_client 
