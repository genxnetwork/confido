# confido

# server
cd ./server
cargo build
RUSTLOG=debug target/debug/confido_server [host:port] [atls-certs-folder] 

Build requirements: 
 - sudo yum install perl-FindBin perl-IPC-Cmd tss2 tss2-devel tpm2-tss tpm2-tss-devel clang
 - Fork of the [azure-cvm-tooling](https://github.com/genxnetwork/azure-cvm-tooling)

# client 
cd ./client
cargo build
RUSTLOG=debug target/debug/confido_client 
