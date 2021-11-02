use tokio::task;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() {
	let handle = tokio::spawn(async {
		task::spawn(async {
		    // ...
		    println!("spawned task done!")
		});

		// Yield, allowing the newly-spawned task to execute first.
		task::yield_now().await;
		println!("main task done!");
	});
	handle.await;
	println!("done");
}

