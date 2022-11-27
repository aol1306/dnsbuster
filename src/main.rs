use clap::Parser;
use futures::future::select_all;
use futures::FutureExt;
use std::collections::VecDeque;
use std::fs::File;
use std::io::BufRead;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::{config::*, AsyncResolver};

/// Asynchronous DNS subdomain enumeration tool
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Path to subdomains file
    #[arg(short, long)]
    subdomains: String,

    /// Target domain to enumerate
    #[arg(short, long)]
    target: String,

    /// Name server to use (example: 1.1.1.1:53)
    #[arg(short, long)]
    ns: Option<String>,

    /// Queries per Second
    #[arg(short, long, default_value_t = 10)]
    qps: u32,

    /// Enable debug output
    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

#[derive(Debug, Clone)]
enum ResolveStatus {
    Pending,
    Timeout,
    Resolved,
    CantResolve,
}

#[derive(Debug, Clone)]
struct ResolveTask {
    subdomain: String,
    status: ResolveStatus,
}

impl ResolveTask {
    fn new(subdomain: String) -> ResolveTask {
        ResolveTask {
            subdomain,
            status: ResolveStatus::Pending,
        }
    }
}

async fn resolve(
    resolver: &AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>,
    task: ResolveTask,
    target: &str,
) -> ResolveTask {
    let to_resolve = format!("{}.{}", task.subdomain, target);
    let response = resolver.lookup_ip(to_resolve).await;
    match response {
        Err(e) => match e.kind() {
            ResolveErrorKind::Timeout => ResolveTask {
                subdomain: task.subdomain,
                status: ResolveStatus::Timeout,
            },
            ResolveErrorKind::NoRecordsFound {
                query: _,
                soa: _,
                negative_ttl: _,
                response_code: _,
                trusted: _,
            } => ResolveTask {
                subdomain: task.subdomain,
                status: ResolveStatus::CantResolve,
            },
            _ => ResolveTask {
                subdomain: task.subdomain,
                status: ResolveStatus::CantResolve,
            },
        },
        Ok(_) => ResolveTask {
            subdomain: task.subdomain,
            status: ResolveStatus::Resolved,
        },
    }
}

/// Read input file and build a list of resolve tasks
fn read_subdomains(filename: String) -> Result<VecDeque<ResolveTask>, std::io::Error> {
    let file = File::open(filename)?;
    let lines: VecDeque<_> = std::io::BufReader::new(file)
        .lines()
        .filter_map(|x| x.ok())
        .map(|x| ResolveTask::new(x.to_string()))
        .collect();

    Ok(lines)
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // create tasks
    let mut pending_tasks = read_subdomains(args.subdomains).unwrap();

    // init resolver
    let resolver_config = match args.ns {
        Some(v) => {
            let mut ret = ResolverConfig::new();
            ret.add_name_server(NameServerConfig::new(v.parse().expect("Invalid NS address"), Protocol::Udp));
            ret
        },
        None => ResolverConfig::default(),
    };
    let resolver =
        AsyncResolver::tokio(resolver_config, ResolverOpts::default()).unwrap();

    let mut futures = vec![];
    let mut completed: usize = 0;
    let mut last_future_created = Instant::now();
    let future_creation_interval = Duration::from_secs(1) / args.qps;

    if args.debug {
        eprintln!("Target interval: {:?}", future_creation_interval);
    }

    loop {
        // calculate how many new futures to add this iteration
        let n_new_tasks: usize = if last_future_created.elapsed() > future_creation_interval {
            (last_future_created.elapsed().as_secs_f64() / future_creation_interval.as_secs_f64())
                .floor() as usize
        } else {
            0
        };

        // add futures
        for _ in 0..std::cmp::min(n_new_tasks, pending_tasks.len()) {
            if let Some(task) = pending_tasks.pop_back() {
                last_future_created = Instant::now();
                futures.push(resolve(&resolver, task, &args.target).boxed());
            }
        }

        // get some results
        if futures.len() > 0 {
            let (result, _, remaining_futures) = select_all(futures).await;
            completed += 1;
            println!("{}.{} {:?}", result.subdomain, args.target, result.status);
            futures = remaining_futures;
        }

        // only sleep if we are waiting for new tasks
        if futures.len() == 0 {
            sleep(Duration::from_millis(20)).await;
        }

        // In progress should ideally be a small number
        if args.debug {
            eprintln!(
                "Pending: {}, In progress: {}, Completed: {}",
                pending_tasks.len(),
                futures.len(),
                completed
            );
        }

        // if everything is done, quit
        if futures.len() == 0 && pending_tasks.len() == 0 {
            eprintln!("Completed");
            break;
        }
    }
}
