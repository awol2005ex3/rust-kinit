// kinit -kt CLI 入口
// 用法: kinit.exe -kt <keytab文件> <principal@REALM> [-o <ccache文件>]

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut keytab_path = None;
    let mut principal = None;
    let mut out_path = None;

    // 简单参数解析
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-kt" => {
                i += 1;
                if i < args.len() {
                    keytab_path = Some(args[i].as_str());
                }
            }
            "-o" => {
                i += 1;
                if i < args.len() {
                    out_path = Some(args[i].as_str());
                }
            }
            "-h" | "--help" => {
                print_usage(&args[0]);
                std::process::exit(0);
            }
            _ => {
                if principal.is_none() && !args[i].starts_with('-') {
                    principal = Some(args[i].as_str());
                }
            }
        }
        i += 1;
    }

    let keytab_path = match keytab_path {
        Some(p) => p,
        None => {
            eprintln!("错误: 必须指定 -kt <keytab文件>");
            print_usage(&args[0]);
            std::process::exit(1);
        }
    };

    let principal = match principal {
        Some(p) => p,
        None => {
            eprintln!("错误: 必须指定 principal");
            print_usage(&args[0]);
            std::process::exit(1);
        }
    };

    // 调用 lib 获取 TGT
    let ccache_data = match kinit_kt::request_tgt(keytab_path, principal, None) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("错误: {}", e);
            std::process::exit(1);
        }
    };

    // 确定输出路径（默认 %TEMP%\krb5cc_<USERNAME>，与 MIT kinit Windows 版行为一致）
    let out_path = match out_path {
        Some(p) => Path::new(p).to_path_buf(),
        None => {
            // 使用 Windows 用户名（与 MIT kinit 一致），而非 principal 名
            let os_user = env::var("USERNAME")
                .or_else(|_| env::var("USER"))
                .unwrap_or_else(|_| "unknown".to_string());
            let temp_dir = env::var("TEMP")
                .or_else(|_| env::var("TMP"))
                .unwrap_or_else(|_| ".".to_string());
            std::path::Path::new(&temp_dir).join(format!("krb5cc_{}", os_user))
        }
    };

    // 写入文件
    if let Err(e) = fs::write(&out_path, &ccache_data) {
        eprintln!("错误: 写入 {} 失败: {}", out_path.display(), e);
        std::process::exit(1);
    }

    eprintln!("TGT 已保存到 FILE:{}", out_path.display());
}

fn print_usage(program: &str) {
    eprintln!("用法: {} -kt <keytab文件> <principal@REALM> [-o <ccache文件>]", program);
    eprintln!("");
    eprintln!("示例:");
    eprintln!("  {} -kt hdfs.keytab hdfs@XXX.COM", program);
    eprintln!("  {} -kt hdfs.keytab hdfs@XXX.COM -o /tmp/krb5cc", program);
}
