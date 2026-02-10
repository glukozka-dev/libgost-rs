use libgost_rs::Kuznechik;
use std::fs::File;
use std::io::Read;
use std::time::Instant;

fn flatten_ciphertext(ciphertext: Vec<Vec<u8>>) -> Vec<u8> {
    let total_len: usize = ciphertext.iter().map(|block| block.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    
    for block in ciphertext {
        result.extend_from_slice(&block);
    }
    
    result
}

fn benchmark_encrypt_file(kuznechik: &Kuznechik, filename: &str, iv: &[u8]) -> (f64, Vec<Vec<u8>>, usize) {
    let mut file = File::open(filename).expect("Не удалось открыть файл");
    let mut plaintext = Vec::new();
    file.read_to_end(&mut plaintext).expect("Не удалось прочитать файл");
    
    let total_bytes = plaintext.len();
    println!("Файл: {} ({} байт)", filename, total_bytes);

    let start = Instant::now();
    let ciphertext = kuznechik.encrypt_cbc(plaintext, iv.to_vec());
    let duration = start.elapsed();
    
    let speed = total_bytes as f64 / duration.as_secs_f64() / 1024.0 / 1024.0;
    
    (speed, ciphertext, total_bytes)
}

fn benchmark_decrypt_file(kuznechik: &Kuznechik, ciphertext: Vec<Vec<u8>>, iv: &[u8], total_bytes: usize) -> f64 {
    let flat_ciphertext = flatten_ciphertext(ciphertext);
    
    let start = Instant::now();
    let _plaintext = kuznechik.decrypt_cbc(flat_ciphertext, iv.to_vec());
    let duration = start.elapsed();
    
    total_bytes as f64 / duration.as_secs_f64() / 1024.0 / 1024.0
}

fn main() {
    let kuznechik = Kuznechik::new([
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
    ]);
    
    let iv = vec![
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5,
        0xf0, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19
    ];
    
    println!("=== Бенчмарк шифрования файлов ===\n");
    
    let test_files = ["test_1k.bin", "test_10k.bin", "test_100k.bin", "test_1m.bin", "test_10m.bin", "test_50m.bin", "test_100m.bin"];
    
    for filename in test_files.iter() {
        if std::path::Path::new(filename).exists() {
            println!("Тестируем файл: {}", filename);
            
            // Шифрование
            let (encrypt_speed, ciphertext, total_bytes) = benchmark_encrypt_file(&kuznechik, filename, &iv);
            println!("  Шифрование: {:.2} MB/s", encrypt_speed);
            
            // Дешифрование
            let decrypt_speed = benchmark_decrypt_file(&kuznechik, ciphertext, &iv, total_bytes);
            println!("  Дешифрование: {:.2} MB/s", decrypt_speed);
            println!("  Отношение: {:.2}\n", encrypt_speed / decrypt_speed);
        } else {
            println!("Файл {} не найден, пропускаем\n", filename);
        }
    }
}
