use crate::streebog::constants::*;


pub const BLOCK_SIZE: usize = 64; // 512 бит
pub const HASH_SIZE_256: usize = 32; // 256 бит
pub const HASH_SIZE_512: usize = 64; // 512 бит

/// Инициализационные векторы из п.5.1
const IV_512: [u8; BLOCK_SIZE] = [0x00; BLOCK_SIZE];
const IV_256: [u8; BLOCK_SIZE] = {
    let mut iv = [0x00; BLOCK_SIZE];
    iv[0] = 0x01;
    iv
};

/// Преобразование S (п.5.2) - использование таблицы P
fn s_transform(a: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = P[a[i] as usize];
    }
    result
}

/// Преобразование P (перестановка байт, п.5.3)
fn p_transform(a: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    
    // Транспонирование матрицы 8x8 (перестановка τ из п.5.3)
    for i in 0..8 {
        for j in 0..8 {
            result[8 * j + i] = a[8 * i + j];
        }
    }
    
    result
}

/// Линейное преобразование L (п.5.4) с использованием предвычисленной таблицы
fn l_transform(a: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    
    // Разбиваем на 8 64-битных слов (порядок little-endian)
    let words: [u64; 8] = unsafe { std::mem::transmute(a) };
    
    // Применяем линейное преобразование к каждому слову
    for i in 0..8 {
        let mut acc = 0u64;
        
        // Умножение на матрицу A через предвычисленную таблицу
        for j in 0..8 {
            let byte = (words[j] >> (8 * i)) as u8;
            acc ^= SHUFFLED_LIN_TABLE[j][byte as usize];
        }
        
        // Сохраняем результат
        let bytes = acc.to_le_bytes();
        result[8*i..8*(i+1)].copy_from_slice(&bytes);
    }
    
    result
}

/// LPS-преобразование: L ∘ P ∘ S (раздел 6)
fn lps_transform(a: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    l_transform(p_transform(s_transform(a)))
}

/// X[k](a) = k ⊕ a (формула 3)
fn x_transform(k: [u8; BLOCK_SIZE], a: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        result[i] = k[i] ^ a[i];
    }
    result
}

/// E(K, m) = X[K13] ∘ LPSX[K12] ∘ ... ∘ LPSX[K1](m) (раздел 7)
fn e_function(k: [u8; BLOCK_SIZE], m: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut state = m;
    let mut current_k = k;
    
    // Итерации 1-12
    for i in 0..12 {
        if i == 0 {
            // X[K1] для первой итерации
            state = x_transform(current_k, state);
        } else {
            // LPSX[Ki] для итераций 2-12
            state = lps_transform(state);
            state = x_transform(current_k, state);
        }
        
        // Вычисляем следующий Ki (формулы 9-10)
        if i < 11 {
            let k_plus_c = x_transform(current_k, C[i]);
            current_k = lps_transform(k_plus_c);
        }
    }
    
    state
}

/// Функция сжатия g_N(h, m) (формула 8)
fn g_function(h: [u8; BLOCK_SIZE], m: [u8; BLOCK_SIZE], n: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // K = LPS(h ⊕ N)
    let k = lps_transform(x_transform(h, n));
    
    // E(K, m)
    let e_result = e_function(k, m);
    
    // E(K, m) ⊕ h ⊕ m
    x_transform(x_transform(e_result, h), m)
}

/// Сложение по модулю 2^512
fn add_mod_512(a: [u8; BLOCK_SIZE], b: [u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    let mut result = [0u8; BLOCK_SIZE];
    let mut carry = 0u16;
    
    for i in 0..BLOCK_SIZE {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
    
    result
}

/// Конвертация 64-битного числа в массив байт (little-endian)
fn u64_to_bytes(value: u64) -> [u8; 8] {
    value.to_le_bytes()
}

/// Конвертация массива байт в 64-битное число (little-endian)
fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[0..8]);
    u64::from_le_bytes(buf)
}

/// Основная структура для хеширования
pub struct Streebog {
    h: [u8; BLOCK_SIZE],     // текущее состояние
    n: [u8; BLOCK_SIZE],     // длина обработанных данных в битах
    sigma: [u8; BLOCK_SIZE], // сумма всех блоков
    buffer: Vec<u8>,
    is_256: bool,
}

impl Streebog {
    /// Создание хешера для 256-битного хеша
    pub fn new_256() -> Self {
        Streebog {
            h: IV_256,
            n: [0u8; BLOCK_SIZE],
            sigma: [0u8; BLOCK_SIZE],
            buffer: Vec::new(),
            is_256: true,
        }
    }
    
    /// Создание хешера для 512-битного хеша
    pub fn new_512() -> Self {
        Streebog {
            h: IV_512,
            n: [0u8; BLOCK_SIZE],
            sigma: [0u8; BLOCK_SIZE],
            buffer: Vec::new(),
            is_256: false,
        }
    }
    
    /// Добавление данных для хеширования
    pub fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        
        // Обработка полных блоков
        while self.buffer.len() >= BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            block.copy_from_slice(&self.buffer[..BLOCK_SIZE]);
            
            // Обработка блока (п.8.2)
            self.h = g_function(self.h, block, self.n);
            
            // Обновление N (добавление 512 бит)
            let mut block_len = [0u8; BLOCK_SIZE];
            block_len[0] = 0x02; // 512 бит = 0x200 в little-endian
            block_len[1] = 0x00;
            self.n = add_mod_512(self.n, block_len);
            
            // Обновление Σ
            self.sigma = add_mod_512(self.sigma, block);
            
            // Удаление обработанного блока
            self.buffer.drain(..BLOCK_SIZE);
        }
    }
    
    /// Завершение хеширования и получение результата
    pub fn finalize(mut self) -> Vec<u8> {
        let original_len = self.buffer.len();
        
        // Создание дополненного блока (п.8.3, этап 3.1)
        let mut padded_block = [0u8; BLOCK_SIZE];
        if original_len > 0 {
            padded_block[..original_len].copy_from_slice(&self.buffer);
        }
        padded_block[original_len] = 0x01; // Добавление 1
        
        // Обработка дополненного блока
        self.h = g_function(self.h, padded_block, self.n);
        
        // Обновление N (добавление длины исходных данных в битах)
        let bit_length = (original_len as u64) * 8;
        let mut length_bytes = [0u8; BLOCK_SIZE];
        length_bytes[..8].copy_from_slice(&bit_length.to_le_bytes());
        self.n = add_mod_512(self.n, length_bytes);
        
        // Обновление Σ
        self.sigma = add_mod_512(self.sigma, padded_block);
        
        // Финальные преобразования (п.8.3, этап 3.5-3.6)
        let zeros = [0u8; BLOCK_SIZE];
        
        // g_0(h, N)
        self.h = g_function(self.h, self.n, zeros);
        
        // g_0(h, Σ)
        self.h = g_function(self.h, self.sigma, zeros);
        
        // Для 256-битной версии берем младшие 32 байта
        if self.is_256 {
            let mut result = vec![0u8; HASH_SIZE_256];
            result.copy_from_slice(&self.h[32..]);
            result
        } else {
            self.h.to_vec()
        }
    }
    
    /// Хеширование с одним вызовом (256 бит)
    pub fn hash_256(data: &[u8]) -> [u8; HASH_SIZE_256] {
        let mut hasher = Streebog::new_256();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; HASH_SIZE_256];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Хеширование с одним вызовом (512 бит)
    pub fn hash_512(data: &[u8]) -> [u8; HASH_SIZE_512] {
        let mut hasher = Streebog::new_512();
        hasher.update(data);
        let result = hasher.finalize();
        let mut hash = [0u8; HASH_SIZE_512];
        hash.copy_from_slice(&result);
        hash
    }
    
    /// Отладочная информация
    pub fn debug_state(&self) {
        println!("h: {:02x?}", &self.h);
        println!("n: {:02x?}", &self.n);
        println!("sigma: {:02x?}", &self.sigma);
        println!("buffer len: {}", self.buffer.len());
    }
}

// Вспомогательные функции
pub fn to_hex_string(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

fn from_hex_string(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..hex.len() / 2 {
        let byte = u8::from_str_radix(&hex[i*2..i*2+2], 16).unwrap();
        bytes.push(byte);
    }
    bytes
}

// Тесты на основе стандарта
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_streebog() {
        let M1_hex: &str = "323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130";
        let M1_HASH_512_EXPECTED: [u8; 64] = [
    0x48, 0x6f, 0x64, 0xc1, 0x91, 0x78, 0x79, 0x41,
    0x7f, 0xef, 0x08, 0x2b, 0x33, 0x81, 0xa4, 0xe2,
    0x11, 0xc3, 0x24, 0xf0, 0x74, 0x65, 0x4c, 0x38,
    0x82, 0x3a, 0x7b, 0x76, 0xf8, 0x30, 0xad, 0x00,
    0xfa, 0x1f, 0xba, 0xe4, 0x2b, 0x12, 0x85, 0xc0,
    0x35, 0x2f, 0x22, 0x75, 0x24, 0xbc, 0x9a, 0xb1,
    0x62, 0x54, 0x28, 0x8d, 0xd6, 0x86, 0x3d, 0xcc,
    0xd5, 0xb9, 0xf5, 0x4a, 0x1a, 0xd0, 0x54, 0x1b
];
    
        let M1_HASH_256_EXPECTED: [u8; 32] = [
        0x9d, 0xd2, 0xfe, 0x4e, 0x90, 0x40, 0x9e, 0x5d,
        0xa8, 0x7f, 0x53, 0x97, 0x6d, 0x74, 0x05, 0xb0,
        0xc0, 0xca, 0xc6, 0x28, 0xfc, 0x66, 0x9a, 0x74,
        0x1d, 0x50, 0x06, 0x3c, 0x55, 0x7e, 0x8f, 0x50
    ];
        let message = hex_to_bytes(M1_hex);
        let hash = Streebog::hash_512(&message);
        let hash_hex = to_hex_string(&hash);
        let expected_hex = to_hex_string(&M1_HASH_512_EXPECTED);

        println!("Computed hash: {}", hash_hex);
        println!("Expected hash: {}", expected_hex);
         assert_eq!(hash, M1_HASH_512_EXPECTED, 
            "512-bit hash mismatch for M1\nComputed: {}\nExpected: {}", 
            hash_hex, expected_hex);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}