
struct Block {
    block: [u8; 16], // Use bytes instead of bits
    master_key: [u8; 32],
}

impl Block {
    fn xor(&self, xor_arr: [u8; 16]) -> [u8; 16] {
        let mut result: [u8; 16] = [0x00;16];
        for i in 0..16 {
            result[i] = self.block[i] ^ xor_arr[i];
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn xor_test() {
        let block = Block {
            block: [ 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 ],
            master_key: [0; 32],
        };
        let test_arr: [u8; 16] = [ 0x6e, 0xa2, 0x76, 0x72, 0x6c, 0x48, 0x7a, 0xb8,
                                  0x5d, 0x27, 0xbd, 0x10, 0xdd, 0x84, 0x94, 0x01 ];
        let valid_xored_arr: [u8; 16] = [ 0xe6, 0x3b, 0xdc, 0xc9, 0xa0, 0x95, 0x94, 0x47, 
                                       0x5d, 0x36, 0x9f, 0x23, 0x99, 0xd1, 0xf2, 0x76 ];
        assert_eq!(block.xor(test_arr), valid_xored_arr)
    }
}