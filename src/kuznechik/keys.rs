use crate::kuznechik::operations::*;

pub struct Keys {
    master_key: [u8; KEY_SIZE],
    round_keys: [[u8;BLOCK_SIZE]; 10],
    constants: [[u8;BLOCK_SIZE]; 32]
}

impl Keys {
    pub fn new(master_key: [u8; KEY_SIZE]) -> Self {
        let mut keys = Keys { master_key, round_keys: [[0x00; BLOCK_SIZE]; 10],  constants: [[0x00; BLOCK_SIZE]; 32] };
        keys.gen_const();
        keys.gen_round_keys();
        keys
    }

    pub fn get_round_key(&self, round: usize) -> [u8; BLOCK_SIZE] {
        self.round_keys[round - 1]
    }

    fn feistel(&self, left: [u8;BLOCK_SIZE], right: [u8;BLOCK_SIZE], base_iter: usize) -> [[u8;BLOCK_SIZE]; 2] {
        let mut temp_result: [u8; BLOCK_SIZE];
        let mut temp_left = left;
        let mut temp_right = right;
        for i in 0..8{
            temp_result = x_transform(l_transform(&s_transform(x_transform(temp_left,self.constants[base_iter + i] ))),temp_right);
            temp_right = temp_left;
            temp_left = temp_result;
        }
        [temp_left, temp_right]
    }

    fn gen_const(&mut self) {
        for i in 0..32 {
            let mut c: [u8; BLOCK_SIZE] = [ 0x00, 0x00, 0x00, 0x00,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00,  0x00, 0x00 ];
            c[15] = (i + 1) as u8;
            self.constants[i] = l_transform(&c);
        }
    }

    fn gen_round_keys(&mut self) {
        let mut k1: [u8;BLOCK_SIZE] = Default::default();
        let mut k2: [u8;BLOCK_SIZE] = Default::default();

        k1.copy_from_slice(&self.master_key[0..BLOCK_SIZE]);
        k2.copy_from_slice(&self.master_key[BLOCK_SIZE..KEY_SIZE]);

        self.round_keys[0] = k1;
        self.round_keys[1] = k2;

        let constants_start: [usize;4] = [ 0, 8, 16, 24];
        let mut start_counter: usize = 0;
        for i in (2..10).step_by(2) {
            let result = self.feistel(self.round_keys[i-2], self.round_keys[i-1], constants_start[start_counter]);
            self.round_keys[i] = result[0];
            self.round_keys[i+1] = result[1];
            start_counter += 1;
        }

    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_key() {
        let k1: [u8; BLOCK_SIZE] = [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let k2: [u8; BLOCK_SIZE] = [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let k3: [u8; BLOCK_SIZE] = [0xdb, 0x31, 0x48, 0x53, 0x15, 0x69, 0x43, 0x43, 0x22, 0x8d, 0x6a, 0xef, 0x8c, 0xc7, 0x8c, 0x44];
        let k4: [u8; BLOCK_SIZE] = [0x3d, 0x45, 0x53, 0xd8, 0xe9, 0xcf, 0xec, 0x68, 0x15, 0xeb, 0xad, 0xc4, 0x0a, 0x9f, 0xfd, 0x04];
        let k5: [u8; BLOCK_SIZE] = [0x57, 0x64, 0x64, 0x68, 0xc4, 0x4a, 0x5e, 0x28, 0xd3, 0xe5, 0x92, 0x46, 0xf4, 0x29, 0xf1, 0xac];
        let k6: [u8; BLOCK_SIZE] = [0xbd, 0x07, 0x94, 0x35, 0x16, 0x5c, 0x64, 0x32, 0xb5, 0x32, 0xe8, 0x28, 0x34, 0xda, 0x58, 0x1b];
        let k7: [u8; BLOCK_SIZE] = [0x51, 0xe6, 0x40, 0x75, 0x7e, 0x87, 0x45, 0xde, 0x70, 0x57, 0x27, 0x26, 0x5a, 0x00, 0x98, 0xb1];
        let k8: [u8; BLOCK_SIZE] = [0x5a, 0x79, 0x25, 0x01, 0x7b, 0x9f, 0xdd, 0x3e, 0xd7, 0x2a, 0x91, 0xa2, 0x22, 0x86, 0xf9, 0x84];
        let k9: [u8; BLOCK_SIZE] = [0xbb, 0x44, 0xe2, 0x53, 0x78, 0xc7, 0x31, 0x23, 0xa5, 0xf3, 0x2f, 0x73, 0xcd, 0xb6, 0xe5, 0x17];
        let k10: [u8; BLOCK_SIZE] = [0x72, 0xe9, 0xdd, 0x74, 0x16, 0xbc, 0xf4, 0x5b, 0x75, 0x5d, 0xba, 0xa8, 0x8e, 0x4a, 0x40, 0x43];

        let master_key: [u8;KEY_SIZE] = [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

        let keys = Keys::new(master_key);
        
        assert_eq!(k1,keys.get_round_key(1));
        assert_eq!(k2,keys.get_round_key(2));
        assert_eq!(k3,keys.get_round_key(3));
        assert_eq!(k4,keys.get_round_key(4));
        assert_eq!(k5,keys.get_round_key(5));
        assert_eq!(k6,keys.get_round_key(6));
        assert_eq!(k7,keys.get_round_key(7));
        assert_eq!(k8,keys.get_round_key(8));
        assert_eq!(k9,keys.get_round_key(9));
        assert_eq!(k10,keys.get_round_key(10));
    }
}