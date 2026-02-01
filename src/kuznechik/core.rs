use crate::kuznechik::block::{ Block};
use crate::kuznechik::keys::{ Keys};
use crate::kuznechik::operations::{KEY_SIZE, BLOCK_SIZE};
use crate::kuznechik::kdf::kdf_gostr3411_2012_256;

struct Kuznechik {
    keys: Keys
}

impl Kuznechik {

    pub fn new(key: [u8; KEY_SIZE]) -> Self {
        Kuznechik {
            keys: Keys::new(key)
        }
    }

    pub fn new_from_kdf(kin: &[u8], label: &[u8], seed: &[u8]) -> Self {
        let key = kdf_gostr3411_2012_256(kin, label, seed);
        Kuznechik::new(key)
    }

    pub fn encrypt_block(&self, block: &mut Block) -> [u8; BLOCK_SIZE] {
        // 9 раундов с преобразованиями X -> S -> L
        for round in 1..=9 {
            block.x(self.keys.get_round_key(round));
            block.s();
            block.l();
        }

        // 10-й раунд (только X-преобразование)
        block.x(self.keys.get_round_key(10));
        block.get_block()
    }

    pub fn decrypt_block(&self, block: &mut Block) -> [u8; BLOCK_SIZE] {

        // 10-й раунд в обратном порядке (только X)
        block.x(self.keys.get_round_key(10));

        // 9 раундов в обратном порядке: L⁻¹ -> S⁻¹ -> X
        for round in (1..=9).rev() {
            block.l_inv();
            block.s_inv();
            block.x(self.keys.get_round_key(round));
        }

        block.get_block()
    }

}



#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypt_block_test() {
        let kuznechik = Kuznechik::new( [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let mut plaintext = Block::new([ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 ]);
        let ciphertext = [0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd];
        assert_eq!(kuznechik.encrypt_block(&mut plaintext), ciphertext)
    }

    #[test]
    fn decrypt_block_test() {
        let kuznechik = Kuznechik::new( [0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
        let plaintext = [ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88 ];
        let mut ciphertext = Block::new([0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30, 0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd]);
        assert_eq!(kuznechik.decrypt_block(&mut ciphertext), plaintext)
    }
}