pub fn ripemd160(input: &[u8]) -> Vec<u8> {
    // Valeurs d'initialisation (état sur 5 mots 32 bits)
    let mut state = [
        0x67452301u32,
        0xefcdab89u32,
        0x98badcfeu32,
        0x10325476u32,
        0xc3d2e1f0u32,
    ];

    // Copie de l'input pour le padding
    let mut data = input.to_vec();
    let bit_len = (data.len() as u64) * 8;

    // Ajout du bit 1 (0x80)
    data.push(0x80);
    // Compléter avec des zéros jusqu'à atteindre 56 octets modulo 64
    while data.len() % 64 != 56 {
        data.push(0);
    }
    // Ajout de la longueur en bits (little-endian, 8 octets)
    data.extend(&bit_len.to_le_bytes());

    // Constantes et tableaux utilisés dans l'algorithme
    const R: [usize; 80] = [
         0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
         7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
         3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
         1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
         4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13,
    ];
    const S: [u32; 80] = [
        11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
         7,  6,  8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
        11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
         9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6,
    ];

    const R_PRIME: [usize; 80] = [
         5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
         6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
         8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11,
    ];
    const S_PRIME: [u32; 80] = [
         8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
         9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
         9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
         8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11,
    ];

    const K: [u32; 5] = [
        0x00000000,
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xA953FD4E,
    ];
    const K_PRIME: [u32; 5] = [
        0x50A28BE6,
        0x5C4DD124,
        0x6D703EF3,
        0x7A6D76E9,
        0x00000000,
    ];

    // Traitement de chaque bloc de 64 octets
    for block in data.chunks(64) {
        // Décodage du bloc en 16 mots 32 bits (little-endian)
        let mut x = [0u32; 16];
        for i in 0..16 {
            let j = i * 4;
            x[i] = u32::from_le_bytes([block[j], block[j + 1], block[j + 2], block[j + 3]]);
        }

        // Initialisation des registres pour ce bloc
        let mut a  = state[0];
        let mut b  = state[1];
        let mut c  = state[2];
        let mut d  = state[3];
        let mut e  = state[4];

        let mut a_prime  = state[0];
        let mut b_prime  = state[1];
        let mut c_prime  = state[2];
        let mut d_prime  = state[3];
        let mut e_prime  = state[4];

        // Fonctions de ronde
        let f = |j: usize, x: u32, y: u32, z: u32| -> u32 {
            match j / 16 {
                0 => x ^ y ^ z,
                1 => (x & y) | (!x & z),
                2 => (x | !y) ^ z,
                3 => (x & z) | (y & !z),
                4 => x ^ (y | !z),
                _ => unreachable!(),
            }
        };
        let f_prime = |j: usize, x: u32, y: u32, z: u32| -> u32 {
            match j / 16 {
                0 => x ^ (y | !z),
                1 => (x & z) | (y & !z),
                2 => (x | !y) ^ z,
                3 => (x & y) | (!x & z),
                4 => x ^ y ^ z,
                _ => unreachable!(),
            }
        };

        // 80 tours de transformation parallèles
        for j in 0..80 {
            let temp = a
                .wrapping_add(f(j, b, c, d))
                .wrapping_add(x[R[j]])
                .wrapping_add(K[j / 16])
                .rotate_left(S[j])
                .wrapping_add(e);
            a = e;
            e = d;
            d = c.rotate_left(10);
            c = b;
            b = temp;

            let temp_prime = a_prime
                .wrapping_add(f_prime(j, b_prime, c_prime, d_prime))
                .wrapping_add(x[R_PRIME[j]])
                .wrapping_add(K_PRIME[j / 16])
                .rotate_left(S_PRIME[j])
                .wrapping_add(e_prime);
            a_prime = e_prime;
            e_prime = d_prime;
            d_prime = c_prime.rotate_left(10);
            c_prime = b_prime;
            b_prime = temp_prime;
        }

        // Combinaison des deux lignes
        let t = state[1]
            .wrapping_add(c)
            .wrapping_add(d_prime);
        state[1] = state[2]
            .wrapping_add(d)
            .wrapping_add(e_prime);
        state[2] = state[3]
            .wrapping_add(e)
            .wrapping_add(a_prime);
        state[3] = state[4]
            .wrapping_add(a)
            .wrapping_add(b_prime);
        state[4] = state[0]
            .wrapping_add(b)
            .wrapping_add(c_prime);
        state[0] = t;
    }

    // Conversion de l'état final en vecteur de 20 octets (160 bits)
    let mut digest = Vec::with_capacity(20);
    for &word in &state {
        digest.extend_from_slice(&word.to_le_bytes());
    }
    digest
}