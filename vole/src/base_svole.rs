use crate::cope::Cope;
use psiri_aes::prg::PRG;
use crate::comm_channel::CommunicationChannel;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::field::traits::IsPrimeField;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct BaseSvole {
    party: u8,              // 0 for sender, 1 for receiver
    cope: Cope,     // COPE instance
    delta: Option<FE>,      // Delta for the sender
}

impl BaseSvole {
    /// Sender's constructor
    pub fn new_sender<IO: CommunicationChannel>(io: &mut IO, delta: FE) -> Self {
        let mut cope = Cope::new(0, F::field_bit_size());
        cope.initialize_sender(io, delta.clone());
        Self {
            party: 0,
            cope,
            delta: Some(delta),
        }
    }

    /// Receiver's constructor
    pub fn new_receiver<IO: CommunicationChannel>(io: &mut IO) -> Self {
        let mut cope = Cope::new(1, F::field_bit_size());
        cope.initialize_receiver(io);
        Self {
            party: 1,
            cope,
            delta: None,
        }
    }

    /// Sender: Triple generation
    pub fn triple_gen_send<IO: CommunicationChannel>(&mut self, io: &mut IO, share: &mut [FE], size: usize) {
        // Generate share_recv = share_send + delta * u_recv
        self.cope.extend_sender_batch(io, share, size);
        let mut b = vec![FE::zero(); 1];
        self.cope.extend_sender_batch(io, &mut b, 1);
        self.sender_check(io, share, b[0], size);
    }

    /// Receiver: Triple generation
    pub fn triple_gen_recv<IO: CommunicationChannel>(&mut self, io: &mut IO, share: &mut [FE], u: &mut [FE], size: usize) {
        // Generate share_recv = share_send + delta * u_recv
        let mut prg = PRG::new(None, 0);
        let mut x = vec![FE::zero(); 1];
        prg.random_stark252_elements(&mut x);

        prg.random_stark252_elements(u);

        self.cope.extend_receiver_batch(io, share, u, size);

        let mut c = vec![FE::zero(); 1];
        self.cope.extend_receiver_batch(io, &mut c, &x, 1);

        self.receiver_check(io, share, u, c[0], x[0], size);
    }

    /// Sender: Consistency check
    fn sender_check<IO: CommunicationChannel>(&mut self, io: &mut IO, share: &[FE], b: FE, size: usize) {
        // Generate check seed and send it to Receiver
        let mut seed = vec![[0u8; 16]; 1];
        let mut seed_prg = PRG::new(None, 0);
        seed_prg.random_block(&mut seed);
        io.send_block::<16>(&seed);

        let chi = self.generate_hash_coeff(seed[0], size);

        let y = self.vector_inner_product_mod(share, &chi) + b;
        let mut xz = io.receive_stark252(2).expect("Failed to receive xz");

        xz[1] = xz[1] * self.delta.unwrap();
        let y_check = y + xz[1];
        if y_check != xz[0] {
            panic!("Base sVOLE check failed!");
        } else {
            println!("Base sVOLE generated successfully!");
        }
    }

    /// Receiver: Consistency check
    fn receiver_check<IO: CommunicationChannel>(&mut self, io: &mut IO, share: &[FE], x: &[FE], c: FE, a: FE, size: usize) {
        let seed = io.receive_block::<16>()[0];

        let chi = self.generate_hash_coeff(seed, size);

        let xz_0 = self.vector_inner_product_mod(share, &chi) + c;
        let xz_1 = self.vector_inner_product_mod(x, &chi) + a;

        io.send_stark252(&[xz_0, xz_1]).expect("Failed to send xz");
    }

    /// Generate hash coefficients based on a seed
    fn generate_hash_coeff(&self, seed: [u8; 16], size: usize) -> Vec<FE> {
        let mut coeffs = vec![FE::zero(); size];
        let mut prg = PRG::new(Some(&seed), 0);
        prg.random_stark252_elements(&mut coeffs);
        coeffs
    }

    /// Compute modular inner product
    fn vector_inner_product_mod(&self, vec1: &[FE], vec2: &[FE]) -> FE {
        vec1.iter().zip(vec2).fold(FE::zero(), |acc, (v1, v2)| acc + (*v1 * *v2))
    }
}
