use crate::fri::*;
use crate::utils::{rand_field_element, parallel_fft, parallel_ifft};
use crate::comm_channel::CommunicationChannel;
use crate::vole_triple::{VoleTriple, PrimalLPNParameterFp61};
use psiri_aes::prg::PRG;
use psiri_aes::prp::FieldPRP;
use psiri_okvs::types::Okvs;
use psiri_okvs::okvs::RbOkvs;
use rand::Rng;
use sha3::{Keccak256, Digest};
use std::time::Instant;
use std::convert::TryInto;
use std::cmp::min;
use lambdaworks_math::traits::{ByteConversion, AsBytes};
use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset;
use lambdaworks_math::fft::cpu::bit_reversing::{reverse_index, in_place_bit_reverse_permute};
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_crypto::merkle_tree::proof::Proof;
use lambdaworks_crypto::fiat_shamir::is_transcript::IsTranscript;
use stark_platinum_prover::transcript::StoneProverTranscript;
use stark_platinum_prover::fri::{FieldElement, Polynomial};
use stark_platinum_prover::config::Commitment;
use rayon::prelude::*;  
use rayon::current_num_threads;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

const NUM_QUERIES: usize = 100;

pub struct OprfSender {
    n: usize,
    vole_sender: VoleTriple,
    b: Vec<FE>,
    K: Vec<FE>,
    delta: FE,
    malicious: bool,
    okvs: RbOkvs,
    w: FE, 
    P_new_merkle_root: [u8; 32],
    Q_merkle_root: [u8; 32],
    X_new_poly: Polynomial<FE>,
    X_new_commit: FriLayer,
    S_new_commit: FriLayer,
    T_new_last_value: FE,   
    T_new_fri_layers: Vec<FriLayer>,
    outputs_byte: Vec<[u8; 32]>,
    fixed_points_num: usize,
    log_fixed_points_num: usize,
    roots_of_unity: Vec<FE>,
    roots_of_unity_inv: Vec<FE>,
    small_roots_of_unity_inv: Vec<FE>,
    transcript: StoneProverTranscript,
}

impl OprfSender {
    pub fn new<IO: CommunicationChannel>(io: &mut IO, n: usize, malicious: bool, param: PrimalLPNParameterFp61) -> Self {
        // Setup delta
        let mut prg = PRG::new(None, 0);
        let mut FE_vec = [FE::zero(); 1];
        prg.random_stark252_elements(&mut FE_vec);
        let delta = FE_vec[0]; 

        // Receive OKVS seed from the receiver
        let r = io.receive_block::<16>();
        let r1 = r[0];
        let r2 = r[1];
        let okvs = RbOkvs::new(n, &r1, &r2);

        let mut vole_triple = VoleTriple::new(0, malicious, io, param);
        vole_triple.setup_sender(io, delta);
        vole_triple.extend_initialization();

        let fixed_points_num = 2 * n;
        let mut log_fixed_points_num = 1;
        while (1 << log_fixed_points_num) < fixed_points_num {
            log_fixed_points_num += 1;
        }
        assert_eq!(fixed_points_num, 1 << log_fixed_points_num, "Number of values should be a power of 2"); 

        let public_input_data = vec![]; // hopefully it's safe
        let transcript = StoneProverTranscript::new(&public_input_data);

        OprfSender {
            n: n,
            vole_sender: vole_triple,
            b: vec![FE::zero(); okvs.columns],
            K: vec![FE::zero(); okvs.columns],
            delta: delta,
            malicious: malicious,
            okvs: okvs,
            w: FE::zero(),
            P_new_merkle_root: [0u8; 32],
            Q_merkle_root: [0u8; 32],
            X_new_poly: Polynomial::new(vec![FE::zero(); 1].as_slice()),
            X_new_commit: FriLayer::new(
                vec![FE::zero(); 1].as_slice(), 
                MerkleTree::build(vec![[FE::zero(); 2]; 1].as_slice())),
            S_new_commit: FriLayer::new(
                vec![FE::zero(); 1].as_slice(), 
                MerkleTree::build(vec![[FE::zero(); 2]; 1].as_slice())),
            T_new_last_value: FE::zero(),
            T_new_fri_layers: vec![],
            outputs_byte: vec![],
            fixed_points_num: fixed_points_num,
            log_fixed_points_num: log_fixed_points_num,
            roots_of_unity: vec![],
            roots_of_unity_inv: vec![],
            small_roots_of_unity_inv: vec![],
            transcript: transcript,
        }
    }

    pub fn commit_X(&mut self, values: &[FE]) {
        let start = Instant::now();
        self.roots_of_unity = get_powers_of_primitive_root_coset(
            (self.log_fixed_points_num + 2) as u64,
            1 << (self.log_fixed_points_num + 2) as usize,
            &FE::one(),
        ).unwrap();
        println!("Time to get roots of unity: {:?}", start.elapsed());

        self.roots_of_unity_inv = self.roots_of_unity.clone();
        self.roots_of_unity_inv[1..].reverse();

        self.small_roots_of_unity_inv: Vec<FE> = (0..self.fixed_points_num).into_par_iter().map(|i| self.roots_of_unity_inv[i*4]).collect();

        // for i in 0..roots_of_unity_inv.len() {
        //     assert_eq!(roots_of_unity_inv[i] * roots_of_unity[i], FE::one(), "wrong inv of roots of unity");
        // }

        assert_eq!(values.len(), self.n, "The number of values of Sender should be n");
        // Low degree extension to later match with output commitment
        let mut X: Vec<FE> = Vec::with_capacity(2*self.n);
        for i in 0..self.n {
            X.push(values[i]);
            X.push(rand_field_element());
        }
        
        // let X_poly = Polynomial::interpolate_fft::<F>(&X).unwrap();
        let X_poly_coeffs = parallel_ifft(&X, &self.small_roots_of_unity_inv, self.log_fixed_points_num, 0);
        let X_poly = Polynomial::new(&X_poly_coeffs);

        // Start committing S
        assert_eq!(X.len(), 1 << self.log_fixed_points_num, "Number of values should be a power of 2"); 

        let mut X_blind_poly = Polynomial::new(vec![FE::zero(); 1].as_slice());
        (X_blind_poly, self.X_new_poly) = get_blind_poly(&X_poly, self.log_fixed_points_num, 1);

        self.X_new_commit = new_fri_layer(&self.X_new_poly, 1, self.log_fixed_points_num, self.log_fixed_points_num+1, &self.roots_of_unity);
    }


    pub fn receive_P_commit<IO: CommunicationChannel>(&mut self, io: &mut IO) {
        // Receive commitment of P_new
        self.P_new_merkle_root = io.receive_block::<32>()[0];
        self.transcript.append_bytes(&self.P_new_merkle_root);
    }

    pub fn send_X_commit<IO: CommunicationChannel>(&mut self, io: &mut IO) {
        self.transcript.append_bytes(&self.X_new_commit.merkle_tree.root);
        io.send_block::<32>(&[self.X_new_commit.merkle_tree.root]);
    }

    pub fn send<IO: CommunicationChannel>(&mut self, io: &mut IO, values: &[FE]) {
        // Creating ws and send H(ws) to the receiver
        let mut prg = PRG::new(None, 0);
        let mut FE_vec = [FE::zero(); 1];
        prg.random_stark252_elements(&mut FE_vec);
        let ws = FE_vec[0];
        let mut hash_buf = FE::zero();
        if self.malicious {
            let hash_seed = [0u8; 32];
            let hash = FieldPRP::new(Some(&hash_seed));
            let mut ws_vec = [ws];
            hash.permute_block(&mut ws_vec, 1);
            hash_buf = ws_vec[0];
            io.send_stark252(&[hash_buf]).expect("Failed to send H(ws) to the receiver");

            self.transcript.append_bytes(&hash_buf.to_bytes_le());
        }

        // Running Vole
        // c = b + a * delta
        let start = Instant::now();
        let mut z = vec![FE::zero(); self.okvs.columns];
        self.vole_sender.extend(io, &mut self.b, &mut z, self.okvs.columns); 
        println!("Time to extend Vole: {:?}", start.elapsed());

        // Get w = ws + wr;
        if self.malicious {
            let wr = io.receive_stark252(1).expect("Failed to receive wr from the receiver")[0];
            self.w = ws + wr;
            io.send_stark252(&[ws]).expect("Failed to send ws to the receiver");
            self.transcript.append_bytes(&wr.to_bytes_le());
            self.transcript.append_bytes(&self.w.to_bytes_le());
        }

        let start = Instant::now();
        // Receive A = P + a from the receiver and get K = b + A * delta
        let A = io.receive_stark252(self.okvs.columns).expect("Failed to receive A from the receiver");
        let mut K = vec![FE::zero(); self.okvs.columns];
        for i in 0..self.okvs.columns {
            self.K[i] = self.b[i] + A[i] * self.delta;
        }
        println!("Time to receive A and compute K: {:?}", start.elapsed());

        let start = Instant::now();
        println!("Start preparing output consistency");
        self.prepare_output_consistency(&values);
        println!("Time to prepare output consistency: {:?}", start.elapsed());

        let start = Instant::now();
        self.receive_vole_consistency(io, &A);
        println!("Time to receive VOLE consistency: {:?}", start.elapsed());

        let start = Instant::now();
        self.send_output_consistency(io);
        println!("Time to send output consistency: {:?}", start.elapsed());
    }

    pub fn prepare_output_consistency(&mut self, values: &[FE]) {
        let start = Instant::now();

        let mut o = self.okvs.decode(&self.K, values);

        println!("End of decoding: {:?}", start.elapsed());

        let input_seed = [1u8; 32];
        let input_hasher = FieldPRP::new(Some(&input_seed));
        let mut hashes = vec![FE::zero(); self.n];
        hashes.copy_from_slice(values);
        input_hasher.permute_block(&mut hashes, self.n);
        o.par_iter_mut().enumerate().for_each(|(i, oi)| {
            *oi = *oi - self.delta * hashes[i] + self.w;
        });
        // for i in 0..o.len() {
        //     o[i] = o[i] - self.delta * hashes[i] + self.w;
        // }

        println!("End of hashing: {:?}", start.elapsed());

        let mut S = Vec::with_capacity(self.fixed_points_num);
        for i in 0..self.n {
            S.push(values[i]);
            S.push(o[i]);   
        }

        // let S_poly = Polynomial::interpolate_fft::<F>(&S).unwrap();
        let S_poly_coeffs = parallel_ifft(&S, &self.small_roots_of_unity_inv, self.log_fixed_points_num, 0);
        let S_poly = Polynomial::new(&S_poly_coeffs);
        assert_eq!(S_poly.coefficients.len(), 1 << self.log_fixed_points_num, "Number of values should be a power of 2");

        println!("End of interpolation: {:?}", start.elapsed());

        // Do we need to blind S_poly?
        let (S_blind_poly, S_new_poly) = get_blind_poly(&S_poly, self.log_fixed_points_num, 1);

        println!("End of blinding: {:?}", start.elapsed());

        // Commit S_new first
        self.S_new_commit = new_fri_layer(&S_new_poly, 1, self.log_fixed_points_num, self.log_fixed_points_num + 1, &self.roots_of_unity);

        println!("End of FRI commitment: {:?}", start.elapsed());

        // We need to prove that S_new_poly and X_new_poly share the same evaluation on n roots of unity
        // In other words, we need to prove that S_new_poly - X_new_poly = (x^n-1) * T(x), where T(x) has degree < 3n
        // Which means that for any t, S_new_poly - X_new_poly = (x^n + t) * T(x) has degree < 4n

        let mut T1_poly_coefficients = vec![FE::zero(); self.fixed_points_num*2];
        for i in 0..min(S_new_poly.coefficients.len(), self.X_new_poly.coefficients.len()) {
            T1_poly_coefficients[i] = S_new_poly.coefficients[i] - self.X_new_poly.coefficients[i];   
        }
        if S_new_poly.coefficients.len() < self.X_new_poly.coefficients.len() {
            for i in S_new_poly.coefficients.len()..self.X_new_poly.coefficients.len() {
                T1_poly_coefficients[i] = -self.X_new_poly.coefficients[i];   
            }
        } else {
            for i in self.X_new_poly.coefficients.len()..S_new_poly.coefficients.len() {
                T1_poly_coefficients[i] = S_new_poly.coefficients[i];   
            }
        }


        println!("End of manual subtraction: {:?}", start.elapsed());

        // Divide T1_poly by (x^n-1) to get T_poly
        let mut T_poly_coefficients = vec![FE::zero(); 3*self.n];
        for i in 0..self.n {
            T_poly_coefficients[i] = -T1_poly_coefficients[i];   
        }
        for i in self.n..3*self.n {
            T_poly_coefficients[i] = T_poly_coefficients[i-self.n] - T1_poly_coefficients[i];   
        }
        println!("End of manual division: {:?}", start.elapsed());

        let T_poly = Polynomial::new(T_poly_coefficients.as_slice());

        println!("End of division: {:?}", start.elapsed());

        // Just Fiat-Shamir it
        let mut hasher = Keccak256::new();
        hasher.update(self.S_new_commit.merkle_tree.root);
        let mut t_bytes = [0u8; 32];
        t_bytes.copy_from_slice(&hasher.finalize());
        let t = FE::from_bytes_le(&t_bytes).unwrap();

        // Compute T_new_poly = (x^n + t) * T_poly
        let mut T_new_poly_coefficients = vec![FE::zero(); 4*self.n];
        T_new_poly_coefficients[self.n..].copy_from_slice(&T_poly_coefficients);
        T_new_poly_coefficients[..3*self.n].par_iter_mut().enumerate().for_each(|(i, T_new_i)| {
            *T_new_i += t * T_poly_coefficients[i];
        });
        // for i in 0..3*self.n {
        //     T_new_poly_coefficients[i] += t * T_poly_coefficients[i];
        // }

        let T_new_poly = Polynomial::new(T_new_poly_coefficients.as_slice());
        // Prove that T_new_poly has degree < 4n

        println!("End of T_new creation: {:?}", start.elapsed());

        (self.T_new_last_value, self.T_new_fri_layers) = commit_poly(
            &T_new_poly, 
            self.log_fixed_points_num+1, 
            1, 
            self.log_fixed_points_num, 
            &self.roots_of_unity,
            &self.roots_of_unity_inv);

        println!("End of T_new commitment: {:?}", start.elapsed());

        // Almost done. Only need to show that these hashes are the same as the ones in the commitment

        let num_threads = current_num_threads();
        let chunk_size = self.n / num_threads;

        self.outputs_byte = vec![[0u8; 32]; self.n];
        self.outputs_byte.par_iter_mut().enumerate().for_each(|(i, outputs_i)| {
            let mut hasher = Keccak256::new();
            hasher.update(values[i].as_bytes());
            hasher.update(o[i].as_bytes());
            outputs_i.copy_from_slice(&hasher.finalize());
        });

        println!("End of output hashing: {:?}", start.elapsed());
    }

    pub fn send_output_consistency<IO: CommunicationChannel>(&mut self, io: &mut IO) {
        let start = Instant::now();
        io.send_block::<32>(&[self.S_new_commit.merkle_tree.root]);
        self.transcript.append_bytes(&self.S_new_commit.merkle_tree.root);

        let T_new_merkle_roots: Vec<[u8; 32]> = self.T_new_fri_layers
            .iter()
            .map(|fri_layer| fri_layer.merkle_tree.root)
            .collect(); 
        io.send_stark252(&[self.T_new_last_value]).expect("Cannot send last value of T");
        io.send_block::<32>(&T_new_merkle_roots);

        self.transcript.append_bytes(&self.T_new_last_value.to_bytes_le());
        self.transcript.append_bytes(&T_new_merkle_roots[0]);

        let iotas: Vec<usize> = (0..NUM_QUERIES).map(|_| {
            let iota_bytes = self.transcript.sample(8);
            let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap()) % ((self.fixed_points_num*2) as u64) + (self.fixed_points_num*2) as u64;
            self.transcript.append_bytes(&iota_bytes);
            iota as usize
        }).collect();

        let T_new_evaluations: Vec<FE> = iotas
            .iter()
            .map(|&iota| self.T_new_fri_layers[0].evaluation[iota])
            .collect();

        io.send_stark252(&T_new_evaluations).expect("Cannot send evaluations of T_new");
        let T_new_decommit = query_phase(&self.T_new_fri_layers, &iotas);
        send_decommit(io, &T_new_decommit);

        // Now prove that S_new and X_new are consistent
        let iotas_consistency: Vec<usize> = (0..NUM_QUERIES).map(|_| {
            let iota_bytes = self.transcript.sample(8);
            let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap()) % ((self.fixed_points_num*2) as u64) + (self.fixed_points_num*2) as u64;
            self.transcript.append_bytes(&iota_bytes);
            iota as usize
        }).collect();

        // Send evaluations and merkle paths for S_new
        let S_new_evaluations: Vec<FE> = iotas_consistency
            .par_iter()
            .map(|&iota| self.S_new_commit.evaluation[iota])
            .collect();
        io.send_stark252(&S_new_evaluations).expect("Cannot send evaluations of S_new");
        let S_new_evaluations_sym: Vec<FE> = iotas_consistency
            .par_iter()
            .map(|&iota| self.S_new_commit.evaluation[iota^1])
            .collect();
        io.send_stark252(&S_new_evaluations_sym).expect("Cannot send sym evaluations of S_new");
        let S_new_paths: Vec<Proof<Commitment>> = iotas_consistency
            .par_iter()
            .map(|&iota| self.S_new_commit.merkle_tree.get_proof_by_pos(iota>>1))
            .collect();
        send_merkle_path(io, &S_new_paths);

        // Send evaluations and merkle paths for X_new
        let X_new_evaluations: Vec<FE> = iotas_consistency
            .par_iter()
            .map(|&iota| self.X_new_commit.evaluation[iota])
            .collect();
        io.send_stark252(&X_new_evaluations).expect("Cannot send evaluations of X_new");
        let X_new_evaluations_sym: Vec<FE> = iotas_consistency
            .par_iter()
            .map(|&iota| self.X_new_commit.evaluation[iota^1])
            .collect();
        io.send_stark252(&X_new_evaluations_sym).expect("Cannot send sym evaluations of X_new");
        let X_new_paths: Vec<Proof<Commitment>> = iotas_consistency
            .par_iter()
            .map(|&iota| self.X_new_commit.merkle_tree.get_proof_by_pos(iota>>1))
            .collect();
        send_merkle_path(io, &X_new_paths);


        // Send evaluation and merkle paths for T_new
        let T_new_evaluations: Vec<FE> = iotas_consistency
            .par_iter()
            .map(|&iota| self.T_new_fri_layers[0].evaluation[iota])
            .collect();
        io.send_stark252(&T_new_evaluations).expect("Cannot send evaluations of T_new");
        let T_new_evaluations_sym: Vec<FE> = iotas_consistency
            .par_iter()
            .map(|&iota| self.T_new_fri_layers[0].evaluation[iota^1])
            .collect();
        io.send_stark252(&T_new_evaluations_sym).expect("Cannot send sym evaluations of T_new");

        let T_new_paths: Vec<Proof<Commitment>> = iotas_consistency
            .par_iter()
            .map(|&iota| self.T_new_fri_layers[0].merkle_tree.get_proof_by_pos(iota>>1))
            .collect();
        send_merkle_path(io, &T_new_paths);


        // Send the outputs and the verify path
        // Takes 1 second to send a million members
        io.send_block::<32>(&self.outputs_byte);

        // Try to get the path from outputs_byte to merkle_root of S_new
        let outputs_byte_path = self.S_new_commit.merkle_tree.get_proof_by_pos(0).merkle_path;

        let mut verify_path = vec![[0u8; 32]; 2];
        verify_path.copy_from_slice(&outputs_byte_path[self.log_fixed_points_num-1..]);

        io.send_block::<32>(&verify_path);
    }

    pub fn receive_vole_consistency<IO: CommunicationChannel>(&mut self, io: &mut IO, A: &[FE]) {
        // Run FRI degree test on Q
        // Receive commitment of Q
        let Q_last_value = io.receive_stark252(1).expect("Failed to receive Q last value")[0];
        let Q_merkle_roots = io.receive_block::<32>();
        let Q_merkle_root = Q_merkle_roots[0];

        self.transcript.append_bytes(&Q_last_value.to_bytes_le());
        self.transcript.append_bytes(&Q_merkle_root);

        let iotas: Vec<usize> = (0..NUM_QUERIES).map(|_| {
            let iota_bytes = self.transcript.sample(8);
            let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap()) % ((self.fixed_points_num*2) as u64) + (self.fixed_points_num*2) as u64;
            self.transcript.append_bytes(&iota_bytes);
            iota as usize
        }).collect();
        // Receive evaluations
        let Q_evaluations = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations of Q");
        // Receive back the decommitments of P
        let Q_decommit = receive_decommit(io);
        // Verify decommitment
        
        iotas.par_iter().enumerate().for_each(|(i, &iota)| {
            let result = verify_fri_query(
                Q_last_value,
                &Q_merkle_roots,
                &Q_decommit[i],
                iota,
                Q_evaluations[i],
                Q_decommit[i].layers_evaluations_sym[0],
                &self.roots_of_unity,
            );
            if result == false {
                panic!("Receiver lied about Q");
            }
        });
        println!("Q passed the degree test!");

        let iotas_consistency: Vec<usize> = (0..NUM_QUERIES).map(|_| {
            let iota_bytes = self.transcript.sample(8);
            let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap()) % ((self.fixed_points_num*2) as u64) + (self.fixed_points_num*2) as u64;
            self.transcript.append_bytes(&iota_bytes);
            iota as usize
        }).collect();
        let iota_consistency_roots_of_unity = iotas_consistency
            .par_iter()
            .map(|&iota| self.roots_of_unity[reverse_index(iota, self.roots_of_unity.len() as u64)])
            .collect::<Vec<FE>>();


        // Compute evaluations on A and b while receiver is preparing degree check on Q
        let start = Instant::now();

        let b_poly_coeffs = parallel_ifft(&self.b, &self.small_roots_of_unity_inv, self.log_fixed_points_num, 0);
        let b_poly = Polynomial::new(&b_poly_coeffs);
        let A_poly_coeffs = parallel_ifft(&A, &self.small_roots_of_unity_inv, self.log_fixed_points_num, 0);
        let A_poly = Polynomial::new(&A_poly_coeffs);



        println!("Time to interpolate b and A: {:?}", start.elapsed());

        let mut b_evaluations = vec![FE::zero(); NUM_QUERIES];
        let mut A_evaluations = vec![FE::zero(); NUM_QUERIES];

        A_evaluations.par_iter_mut().zip(b_evaluations.par_iter_mut()).enumerate().for_each(|(i, (Ai, bi))| {
            *Ai = A_poly.evaluate(&iota_consistency_roots_of_unity[i]);
            *bi = b_poly.evaluate(&iota_consistency_roots_of_unity[i]);
        });

        // Check consistency of VOLE
        // Receive evaluations on roots of unity of c
        let c_evaluations = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations of c");

        // Receive evaluations on roots of unity of P_new and check with commitment
        let P_new_evaluations = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations of P_new");
        let P_new_evaluations_sym = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations sym of P_new");
        let P_new_paths = receive_merkle_path(io);
        // Verify P_new_evaluations
        iotas_consistency
            .par_iter()
            .enumerate()
            .zip(P_new_evaluations.par_iter())
            .zip(P_new_evaluations_sym.par_iter())
            .zip(P_new_paths.par_iter())
            .for_each(|((((i, &iota), evaluation), evaluation_sym), path)| {
                let openings_ok = verify_fri_layer_openings(
                    &self.P_new_merkle_root,
                    path,
                    evaluation,
                    evaluation_sym,
                    iota
                );
                if !openings_ok {
                    panic!("Lied about P_new at iota = {}", iota);
                }
            });

        // Receive evaluations on roots of unity of Q and check with commitment
        let Q_evaluations = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations of Q");
        let Q_evaluations_sym = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations sym of Q");
        let Q_paths = receive_merkle_path(io);
        // Verify Q_evaluations
        iotas_consistency
            .par_iter()
            .enumerate()
            .zip(Q_evaluations.par_iter())
            .zip(Q_evaluations_sym.par_iter())
            .zip(Q_paths.par_iter())
            .for_each(|((((i, &iota), evaluation), evaluation_sym), path) | {
                let openings_ok = verify_fri_layer_openings(
                    &Q_merkle_root,
                    path,
                    evaluation,
                    evaluation_sym,
                    iota
                );
                if !openings_ok {
                    panic!("Lied about Q at iota = {}", iota);
                }
            });

        // Now we can start checking VOLE, with the following equation:
        // (c(x) - b(x)) * delta_inv - (A(x) - P_new(x)) = a(x) - (a(x) - Q(x) * (x^2n - 1)) = Q(x) * (x^2n - 1)
        let delta_inv = self.delta.inv().expect("Delta is zero");


        let delta_inv = self.delta.inv().expect("Delta is zero");

        for i in 0..NUM_QUERIES {
            if (c_evaluations[i] - b_evaluations[i]) * delta_inv
                != (A_evaluations[i] - P_new_evaluations[i]) + (iota_consistency_roots_of_unity[i].pow(2*self.n) - FE::one()) * Q_evaluations[i] {
                panic!("Wolverine check failed!");
            }
        }

        println!("VOLE passed the consistency check!");
    }

}
