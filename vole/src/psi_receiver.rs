use crate::fri::*;
use crate::comm_channel::CommunicationChannel;  
use crate::vole_triple::{VoleTriple, PrimalLPNParameterFp61};
use crate::utils::parallel_fft;
use psiri_aes::prg::PRG;
use psiri_aes::prp::FieldPRP;
use psiri_okvs::types::{Okvs, Pair};
use psiri_okvs::okvs::RbOkvs;
use rand::Rng;
use sha3::{Digest, Keccak256};
use std::convert::TryInto;
use std::time::Instant;
use std::collections::HashMap;
use lambdaworks_math::traits::{ByteConversion, AsBytes};
use lambdaworks_math::fft::cpu::bit_reversing::{reverse_index, in_place_bit_reverse_permute};
use lambdaworks_math::fft::cpu::roots_of_unity::get_powers_of_primitive_root_coset;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_crypto::merkle_tree::merkle::MerkleTree;
use lambdaworks_crypto::merkle_tree::proof::Proof;
use lambdaworks_crypto::fiat_shamir::is_transcript::IsTranscript;
use stark_platinum_prover::config::{Commitment, BatchedMerkleTreeBackend};
use stark_platinum_prover::fri::{FieldElement, Polynomial};
use stark_platinum_prover::transcript::StoneProverTranscript;
use rayon::prelude::*;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;
pub type MT = MerkleTree<BatchedMerkleTreeBackend<F>>; // MerkleTree

const NUM_QUERIES: usize = 100;

pub struct OprfReceiver {
    n: usize,
    vole_receiver: VoleTriple,
    malicious: bool,
    okvs: RbOkvs,
    P: Vec<FE>,
    Q_poly: Polynomial<FE>,
    Q_last_value: FE,
    Q_fri_layers: Vec<FriLayer>,
    P_new_poly: Polynomial<FE>,
    P_new_commit: FriLayer,
    X_new_merkle_root: [u8; 32],
    fixed_points_num: usize,
    log_fixed_points_num: usize,
    roots_of_unity: Vec<FE>,
    roots_of_unity_inv: Vec<FE>,
    transcript: StoneProverTranscript,
}

impl OprfReceiver {
    pub fn new<IO: CommunicationChannel>(io: &mut IO, n: usize, malicious: bool, param: PrimalLPNParameterFp61) -> Self {
        // Setup OKVS seed
        let mut prg = PRG::new(None, 0);
        let mut r = [[0u8; 16]; 2];
        prg.random_block(&mut r);
        let r1 = r[0];
        let r2 = r[1];
        let okvs = RbOkvs::new(n, &r1, &r2);
        io.send_block::<16>(&r);

        let fixed_points_num = 2 * n;
        let mut log_fixed_points_num = 1;
        while (1 << log_fixed_points_num) < fixed_points_num {
            log_fixed_points_num += 1;
        }
        assert_eq!(fixed_points_num, 1 << log_fixed_points_num, "Number of values should be a power of 2"); 

        let roots_of_unity = get_powers_of_primitive_root_coset(
            (log_fixed_points_num + 2) as u64,
            1 << (log_fixed_points_num + 2) as usize,
            &FE::one(),
        )
        .unwrap();
        let mut roots_of_unity_inv = roots_of_unity.clone();
        roots_of_unity_inv[1..].reverse();

        let mut vole_triple = VoleTriple::new(1, malicious, io, param);
        vole_triple.setup_receiver(io);
        vole_triple.extend_initialization();

        let public_input_data = vec![]; // hopefully it's safe
        let transcript = StoneProverTranscript::new(&public_input_data);
        
        OprfReceiver {
            n: n,
            vole_receiver: vole_triple,
            malicious,
            okvs: okvs,
            P: vec![FE::zero(); 1],
            Q_poly: Polynomial::new(vec![FE::zero(); 1].as_slice()),
            Q_last_value: FE::zero(),
            Q_fri_layers: vec![],
            P_new_poly: Polynomial::new(vec![FE::zero(); 1].as_slice()),
            P_new_commit: FriLayer::new(
                vec![FE::zero(); 1].as_slice(), 
                MT::build(vec![vec![FE::zero(); 2]; 1].as_slice()).unwrap()),
            X_new_merkle_root: [0u8; 32],
            fixed_points_num: 2 * n,
            log_fixed_points_num: log_fixed_points_num,
            roots_of_unity: roots_of_unity,
            roots_of_unity_inv: roots_of_unity_inv,
            transcript: transcript,
        }
    }

    pub fn commit_P(&mut self, values: &[FE]) {
        assert_eq!(values.len(), self.n, "Number of values received does not match the expected number of values");

        // First hash all inputs
        // Takes 15ms for 1<<16 inputs
        let input_seed = [1u8; 32];
        let input_hasher = FieldPRP::new(Some(&input_seed));
        let mut hashes = vec![FE::zero(); self.n];
        hashes.copy_from_slice(values);
        input_hasher.permute_block(&mut hashes, self.n);

        // Encode input using OKVS
        // Takes 680ms for 1<<16 inputs
        let input_kv = values.iter().zip(hashes.iter())
            .map(|(input, hash)| (*input, *hash))
            .collect::<Vec<Pair<FE, FE>>>();
        self.P = self.okvs.encode(&input_kv).expect("Failed to encode using OKVS");

        // Interpolate P
        // Takes 50ms for 1<<16 inputs
        let P_poly = Polynomial::interpolate_fft::<F>(&self.P).unwrap();

        // Blind P
        // Takes 30ms for 1<<16 inputs
        (self.Q_poly, self.P_new_poly) = get_blind_poly(&P_poly, self.log_fixed_points_num, 1);

        // Commit P_new
        self.P_new_commit = new_fri_layer(&self.P_new_poly, 1, self.log_fixed_points_num, self.log_fixed_points_num+1, &self.roots_of_unity);

        // Run FRI degree test on Q
        // Q is the only thing we need to run degree test on
    }

    pub fn send_P_commit<IO: CommunicationChannel>(&mut self, io: &mut IO) {
        self.transcript.append_bytes(&self.P_new_commit.merkle_tree.root);
        println!("Current transcript: {:?}", self.transcript.sample(4));
        io.send_block::<32>(&[self.P_new_commit.merkle_tree.root]);
    }

    pub fn receive_X_commit<IO: CommunicationChannel>(&mut self, io: &mut IO) {
        self.X_new_merkle_root = io.receive_block::<32>()[0];
        self.transcript.append_bytes(&self.X_new_merkle_root);
        println!("Current transcript: {:?}", self.transcript.sample(4));
    }

    pub fn receive<IO: CommunicationChannel>(&mut self, io: &mut IO, values: &[FE]) {
        // Receive committed ws from Sender
        let mut hws = FE::zero();
        if self.malicious {
            hws = io.receive_stark252(1).expect("Failed to receive H(ws) from the sender")[0];
            self.transcript.append_bytes(&hws.to_bytes_le());
            println!("Current transcript: {:?}", self.transcript.sample(4));
        }

        // Running Vole
        // c = b + a * delta
        let mut a = vec![FE::zero(); self.fixed_points_num];
        let mut c = vec![FE::zero(); self.fixed_points_num];    

        let start = Instant::now();
        self.vole_receiver.extend(io, &mut c, &mut a, self.fixed_points_num);
        println!("Vole took {} ms for {} elements", start.elapsed().as_millis(), self.fixed_points_num);


        // Generate random coin if malicious
        let start = Instant::now();
        let mut wr = FE::zero();
        let mut ws = FE::zero();
        let mut w = FE::zero();
        if self.malicious {
            let mut prg = PRG::new(None, 0);
            let mut FE_vec = [FE::zero(); 1];
            prg.random_stark252_elements(&mut FE_vec);
            wr = FE_vec[0];
            self.transcript.append_bytes(&wr.to_bytes_le());
            println!("Current transcript: {:?}", self.transcript.sample(4));

            let start = Instant::now();
            io.send_stark252(&[wr]).expect("Failed to send wr to the sender");
            println!("Sending wr takes {} ms?", start.elapsed().as_millis());
            ws = io.receive_stark252(1).expect("Failed to receive ws from the sender")[0];
            let hash_seed = [0u8; 32];
            let hash = FieldPRP::new(Some(&hash_seed));
            let mut ws_vec = [ws];
            hash.permute_block(&mut ws_vec, 1);
            let hws2 = ws_vec[0];
            assert_eq!(hws, hws2, "H(ws) does not match");

            w = ws + wr;
            self.transcript.append_bytes(&w.to_bytes_le());
            println!("Current transcript: {:?}", self.transcript.sample(4));
        }
        
        println!("Sending these small values take {} ms?", start.elapsed().as_millis());

        // Compute A = P + a
        let mut A = vec![FE::zero(); self.fixed_points_num];
        for i in 0..self.fixed_points_num {
            A[i] = self.P[i] + a[i];
        }
        // Send A = P + a to the sender
        io.send_stark252(&A).expect("Failed to send A to the sender");

        println!("Start preparing vole consistency");   
        let start = Instant::now();
        self.prepare_vole_consistency();
        println!("Proving vole consistency took {} ms", start.elapsed().as_millis());
        self.send_vole_consistency(io, &c);

        let mut o = self.okvs.decode(&c, &values);

        for i in 0..o.len() {
            o[i] = o[i] + w;
        }

        let mut receiver_outputs = vec![[0u8; 32]; self.n];
        for i in 0..self.n {
            let mut hasher = Keccak256::new();
            hasher.update(values[i].as_bytes());
            hasher.update(o[i].as_bytes());
            receiver_outputs[i].copy_from_slice(&hasher.finalize());
        }

        let start = Instant::now();
        let sender_outputs = self.receive_output_consistency(io);
        println!("Check sender output consistency took {} ms", start.elapsed().as_millis());

        // Do intersection
        let start = Instant::now();
        let mut sender_outputs_map = HashMap::<[u8; 32], bool>::new();
        for i in 0..self.n {
            sender_outputs_map.insert(sender_outputs[i], true);
        }

        let mut outputs: Vec<FE> = Vec::new();
        for i in 0..self.n {
            if sender_outputs_map.contains_key(&receiver_outputs[i]) {
                outputs.push(values[i]);
            }
        }
        println!("Table look up took {} ms", start.elapsed().as_millis());

        println!("Done intersection!");
    }

    pub fn prepare_vole_consistency(&mut self) {
        // 420ms for 1<<16 inputs
        (self.Q_last_value, self.Q_fri_layers) = commit_poly(
            &self.Q_poly, 
            self.log_fixed_points_num, 
            2, 
            self.log_fixed_points_num,
            &self.roots_of_unity,
            &self.roots_of_unity_inv);
    }

    pub fn send_vole_consistency<IO: CommunicationChannel>(&mut self, io: &mut IO, c: &[FE]) {
        io.send_stark252(&[self.Q_last_value]).expect("Cannot send last value of Q");
        let Q_merkle_roots: Vec<[u8; 32]> = self.Q_fri_layers
            .iter()
            .map(|fri_layer| fri_layer.merkle_tree.root)
            .collect(); 
        io.send_block::<32>(&Q_merkle_roots);

        self.transcript.append_bytes(&self.Q_last_value.to_bytes_le());
        self.transcript.append_bytes(&Q_merkle_roots[0]);  
        println!("Current transcript: {:?}", self.transcript.sample(4));

        // Receives iotas from Sender
        let iotas: Vec<usize> = (0..NUM_QUERIES).map(|_| {
            let iota_bytes = self.transcript.sample(8);
            let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap()) % ((self.fixed_points_num*2) as u64) + (self.fixed_points_num*2) as u64;
            self.transcript.append_bytes(&iota_bytes);
            iota as usize
        }).collect();
        println!("Current transcript: {:?}", self.transcript.sample(4));

        // Open commitments on P_blind
        let Q_evaluations: Vec<FE> = iotas
            .iter()
            .map(|&iota| self.Q_fri_layers[0].evaluation[iota])
            .collect();
        io.send_stark252(&Q_evaluations).expect("Cannot send evaluations of Q");

        let Q_decommit = query_phase(&self.Q_fri_layers, &iotas);
        send_decommit(io, &Q_decommit);

        // Now we want to prove that A(x) = P(x) + a(x)
        // Where a(x) * delta = c(x) - b(x)
        // The commitment we currently have is P_new(x), which is P(x) + P_blind(x) * (x^n-1)
        // Which is equivalent to (c(x) - b(x)) * delta_inv - (A(x) - P_new(x)) = P_blind(x) * (x^n -1)
        // First, low degree test for P_blind(x). P_blind should have the same degree as P
        let iotas_consistency: Vec<usize> = (0..NUM_QUERIES).map(|_| {
            let iota_bytes = self.transcript.sample(8);
            let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap()) % ((self.fixed_points_num*2) as u64) + (self.fixed_points_num*2) as u64;
            self.transcript.append_bytes(&iota_bytes);
            iota as usize
        }).collect();
        println!("Current transcript: {:?}", self.transcript.sample(4));
        let iota_consistency_roots_of_unity: Vec<FE> = iotas_consistency
            .iter()
            .map(|&iota| self.roots_of_unity[reverse_index(iota, self.roots_of_unity.len() as u64)])
            .collect();

        // Compute evaluations on c to test Wolverine
        let c_poly = Polynomial::interpolate_fft::<F>(&c).unwrap();
        let mut c_evaluations = vec![FE::zero(); NUM_QUERIES];
        c_evaluations.par_iter_mut().enumerate().for_each(|(i, ci)| {
            *ci = c_poly.evaluate(&iota_consistency_roots_of_unity[i]);
        });

        // Send evaluations and merkle paths for P_new
        let P_new_evaluations: Vec<FE> = iotas_consistency
            .iter()
            .map(|&iota| self.P_new_commit.evaluation[iota])
            .collect();
        // Adjacent leaves
        let P_new_evaluations_sym: Vec<FE> = iotas_consistency
            .iter()
            .map(|&iota| self.P_new_commit.evaluation[iota^1])
            .collect();
        // Paths on Merkle Tree
        let P_new_paths: Vec<Proof<Commitment>> = iotas_consistency
            .iter()
            .map(|&iota| self.P_new_commit.merkle_tree.get_proof_by_pos(iota>>1).unwrap())
            .collect();

        // Send evaluations and merkle paths for Q
        let Q_evaluations: Vec<FE> = iotas_consistency
            .iter()
            .map(|&iota| self.Q_fri_layers[0].evaluation[iota])
            .collect();
        let Q_evaluations_sym: Vec<FE> = iotas_consistency
            .iter()
            .map(|&iota| self.Q_fri_layers[0].evaluation[iota^1])
            .collect();
        let Q_paths: Vec<Proof<Commitment>> = iotas_consistency
            .iter()
            .map(|&iota| self.Q_fri_layers[0].merkle_tree.get_proof_by_pos(iota>>1).unwrap())
            .collect();

        // Send everything at once 
        io.send_stark252(&c_evaluations).expect("Cannot send evaluations of c");
        io.send_stark252(&P_new_evaluations).expect("Cannot send evaluations of P_new");
        io.send_stark252(&P_new_evaluations_sym).expect("Cannot send sym evaluations of P_new");
        send_merkle_path(io, &P_new_paths);
        io.send_stark252(&Q_evaluations).expect("Cannot send evaluations of Q");
        io.send_stark252(&Q_evaluations_sym).expect("Cannot send sym evaluations of Q");
        send_merkle_path(io, &Q_paths);
    }

    // Returns the sender hashes of PSI
    pub fn receive_output_consistency<IO: CommunicationChannel>(&mut self, io: &mut IO) -> Vec<[u8; 32]> {
        let S_new_merkle_root = io.receive_block::<32>()[0];
        self.transcript.append_bytes(&S_new_merkle_root);
        println!("Current transcript: {:?}", self.transcript.sample(4));

        // Generate random t to create the degree test
        let mut hasher = Keccak256::new();
        hasher.update(S_new_merkle_root);
        let mut t_bytes = [0u8; 32];
        t_bytes.copy_from_slice(&hasher.finalize());
        let t = FE::from_bytes_le(&t_bytes).unwrap();

        // Receive FRI degree test of T_new
        let T_new_last_value = io.receive_stark252(1).expect("Failed to receive last value of T_new")[0];
        let T_new_merkle_roots = io.receive_block::<32>();

        self.transcript.append_bytes(&T_new_last_value.to_bytes_le());
        self.transcript.append_bytes(&T_new_merkle_roots[0]);
        println!("Current transcript: {:?}", self.transcript.sample(4));

        // Generate iotas for the degree test
        let iotas: Vec<usize> = (0..NUM_QUERIES).map(|_| {
            let iota_bytes = self.transcript.sample(8);
            let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap()) % ((self.fixed_points_num*2) as u64) + (self.fixed_points_num*2) as u64;
            self.transcript.append_bytes(&iota_bytes);
            iota as usize
        }).collect();
        println!("Current transcript: {:?}", self.transcript.sample(4));

        let T_new_evaluations = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations of T_new");
        // Receive back the decommitments of T_new
        let T_new_decommit = receive_decommit(io);
        // Verify decommitment
        for (i, &iota) in iotas.iter().enumerate() {
            let result = verify_fri_query(
                T_new_last_value,
                &T_new_merkle_roots,
                &T_new_decommit[i],
                iota,
                T_new_evaluations[i],
                T_new_decommit[i].layers_evaluations_sym[0],
                &self.roots_of_unity,
            );
            if result == false {
                panic!("Receiver lied about T_new");
            }
        }
        println!("T_new passed the degree test!");

        // Now test consistency between X_new and S_new
        let iotas: Vec<usize> = (0..NUM_QUERIES).map(|_| {
            let iota_bytes = self.transcript.sample(8);
            let iota = u64::from_le_bytes(iota_bytes.clone().try_into().unwrap()) % ((self.fixed_points_num*2) as u64) + (self.fixed_points_num*2) as u64;
            self.transcript.append_bytes(&iota_bytes);
            iota as usize
        }).collect();
        println!("Current transcript: {:?}", self.transcript.sample(4));

        // Receive evaluations on roots of unity of S_new and check with commitment
        let S_new_evaluations = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations of S_new");
        let S_new_evaluations_sym = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations sym of S_new");
        let S_new_paths = receive_merkle_path(io);
        // Verify S_new_evaluations
        let verify_S_openings: bool = iotas
        .iter()
        .enumerate()
        .zip(S_new_evaluations.iter())
        .zip(S_new_evaluations_sym.iter())
        .zip(S_new_paths.iter())
        .fold(true, |result, ((((i, &iota), evaluation), evaluation_sym), path) | {
            let openings_ok = verify_fri_layer_openings(
                &S_new_merkle_root,
                path,
                evaluation,
                evaluation_sym,
                iota
            );
            if !openings_ok {
                panic!("Lied about S_new at iota = {}", iota);
            }
            result & openings_ok
        });

        // Receive evaluations on roots of unity of X_new and check with commitment
        let X_new_evaluations = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations of X_new");
        let X_new_evaluations_sym = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations sym of X_new");
        let X_new_paths = receive_merkle_path(io);
        // Verify X_new_evaluations
        let verify_X_openings: bool = iotas
        .iter()
        .enumerate()
        .zip(X_new_evaluations.iter())
        .zip(X_new_evaluations_sym.iter())
        .zip(X_new_paths.iter())
        .fold(true, |result, ((((i, &iota), evaluation), evaluation_sym), path) | {
            let openings_ok = verify_fri_layer_openings(
                &self.X_new_merkle_root,
                path,
                evaluation,
                evaluation_sym,
                iota
            );
            if !openings_ok {
                panic!("Lied about X_new at iota = {}", iota);
            }
            result & openings_ok
        });

        // Receive evaluations on roots of unity of T_new and check with commitment
        let T_new_evaluations = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations of T_new");
        let T_new_evaluations_sym = io.receive_stark252(NUM_QUERIES).expect("Cannot receive evaluations sym of T_new");
        let T_new_paths = receive_merkle_path(io);
        // Verify T_new_evaluations
        let verify_T_openings: bool = iotas
        .iter()
        .enumerate()
        .zip(T_new_evaluations.iter())
        .zip(T_new_evaluations_sym.iter())
        .zip(T_new_paths.iter())
        .fold(true, |result, ((((i, &iota), evaluation), evaluation_sym), path) | {
            let openings_ok = verify_fri_layer_openings(
                &T_new_merkle_roots[0],
                path,
                evaluation,
                evaluation_sym,
                iota
            );
            if !openings_ok {
                panic!("Lied about T_new at iota = {}", iota);
            }
            result & openings_ok
        });

        let evaluation_points: Vec<FE> = iotas
            .iter()
            .map(|&iota| self.roots_of_unity[reverse_index(iota, self.roots_of_unity.len() as u64)])
            .collect();

        // Now check for the following equation
        // (S_new(x) - X_new(x)) * (x^n + t) = (x^n - 1) * T_new(x)
        for i in 0..NUM_QUERIES {
            if (S_new_evaluations[i] - X_new_evaluations[i]) * (evaluation_points[i].pow(self.n) + t)
                != T_new_evaluations[i] * (evaluation_points[i].pow(self.n) - FE::one()) {
                panic!("Equation does not hold at iota = {}", iotas[i]);
            }
        }
        println!("The hash outputs passed the consistency check!");

        // Receive the hashes
        let sender_outputs_byte = io.receive_block::<32>();
        let verify_path = io.receive_block::<32>();
        
        // Check if the hashes are consistent with the merkle root of S_new
        let mut sender_outputs_hash = vec![[0u8; 32]; self.n];
        sender_outputs_hash.copy_from_slice(&sender_outputs_byte);
        let mut current_size = self.n;
        let start = Instant::now();
        for _ in 0..self.log_fixed_points_num - 1 {
            current_size >>= 1;

            let mut new_sender_outputs_hash = vec![[0u8; 32]; current_size];
            new_sender_outputs_hash
                .par_iter_mut()
                .enumerate()
                .for_each(|(j, hash)| {
                    let mut hasher = Keccak256::new();
                    hasher.update(sender_outputs_hash[2 * j]);
                    hasher.update(sender_outputs_hash[2 * j + 1]);
                    hash.copy_from_slice(&hasher.finalize());
                });
            sender_outputs_hash[..current_size].copy_from_slice(&new_sender_outputs_hash);
        }

        println!("Time for hash reconstruction: {:?}", start.elapsed());

        let mut ref_root = sender_outputs_hash[0];
        for i in 0..verify_path.len() {
            let mut hasher = Keccak256::new();
            hasher.update(ref_root);
            hasher.update(verify_path[i]);
            ref_root.copy_from_slice(&hasher.finalize());
        }

        assert_eq!(ref_root, S_new_merkle_root, "The hash outputs do not match the merkle root of S_new");
        println!("The hash outputs are consistent with the merkle root of S_new");

        sender_outputs_byte
    }

}