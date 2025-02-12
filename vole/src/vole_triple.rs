use crate::preot::OTPre;
use crate::comm_channel::CommunicationChannel;
use crate::base_cot::BaseCot;
use crate::lpn::Lpn;
use crate::mpfss_reg::MpfssReg;
use crate::base_svole::BaseSvole;
use lambdaworks_math::field::fields::fft_friendly::stark_252_prime_field::Stark252PrimeField;
use lambdaworks_math::field::element::FieldElement;
use lambdaworks_math::traits::ByteConversion;
use std::time::Instant;

pub type F = Stark252PrimeField;
pub type FE = FieldElement<F>;

pub struct PrimalLPNParameterFp61 {
    n: usize,
    t: usize,
    k: usize,
    log_bin_sz: usize,
    n_pre: usize,
    t_pre: usize,
    k_pre: usize,
    log_bin_sz_pre: usize,
    n_pre0: usize,
    t_pre0: usize,
    k_pre0: usize,
    log_bin_sz_pre0: usize,
}

impl PrimalLPNParameterFp61 {
    // Default constructor
    pub fn new() -> Self {
        Self {
            n: 0,
            t: 0,
            k: 0,
            log_bin_sz: 0,
            n_pre: 0,
            t_pre: 0,
            k_pre: 0,
            log_bin_sz_pre: 0,
            n_pre0: 0,
            t_pre0: 0,
            k_pre0: 0,
            log_bin_sz_pre0: 0,
        }
    }

    // Parameterized constructor
    pub fn with_params(
        n: usize,
        t: usize,
        k: usize,
        log_bin_sz: usize,
        n_pre: usize,
        t_pre: usize,
        k_pre: usize,
        log_bin_sz_pre: usize,
        n_pre0: usize,
        t_pre0: usize,
        k_pre0: usize,
        log_bin_sz_pre0: usize,
    ) -> Self {
        // Ensure parameters are valid
        if n != t * (1 << log_bin_sz)
            || n_pre != t_pre * (1 << log_bin_sz_pre)
            || n_pre < k + t + 1
        {
            panic!("LPN parameter not matched");
        }

        Self {
            n,
            t,
            k,
            log_bin_sz,
            n_pre,
            t_pre,
            k_pre,
            log_bin_sz_pre,
            n_pre0,
            t_pre0,
            k_pre0,
            log_bin_sz_pre0,
        }
    }

    // Compute buffer size
    pub fn buf_sz(&self) -> usize {
        self.n - self.t - self.k - 1
    }
}

// Default instance
pub const FP_DEFAULT: PrimalLPNParameterFp61 = PrimalLPNParameterFp61 {
    n: 10168320,
    t: 4965,
    k: 158000,
    log_bin_sz: 11,
    n_pre: 166400,
    t_pre: 2600,
    k_pre: 5060,
    log_bin_sz_pre: 6,
    n_pre0: 9600,
    t_pre0: 600,
    k_pre0: 1220,
    log_bin_sz_pre0: 4,
};

// Wolverine instance
pub const WOLVERINE_LPN: PrimalLPNParameterFp61 = PrimalLPNParameterFp61 {
    n: 10805248,
    t: 1319,
    k: 589760,
    log_bin_sz: 13,
    n_pre: 642048,
    t_pre: 2508,
    k_pre: 19870,
    log_bin_sz_pre: 8,
    n_pre0: 22400,
    t_pre0: 700,
    k_pre0: 2000,
    log_bin_sz_pre0: 5,
};

// instance
pub const MILLION_LPN: PrimalLPNParameterFp61 = PrimalLPNParameterFp61 {
    n: 675328,
    t: 1319,
    k: 50000,
    log_bin_sz: 9,
    n_pre: 160512,
    t_pre: 2508,
    k_pre: 19870,
    log_bin_sz_pre: 6,
    n_pre0: 22400,
    t_pre0: 700,
    k_pre0: 2000,
    log_bin_sz_pre0: 5,
};

pub const ONE_MILLION_LPN: PrimalLPNParameterFp61 = PrimalLPNParameterFp61 {
    n: 1228800,
    t: 1200,
    k: 70000,
    log_bin_sz: 10,
    n_pre: 160512,
    t_pre: 2508,
    k_pre: 19870,
    log_bin_sz_pre: 6,
    n_pre0: 22400,
    t_pre0: 700,
    k_pre0: 2000,
    log_bin_sz_pre0: 5,
};

pub const TWO_MILLION_LPN: PrimalLPNParameterFp61 = PrimalLPNParameterFp61 {
    n: 2496512,
    t: 1319,
    k: 130000,
    log_bin_sz: 11,
    n_pre: 160512,
    t_pre: 2508,
    k_pre: 19870,
    log_bin_sz_pre: 6,
    n_pre0: 22400,
    t_pre0: 700,
    k_pre0: 2000,
    log_bin_sz_pre0: 5,
};

pub const THREE_MILLION_LPN: PrimalLPNParameterFp61 = PrimalLPNParameterFp61 {
    n: 3686400,
    t: 900,
    k: 250000,
    log_bin_sz: 12,
    n_pre: 307200,
    t_pre: 1200,
    k_pre: 20000,
    log_bin_sz_pre: 8,
    n_pre0: 22400,
    t_pre0: 700,
    k_pre0: 2000,
    log_bin_sz_pre0: 5,
};

pub struct VoleTriple {
    party: usize,
    param: PrimalLPNParameterFp61,
    m: usize,
    ot_used: usize,
    ot_limit: usize,
    is_malicious: bool,
    extend_initialized: bool,
    pre_ot_inplace: bool,

    pre_y: Vec<FE>,
    pre_z: Vec<FE>,
    pre_x: Vec<FE>,
    vole_y: Vec<FE>,
    vole_z: Vec<FE>,
    vole_x: Vec<FE>,

    cot: BaseCot,
    pre_ot: Option<OTPre>,

    delta: FE,
    mpfss: Option<MpfssReg>,
}

impl VoleTriple {
    pub fn new<IO: CommunicationChannel>(party: usize, malicious: bool, io: &mut IO, param: PrimalLPNParameterFp61) -> Self {
        let n_pre = param.n_pre;
        let t_pre = param.t_pre;
        let n = param.n;
        let t = param.t;
        let mut cot = BaseCot::new(party, malicious);
        cot.cot_gen_pre(io, None);

        VoleTriple {
            party: party,
            param: param,
            m: 0,
            ot_used: 0,
            ot_limit: 0,
            is_malicious: malicious,
            extend_initialized: false,
            pre_ot_inplace: false,

            pre_y: vec![FE::zero(); n_pre],
            pre_z: vec![FE::zero(); n_pre],
            pre_x: vec![FE::zero(); t_pre + 1],
            vole_y: vec![FE::zero(); n],
            vole_z: vec![FE::zero(); n],
            vole_x: vec![FE::zero(); t + 1],

            cot: cot,
            pre_ot: None,

            delta: FE::zero(),
            mpfss: None,
        }
    }

    pub fn extend_send<IO: CommunicationChannel>(&mut self, io: &mut IO, y: &mut [FE], mpfss: &mut MpfssReg, pre_ot: &mut OTPre, lpn: &mut Lpn, key: &[FE], t: usize) {
        mpfss.sender_init(self.delta);
        mpfss.mpfss_sender(io, pre_ot, key, y);
        pre_ot.reset();

        // // y is already a regular vector (concat of n/t unit vectors), which corresponses to the noise in LPN
        lpn.compute_send(y, &key[t+1..]);
    }

    pub fn extend_recv<IO: CommunicationChannel>(&mut self, io: &mut IO, y: &mut [FE], z: &mut [FE], mpfss: &mut MpfssReg, pre_ot: &mut OTPre, lpn: &mut Lpn, mac: &[FE], u: &[FE], t: usize) {
        mpfss.receiver_init();
        mpfss.mpfss_receiver(io, pre_ot, mac, u, y, z);
        pre_ot.reset();
        lpn.compute_recv(y, z, &mac[t+1..], &u[t+1..]);
    }

    pub fn setup_sender<IO: CommunicationChannel>(&mut self, io: &mut IO, delta: FE) {
        self.delta = delta;
        io.send_stark252(&[self.delta]).expect("Cannot send test delta"); //debug only

        let seed_pre0 = [0u8; 16];
        // let seed_field_pre0 = [[0u8; 16]; 4];
        let mut seed_field_pre0 = [0u8; 32];
        seed_field_pre0[0] = 1;
        let mut lpn_pre0 = Lpn::new(self.param.k_pre0, self.param.n_pre0, &seed_pre0, &seed_field_pre0);
        let mut mpfss_pre0 = MpfssReg::new(self.param.n_pre0, self.param.t_pre0, self.param.log_bin_sz_pre0, self.party);
        mpfss_pre0.set_malicious();
        let mut pre_ot_ini0 = OTPre::new(self.param.log_bin_sz_pre0, self.param.t_pre0);

        let m_pre0 = self.param.log_bin_sz_pre0 * self.param.t_pre0;
        self.cot.cot_gen_preot(io, &mut pre_ot_ini0, m_pre0, None);

        // mac = key + delta * u
        let triple_n0 = 1 + self.param.t_pre0 + self.param.k_pre0;
        let mut key = vec![FE::zero(); triple_n0];
        let mut svole0 = BaseSvole::new_sender(io, self.delta);
        svole0.triple_gen_send(io, &mut key, triple_n0);

        // println!("Test base svole: {:?}", key[0]);

        io.flush();

        let mut pre_y0 = vec![FE::zero(); self.param.n_pre0];
        self.extend_send(io, &mut pre_y0, &mut mpfss_pre0, &mut pre_ot_ini0, &mut lpn_pre0, &key, self.param.t_pre0);

        // println!("Test LPN: {:?}", pre_y0[0]);

        let seed_pre = [0u8; 16];
        // let seed_field_pre = [[0u8; 16]; 4];
        let mut seed_field_pre = [0u8; 32];
        seed_field_pre[0] = 1;
        let mut lpn_pre = Lpn::new(self.param.k_pre, self.param.n_pre, &seed_pre, &seed_field_pre);
        let mut mpfss_pre = MpfssReg::new(self.param.n_pre, self.param.t_pre, self.param.log_bin_sz_pre, self.party); 
        mpfss_pre.set_malicious();
        let mut pre_ot_ini = OTPre::new(self.param.log_bin_sz_pre, self.param.t_pre);

        let m_pre = self.param.log_bin_sz_pre * self.param.t_pre;
        self.cot.cot_gen_preot(io, &mut pre_ot_ini, m_pre, None);

        // 
        let triple_n = 1 + self.param.t_pre + self.param.k_pre;        
        let mut pre_y = vec![FE::zero(); self.param.n_pre];
        self.extend_send(io, &mut pre_y, &mut mpfss_pre, &mut pre_ot_ini, &mut lpn_pre, &pre_y0[..triple_n], self.param.t_pre);
        self.pre_y.copy_from_slice(&pre_y);

        self.pre_ot_inplace = true;
    }

    pub fn setup_receiver<IO: CommunicationChannel>(&mut self, io: &mut IO) {
        self.delta = io.receive_stark252(1).expect("Failed to receive test delta")[0]; //debug only

        let seed_pre0 = [0u8; 16];
        let mut seed_field_pre0 = [0u8; 32];
        seed_field_pre0[0] = 1;
        let mut lpn_pre0 = Lpn::new(self.param.k_pre0, self.param.n_pre0, &seed_pre0, &seed_field_pre0);
        let mut mpfss_pre0 = MpfssReg::new(self.param.n_pre0, self.param.t_pre0, self.param.log_bin_sz_pre0, self.party);
        mpfss_pre0.set_malicious();
        let mut pre_ot_ini0 = OTPre::new(self.param.log_bin_sz_pre0, self.param.t_pre0);

        let m_pre0 = self.param.log_bin_sz_pre0 * self.param.t_pre0;
        self.cot.cot_gen_preot(io, &mut pre_ot_ini0, m_pre0, None);

        // mac = key + delta * u
        let triple_n0 = 1 + self.param.t_pre0 + self.param.k_pre0;
        let mut mac = vec![FE::zero(); triple_n0];
        let mut u = vec![FE::zero(); triple_n0];
        let mut svole0 = BaseSvole::new_receiver(io);
        svole0.triple_gen_recv(io, &mut mac, &mut u, triple_n0);

        // println!("Test base svole: {:?}", mac[0] - u[0] * self.delta);

        io.flush();

        let mut pre_y0 = vec![FE::zero(); self.param.n_pre0];
        let mut pre_z0 = vec![FE::zero(); self.param.n_pre0];
        self.extend_recv(io, &mut pre_y0, &mut pre_z0, &mut mpfss_pre0, &mut pre_ot_ini0, &mut lpn_pre0, &mac, &u, self.param.t_pre0);

        let seed_pre = [0u8; 16];
        let mut seed_field_pre = [0u8; 32];
        seed_field_pre[0] = 1;
        let mut lpn_pre = Lpn::new(self.param.k_pre, self.param.n_pre, &seed_pre, &seed_field_pre);
        let mut mpfss_pre = MpfssReg::new(self.param.n_pre, self.param.t_pre, self.param.log_bin_sz_pre, self.party); 
        mpfss_pre.set_malicious();
        let mut pre_ot_ini = OTPre::new(self.param.log_bin_sz_pre, self.param.t_pre);

        let m_pre = self.param.log_bin_sz_pre * self.param.t_pre;
        self.cot.cot_gen_preot(io, &mut pre_ot_ini, m_pre, None);

        // 
        let triple_n = 1 + self.param.t_pre + self.param.k_pre;        
        let mut pre_y = vec![FE::zero(); self.param.n_pre];
        let mut pre_z = vec![FE::zero(); self.param.n_pre];
        self.extend_recv(io, &mut pre_y, &mut pre_z, &mut mpfss_pre, &mut pre_ot_ini, &mut lpn_pre, &pre_y0[..triple_n], &pre_z0[..triple_n], self.param.t_pre);
        self.pre_y.copy_from_slice(&pre_y);
        self.pre_z.copy_from_slice(&pre_z);

        self.pre_ot_inplace = true;
    }

    pub fn extend_initialization(&mut self) {
        self.m = self.param.k + self.param.t + 1;
        self.ot_limit = self.param.n - self.m;
        self.ot_used = self.ot_limit;
        self.extend_initialized = true;
    }

    pub fn extend_once<IO: CommunicationChannel>(&mut self, io: &mut IO, data_y: &mut [FE], data_z: &mut [FE], mpfss: &mut MpfssReg, pre_ot: &mut OTPre, lpn: &mut Lpn) {
        self.cot.cot_gen_preot(io, pre_ot, self.param.t * self.param.log_bin_sz, None);
        let mut pre_y = vec![FE::zero(); self.m];
        pre_y.copy_from_slice(&self.pre_y[..self.m]);
        let mut pre_z = vec![FE::zero(); self.m];
        pre_z.copy_from_slice(&self.pre_z[..self.m]);
        if self.party == 0{
            self.extend_send(io, data_y, mpfss, pre_ot, lpn, &pre_y, self.param.t);
        } else {
            self.extend_recv(io, data_y, data_z, mpfss, pre_ot, lpn, &pre_y, &pre_z, self.param.t);
        }
        self.pre_y[..self.m].copy_from_slice(&data_y[self.ot_limit..]);
        self.pre_z[..self.m].copy_from_slice(&data_z[self.ot_limit..]);
    }

    pub fn extend<IO: CommunicationChannel>(&mut self, io: &mut IO, data_y: &mut [FE], data_z: &mut [FE], num: usize) {
        if self.extend_initialized == false {
            panic!("Run extend_initialization first!");
        }

        if num <= self.silent_ot_left() {
            data_y.copy_from_slice(&self.vole_y[self.ot_used..self.ot_used+num]);
            data_z.copy_from_slice(&self.vole_z[self.ot_used..self.ot_used+num]);
            return;
        }

        let gened = self.silent_ot_left();
        let mut copied = 0;
        if gened > 0 {
            data_y.copy_from_slice(&self.vole_y[self.ot_used..self.ot_used+gened]);
            data_z.copy_from_slice(&self.vole_z[self.ot_used..self.ot_used+gened]);
            copied += gened;
        }

        self.m = self.param.k + self.param.t + 1;
        let mut round_inplace = 0;
        if num > gened + self.m {
            round_inplace = (num - gened - self.m) / self.ot_limit;
        }
        let mut last_round_ot = num - gened - round_inplace * self.ot_limit; // m + something
        let round_memcpy = (last_round_ot > self.ot_limit) as bool;
        if round_memcpy {
            last_round_ot -= self.ot_limit;
        }

        let mut pre_ot = OTPre::new(self.param.log_bin_sz, self.param.t);
        let seed = [0u8; 16];
        let mut seed_field = [0u8; 32];
        seed_field[0] = 1;
        let mut lpn = Lpn::new(self.param.k, self.param.n, &seed, &seed_field);
        let mut mpfss = MpfssReg::new(self.param.n, self.param.t, self.param.log_bin_sz, self.party); 
        mpfss.set_malicious();

        for i in 0..round_inplace {
            self.extend_once(io, &mut data_y[copied..copied+self.param.n], &mut data_z[copied..copied+self.param.n], &mut mpfss, &mut pre_ot, &mut lpn);
            self.ot_used = self.ot_limit;
            copied += self.ot_limit;
        }

        if round_memcpy {
            let mut tmp_y = vec![FE::zero(); self.param.n];
            let mut tmp_z = vec![FE::zero(); self.param.n];
            self.extend_once(io, &mut tmp_y, &mut tmp_z, &mut mpfss, &mut pre_ot, &mut lpn);
            self.vole_y.copy_from_slice(&tmp_y);
            self.vole_z.copy_from_slice(&tmp_z);
            data_y[copied..copied+self.ot_limit].copy_from_slice(&tmp_y[..self.ot_limit]);
            data_z[copied..copied+self.ot_limit].copy_from_slice(&tmp_z[..self.ot_limit]);
            self.ot_used = self.ot_limit;
            copied += self.ot_limit;
        }

        if last_round_ot > 0 {
            let mut tmp_y = vec![FE::zero(); self.param.n];
            let mut tmp_z = vec![FE::zero(); self.param.n];
            self.extend_once(io, &mut tmp_y, &mut tmp_z, &mut mpfss, &mut pre_ot, &mut lpn);
            self.vole_y.copy_from_slice(&tmp_y);
            self.vole_z.copy_from_slice(&tmp_z);
            data_y[copied..].copy_from_slice(&tmp_y[..last_round_ot]);
            data_z[copied..].copy_from_slice(&tmp_z[..last_round_ot]);
            self.ot_used = last_round_ot;
        }
    }        

    pub fn silent_ot_left(&self) -> usize {
        self.ot_limit - self.ot_used
    }

    // debug only
    pub fn check_triple<IO: CommunicationChannel>(&self, io: &mut IO, x: FE, y: &[FE], z: &[FE], size: usize) {
        if self.party == 0 {
            io.send_stark252(&[x]).expect("Failed to send delta test.");
            io.send_stark252(&y).expect("Failed to send k test.");
        } else {
            // want y = k + delta * z
            let delta = io.receive_stark252(1).expect("Failed to receive delta test.")[0];
            let k = io.receive_stark252(size).expect("Failed to receive k test");
            for i in 0..size {
                if y[i] != k[i] + delta * z[i] {
                    panic!("tripple error at index {}", i);
                }
            }
        }
    }
}