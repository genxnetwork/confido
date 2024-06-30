// mod pcr;

use ring::digest::Context;
use ring::digest::Algorithm;

pub struct PCR {
    digest_size: usize,
    pub algo: &'static Algorithm,
    digest: Vec<u8>,
    pub value: Vec<u8>,
}

impl PCR {
    pub fn new(algo: &'static Algorithm, value: Option<Vec<u8>>) -> PCR {
        let digest_size = algo.output_len;
        let digest = vec![0; digest_size];
        let value = value.unwrap_or_else(|| vec![0; digest_size]);

        PCR {
            digest_size,
            algo,
            digest,
            value,
        }
    }

    // pub fn algo_name(&self) -> String {
    //     self.algo.name().to_string()
    // }

    pub fn get(&self) -> Vec<u8> {
        self.value.clone()
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Context::new(self.algo);
        hasher.update(data);
        hasher.finish().as_ref().to_vec()
    }

    pub fn extend(&mut self, template_data: &[u8]) {
        let template_hash = self.hash(template_data);
        self.value = self.hash(&[self.value.clone(), template_hash].concat());
    }
}

// fn initial_pcr_value() -> Vec<u8> {
//     let mut context = Context::new(&SHA256);
//     context.update(&[0; 32]);  // Hashing 32 zero bytes
//     context.finish()//.as_ref().to_vec()
// }

// fn extend_pcr(pcr_value: &[u8], new_data: &[u8]) -> Vec<u8> {
//     let mut context = Context::new(&SHA256);
//     context.update(pcr_value);
//     context.update(new_data);
//     context.finish()// .as_ref().to_vec()
// }