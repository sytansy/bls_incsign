extern crate mcore;

use mcore::bls12381::bls::bls_hash_to_point;
use mcore::bls12381::ecp2::ECP2;
use mcore::bls12381::ecp::ECP;
use mcore::bls12381::big::BIG;
use mcore::hash256::HASH256;
use mcore::rand::RAND;
use rand::{rngs::OsRng, RngCore};
//use std::io::Read;
use std::time::Instant;
use mcore::bls12381::bls;
use mcore::bls12381::rom;
use mcore::bls12381::pair;
use std::io::{self, Write};


//field sizes
const BFS: usize = bls::BFS;
const BGS: usize = bls::BGS;
const G1S: usize = BFS + 1; /* Group 1 Size  - compressed */
const G2S: usize = 2 * BFS +1 ; /* Group 2 Size  - compressed */

pub fn printbinary(array: &[u8]) {
    for i in 0..array.len() {
        print!("{:02X}", array[i])
    }
    println!("")
}

pub fn bigtobytes(num: &BIG) -> [u8; BGS]{
    let mut n: [u8; BGS] = [0; BGS];
    num.tobytes(&mut n);

    return n;    
}

pub fn ecptobytes(n: &ECP) -> [u8; G1S]{
    let mut point: [u8; G1S] = [0; G1S];
    n.tobytes(&mut point, true);

    return point;    
}

pub fn ecp2tobytes(n: &ECP2) -> [u8; G2S]{
    let mut point: [u8; G2S] = [0; G2S];
    n.tobytes(&mut point, true);

    return point;    
}

fn bls_setup(rng: &mut RAND, mut sk: &mut [u8], mut pk: &mut [u8]) -> isize{
  
    let mut ikm: [u8; 32] = [0; 32];

    for i in 0..32 {
        ikm[i]=rng.getbyte();
    }

    return bls::key_pair_generate(&ikm, &mut sk, &mut pk)    
}

/* 
fn bls(rng: &mut RAND) {    
    //sk
    let mut sk: [u8; BGS] = [0; BGS];

    //pk
    let mut pk: [u8; G2S] = [0; G2S];

    let mut time = Instant::now();
    let mut res = bls_setup(rng, &mut sk, &mut pk);
    let time_setup = time.elapsed().as_nanos();

    if res ==0 {
        println!("BLS Setup OK, completed in {}ns", fmt_time(&time_setup));
    }else{
        println!("BLS Setup FAILED, completed in {}ns", fmt_time(&time_setup));
    }
    println!("subgroup order bits: {}", BGS*8);
    println!("group modulus bits : {}", G1S*8);
    print!("Private key : 0x");
    printbinary(&sk);
    print!("Public  key : 0x");
    printbinary(&pk);    

    //sign
    let m: &str = "test message";
    let mut sig: [u8; G1S] = [0; G1S];
    
    time = Instant::now();
    bls::core_sign(&mut sig, &m.as_bytes(), &sk);
    let time_sign = time.elapsed().as_nanos();

    print!("\nSignature : 0x");
    printbinary(&sig);
    println!("Sign time taken: {}ns\n", fmt_time(&time_sign));

    //verify
    time = Instant::now();
    res = bls::core_verify(&sig, &m.as_bytes(), &pk);
    let time_vrf = time.elapsed().as_nanos();
    if res == 0 {
        println!("Signature verified.");
        println!("Verify time taken: {}ns\n", fmt_time(&time_vrf));
    } else {
        println!("Signature NOT verified.");
        println!("Verify time taken: {}ns\n", fmt_time(&time_vrf));
    }
}
 */

fn bdn_blsms(rng: &mut [RAND], benchmark: bool) -> (u128, u128, u128, u128, u128){    
    let l = rng.len();
    let mut sk: Vec<[u8; BGS]> = vec![[0; BGS]; l];
    let mut pk: Vec<[u8; G2S]> = vec![[0; G2S]; l];
    let mut sig: Vec<[u8; G1S]> = vec![[0; G1S]; l];

    let mut res: isize = 0;
    let mut time;
    let mut time_setup: u128 = 0;

    //setup
    for i in 0..l{
        //sk
        sk[i] = [0; BGS];

        //pk
        pk[i] = [0; G2S];

        time = Instant::now();
        res += bls_setup(&mut rng[i], &mut sk[i], &mut pk[i]);
        time_setup += time.elapsed().as_nanos();
    }

    if !benchmark{
        if res == 0 {
            println!("{} BLS Setup OK, completed in {}ns", l, fmt_time(&time_setup));
        }else{
            println!("{} BLS Setup FAILED, completed in {}ns", l, fmt_time(&time_setup));
        } 
    }

    //sign
    let m: &str = "test message";
    let mut sigma = ECP::new();
    
    let mut exp = vec![BIG::new(); l];
    let mut h1 = HASH256::new();

    //concatenate all pk bytes
    let mut allpk: Vec<u8> = vec![0; l * G2S];

    for i in 0..l{
        allpk.extend(pk[i].clone());
    }
    let order = BIG::new_ints(&rom::CURVE_ORDER);
    
    time = Instant::now();
    for i in 0..l {
        exp[i] = BIG::modmul(&BIG::frombytes(&sk[i]), &hash_pks2big(&mut h1, &pk[i], &allpk, &order), &order);
        let mut newsk: [u8; BGS] = [0; BGS];
        exp[i].tobytes(&mut newsk);

        bls::core_sign(&mut sig[i], &m.as_bytes(), &newsk);
    }
    let time_sign = time.elapsed().as_nanos();

    if !benchmark{
        println!("All {} signers signed in: {}ns\n", l, fmt_time(&time_sign));
    }

    time = Instant::now();    
    for i in 0..sig.len(){
        sigma.add(&ECP::frombytes(&sig[i]));        
    }
    let time_comb = time.elapsed().as_nanos();
    
    if !benchmark{
        print!("\nSignature : 0x");
        printbinary(&ecptobytes(&sigma));
        println!("Combining time taken: {}ns\n", fmt_time(&time_comb));
    }

    //pk aggregation
    time = Instant::now();
    let apk = bdn_aggpk(&mut h1, &pk, &order);    
    let time_apk = time.elapsed().as_nanos();

    if !benchmark{
        print!("APK : 0x");
        printbinary(&ecp2tobytes(&apk));
        println!("AggPK time taken: {}ns\n", fmt_time(&time_apk));
    }

    //verify    
    time = Instant::now();
    let mut r = pair::initmp();
    sigma.neg();
    pair::another(&mut r, &ECP2::generator(), &sigma);
    pair::another(&mut r, &apk, &bls_hash_to_point(&m.as_bytes()));

    let mut v = pair::miller(&mut r);
    v = pair::fexp(&v);
    if v.isunity() {
        res = 0;
    } else{
        res = -1;
    }
    //res = bls::core_verify(&ecptobytes(&sigma), &m.as_bytes(), &ecp2tobytes(&apk));
    let time_vrf = time.elapsed().as_nanos();

    if !benchmark{
        if res == 0 {
            println!("Signature verified.");
            println!("Verify time taken: {}ns\n", fmt_time(&time_vrf));
        } else {
            println!("Signature NOT verified.");
            println!("Verify time taken: {}ns\n", fmt_time(&time_vrf));
        }
    }

    return (time_setup, time_sign, time_comb, time_apk, time_vrf);
}

fn bdn_aggpk(h1: &mut HASH256, pkvec: &Vec<[u8; G2S]>, order : &BIG) -> ECP2 {
    //concatenate all pk bytes
    let mut allpk: Vec<u8> = vec![0; pkvec.len() * G2S];

    for i in 0..pkvec.len(){
        allpk.extend(pkvec[i].clone());
    }

    let mut apk = ECP2::new();

    
    for i in 0..pkvec.len(){    
        apk.add(
            &pair::g2mul(&ECP2::frombytes(&pkvec[i]), &hash_pks2big(h1, &pkvec[i], &allpk, &order))
        );
        
        /*
        let time0 = Instant::now();
        pair::g2mul(&ECP2::generator(), &BIG::new_int(2));
        let tt = time0.elapsed().as_nanos();
        println!("Time taken by g2mul in bdn: {}ns", fmt_time(&tt));
        */
    }
    
    apk
}



fn our_blsms(rng: &mut [RAND], ell: usize, benchmark: bool) -> (u128, u128, u128, u128, u128){    
    let mut h = HASH256::new();
    let l = rng.len();
    let mut sk: Vec<[u8; BGS]> = vec![[0; BGS]; l];
    let mut pk: Vec<[u8; G2S]> = vec![[0; G2S]; l];
    let mut sig: Vec<[u8; G1S]> = vec![[0; G1S]; l];
    let mut s1: ECP;
    
    let mut res: isize = 0;
    let mut time;
    let mut time_setup: u128 = 0;

    //setup
    for i in 0..l{
        //sk
        sk[i] = [0; BGS];

        //pk
        pk[i] = [0; G2S];

        time = Instant::now();
        res += bls_setup(&mut rng[i], &mut sk[i], &mut pk[i]);
        time_setup += time.elapsed().as_nanos();
    }

    if !benchmark{
        if res == 0 {
            println!("{} BLS Setup OK, completed in {}ns", l, fmt_time(&time_setup));
        }else{
            println!("{} BLS Setup FAILED, completed in {}ns", l, fmt_time(&time_setup));
        } 
    }

    //sign
    let m: &str = "test message";
    
    let order = BIG::new_ints(&rom::CURVE_ORDER);
    
    time = Instant::now();
    for i in 0..l {
        bls::core_sign(&mut sig[i], &m.as_bytes(), &sk[i]);
    }
    let time_sign = time.elapsed().as_nanos();

    if !benchmark{
        println!("All {} signers signed in: {}ns\n", l, fmt_time(&time_sign));
    }

    time = Instant::now();    
    s1 = our_combiner(&sig, &BIG::frombytes(&sk[0]), &order, &hash_2big(&mut h, &sig[0], ell, &order));
    
    let time_comb = time.elapsed().as_nanos();
    
    if !benchmark{
        print!("\nS1 : 0x");
        printbinary(&ecptobytes(&s1));
        print!("\nS2 : 0x");
        printbinary(&sig[0]);
        println!("Combining time taken: {}ns\n", fmt_time(&time_comb));
    }

    //pk aggregation    
    time = Instant::now();
    let (k1, k2) = our_aggpk(&pk, &order, &hash_2big(&mut HASH256::new(), &sig[0], ell, &order));        
    let time_apk = time.elapsed().as_nanos();

    if !benchmark{
        print!("K1 : 0x");
        printbinary(&ecp2tobytes(&k1));
        println!();
        print!("K2 : 0x");
        printbinary(&ecp2tobytes(&k2));
        println!("AggPK time taken: {}ns\n", fmt_time(&time_apk));
    }
    
    //verify    
    time = Instant::now();    
    //e(S1 + S2, g2)    
    s1.add(&ECP::frombytes(&sig[0]));
    s1.neg();
    let mut r = pair::initmp();
    pair::another(&mut r, &ECP2::generator(), &s1);

    //e(S2, K1)
    pair::another(&mut r, &k1, &ECP::frombytes(&sig[0]));

    //e(H(m), K2)
    pair::another(&mut r, &k2, &bls_hash_to_point(&m.as_bytes()));

    let mut v = pair::miller(&mut r);
    v = pair::fexp(&v);
    if v.isunity() {
        res = 0;
    } else{
        res = -1;
    }
    
    let time_vrf = time.elapsed().as_nanos();

    if !benchmark{
        if res == 0 {
            println!("Signature verified.");
            println!("Verify time taken: {}ns\n", fmt_time(&time_vrf));
        } else {
            println!("Signature NOT verified.");
            println!("Verify time taken: {}ns\n", fmt_time(&time_vrf));
        }
    }
    
    return (time_setup, time_sign, time_comb, time_apk, time_vrf);
}

fn our_combiner(sig: &Vec<[u8; G1S]>, sk: &BIG, order: &BIG, start: &BIG) -> ECP{
    let mut sigma = ECP::new();

    if start.iszilch(){
        for i in 0..sig.len(){        
            let e = BIG::modadd(&sk, 
                                    &BIG::new_int((i as isize) +1), 
                                    &order);
            
            sigma.add(&pair::g1mul(&ECP::frombytes(&sig[i]), &e));        
        }
    }else{
        for i in 0..sig.len(){        
            let e = BIG::modadd(&sk, 
                                    &BIG::modadd(&start, &BIG::new_int((i as isize) +1), &order), 
                                    &order);
            
            sigma.add(&pair::g1mul(&ECP::frombytes(&sig[i]), &e));        
        }
    }
    

    sigma
}

fn our_aggpk(pkvec: &Vec<[u8; G2S]>, order: &BIG, start: &BIG) -> (ECP2, ECP2) {
    //concatenate all pk bytes
    let mut k1 = ECP2::new();
    let mut k2 = ECP2::new();

    
    if start.iszilch(){
        for i in 0..pkvec.len(){                    
            k2.add(
                //&pair::g2mul(&ECP2::frombytes(&pkvec[i]), &BIG::new_int((i as isize) +1))            
                &ECP2::frombytes(&pkvec[i]).mul(&BIG::new_int((i as isize) +1))
            );
            k1.add(
                &ECP2::frombytes(&pkvec[i])
            );

            /*
            let mut time0 = Instant::now();
            pair::g2mul(&ECP2::generator(), &BIG::new_int(2));
            let mut tt = time0.elapsed().as_nanos();
            println!("Time taken by g2mul in ours: {}ns", fmt_time(&tt));

            
            time0 = Instant::now();
            pair::g2mul(&ECP2::generator(), &BIG::modadd(&start, &BIG::new_int(2), &order));
            tt = time0.elapsed().as_nanos();
            println!("Time taken by g2mul in ours: {}ns", fmt_time(&tt));*/
        }    
    }else{
        for i in 0..pkvec.len(){        
            k1.add(
                &ECP2::frombytes(&pkvec[i])
            );
            k2.add(
                //&pair::g2mul(&ECP2::frombytes(&pkvec[i]), &BIG::modadd(&start, &BIG::new_int((i as isize) +1), &order))
                &ECP2::frombytes(&pkvec[i]).mul(&BIG::modadd(&start, &BIG::new_int((i as isize) +1), &order))            
            );
        }
    }
    

    k2.add(&ECP2::frombytes(&pkvec[0]));

    (k1,k2)
}

fn hash_2big(h: &mut HASH256, sig2: &[u8], ell: usize, order: &BIG) -> BIG{
    if ell == 0{
        return BIG::new();
    }

    for i in 0..sig2.len(){
        h.process(sig2[i]);
    }

    let mut output = h.hash().to_vec();

    output = output[..(ell/8)].to_vec();    
    
    if output.len() < BGS {
        let extra = BGS - output.len();
        let mut zeros: Vec<u8> = vec![0; extra];
        zeros.append(&mut output);        

        let mut temp = BIG::frombytes(&zeros);
        temp.rmod(&order);
        return temp;
    }

    let mut temp = BIG::frombytes(&output);
    temp.rmod(&order);
    return temp;
}

fn hash_pks2big(h1: &mut HASH256, pknow: &[u8], input: &[u8], order: &BIG) -> BIG{
    for i in 0..pknow.len(){
        h1.process(pknow[i]);
    }

    for i in 0..input.len(){
        h1.process(input[i]);
    }

    let mut output = h1.hash().to_vec();

    if output.len() < BGS {
        let extra = BGS - output.len();
        let mut zeros: Vec<u8> = vec![0; extra];
        zeros.append(&mut output);        

        let mut temp = BIG::frombytes(&zeros);
        temp.rmod(&order);

        return BIG::frombytes(&zeros);
    }

    let mut temp = BIG::frombytes(&output);
    temp.rmod(&order);

    return BIG::frombytes(&output);
}

fn fmt_time(time: &u128) -> String{
    if (time % 1000000000000) / 1000000000 == 0 && (time % 1000000000) / 1000000 == 0 {
        return format!("{:3},{:03}", (time % 1000000) / 1000 , time % 1000)
    } else if (time % 1000000000000) / 1000000000 == 0 {
        return format!("{:3},{:03},{:03}", (time % 1000000000) / 1000000 , (time % 1000000) / 1000 , time % 1000)
    } else {
        return format!("{:3},{:03},{:03},{:03}", (time % 1000000000000) / 1000000000, (time % 1000000000) / 1000000 , (time % 1000000) / 1000 , time % 1000)
    }
}

fn gen_seed() -> RAND{
    let mut raw: [u8; 100] = [0; 100];
    let mut rng = RAND::new();
    rng.clean();
    OsRng.fill_bytes(&mut raw);
    rng.seed(100, &raw);

    return rng;
}

fn main() {
    //use mcore::arch;
    //println!("{} bit build", arch::CHUNK);
    
    //bls(&mut gen_seed());

    //set to false if want to see the details
    let mut benchmark = false;
    let mut bdn_only = false;
    let mut our_only = false;
    let mut round: u128 = 1;
    let mut input = String::new();
    let mut ell : usize = 0;

    print!("Run a benchmark? Type 'Y' for yes, or press ENTER to run single execution: ");
    io::stdout().flush().unwrap(); 

    io::stdin().read_line(&mut input).unwrap();
    input = input.trim().to_string();

    match input.as_str() {
        "Y" => {
            benchmark = true;

            input.clear();
            print!("Run which scheme? Type '1' for BDN-MS only, '2' for OUR-MS only, press ENTER for both: ");
            io::stdout().flush().unwrap(); 

            io::stdin().read_line(&mut input).unwrap();
            input = input.trim().to_string();

            match input.as_str() {
                "1" => { bdn_only = true;}
                "2" => { 
                    our_only = true;
                    
                    print!("What's the bit length of 'ell' for OUR-MS? Insert a number in multiple of 8 (0 - 64): ");
                    io::stdout().flush().unwrap(); 

                    input.clear();
                    io::stdin().read_line(&mut input).unwrap();

                    ell = input.trim().parse().unwrap();
                }
                _ => {
                    bdn_only = true; our_only = true;

                    print!("What's the bit length of 'ell' for OUR-MS? Insert a number in multiple of 8 (0 - 64): ");
                    io::stdout().flush().unwrap(); 

                    input.clear();
                    io::stdin().read_line(&mut input).unwrap();

                    ell = input.trim().parse().unwrap();
                }
            }

            print!("Run benchmark for how many rounds? ");
            io::stdout().flush().unwrap(); 

            input.clear();
            io::stdin().read_line(&mut input).unwrap();
            round = input.trim().parse().unwrap();            
        }
        _ => {            
            bdn_only = true; our_only = true;
            println!("Run single execution... ");

            print!("What's the bit length of 'ell' for OUR-MS? Insert a number in multiple of 8 (0 - 64): ");
            io::stdout().flush().unwrap(); 

            input.clear();
            io::stdin().read_line(&mut input).unwrap();

            ell = input.trim().parse().unwrap();
        }
    }

    print!("How many MS signers? ");
    io::stdout().flush().unwrap(); 

    input.clear();
    io::stdin().read_line(&mut input).unwrap();

    let input_num: usize = input.trim().parse().unwrap();

    let mut rng: Vec<RAND> = Vec::with_capacity(input_num);
    for _ in 0..input_num {
        rng.push(gen_seed());
    }

    
    if bdn_only{

        println!("\n=================================");
        println!("This is BDN-MS with {} signers\n", input_num);
        println!("=================================\n");
        io::stdout().flush().unwrap();
        
        if benchmark{
            let mut setup : u128 = 0;
            let mut sign : u128 = 0;
            let mut combine : u128 = 0;
            let mut pkagg : u128 = 0;
            let mut verify : u128 = 0;

            for i in 0..round{
                print!("\rRunning round {}/{}", i, round);
                io::stdout().flush().unwrap();

                let (setup_, sign_, combine_, pkagg_, verify_) = bdn_blsms(&mut rng, benchmark);
                setup += setup_;
                sign += sign_;
                combine += combine_;
                pkagg += pkagg_;
                verify += verify_;
            }

            print!("\r{}{}", " ".repeat(30), "\r");
            io::stdout().flush().unwrap();


            setup /= round;
            sign /= round;
            combine /= round;
            pkagg /= round;
            verify /= round;
            
            println!("Average timing for {} rounds:\n", round);
            println!("Setup time taken  : {}ns", fmt_time(&setup));
            println!("Signing time taken: {}ns", fmt_time(&sign));
            println!("Combine time taken: {}ns", fmt_time(&combine));
            println!("PK Agg time taken : {}ns", fmt_time(&pkagg));
            println!("Verify time taken : {}ns", fmt_time(&verify));
        }else{
            bdn_blsms(&mut rng, benchmark);
        }
    }

    if our_only{
        println!("\n=================================");
        println!("\nThis is Our MS with {} signers", input_num);
        println!("=================================\n");
        io::stdout().flush().unwrap();

        if benchmark{
            let mut setup : u128 = 0;
            let mut sign : u128 = 0;
            let mut combine : u128 = 0;
            let mut pkagg : u128 = 0;
            let mut verify : u128 = 0;

            for i in 0..round{
                print!("\rRunning round {}/{}", i, round);
                io::stdout().flush().unwrap();

                let (setup_, sign_, combine_, pkagg_, verify_) = our_blsms(&mut rng, ell, benchmark);
                setup += setup_;
                sign += sign_;
                combine += combine_;
                pkagg += pkagg_;
                verify += verify_;
            }

            print!("\r{}{}", " ".repeat(30), "\r");
            io::stdout().flush().unwrap();


            setup /= round;
            sign /= round;
            combine /= round;
            pkagg /= round;
            verify /= round;
            
            println!("Average timing for {} rounds:\n", round);
            println!("Setup time taken  : {}ns", fmt_time(&setup));
            println!("Signing time taken: {}ns", fmt_time(&sign));
            println!("Combine time taken: {}ns", fmt_time(&combine));
            println!("PK Agg time taken : {}ns", fmt_time(&pkagg));
            println!("Verify time taken : {}ns", fmt_time(&verify));
        }else{
            our_blsms(&mut rng, ell, benchmark);
        }    
    }

    /*
    * pair::g2mul() vs ecp2.mul() performance check
    * g2mul() is faster for big multiplier
    * mul() is faster for small multiplier
    * break even is around 100-bit multiplier
    *
    let order = BIG::new_ints(&rom::CURVE_ORDER);
    let mut time0 = Instant::now();
    let mut num = BIG::new_int(10);
    let mut g2 = pair::g2mul(&ECP2::generator(), &num);    
    let mut tt = time0.elapsed().as_nanos();
    
    print!("g2 is  "); 
    printbinary(&ecp2tobytes(&g2));
    print!("num is "); 
    printbinary(&bigtobytes(&num));
    println!("g2mul time is: {}ns", fmt_time(&tt));

    time0 = Instant::now();
    g2 = ECP2::generator().mul(&num);
    tt = time0.elapsed().as_nanos();
    
    print!("g2 is "); 
    printbinary(&ecp2tobytes(&g2));
    print!("num is "); 
    printbinary(&bigtobytes(&num));
    println!("mul time is: {}ns", fmt_time(&tt));

    time0 = Instant::now();
    num = BIG::randomnum(&order, &mut rng[0]);
    g2 = pair::g2mul(&ECP2::generator(), &num);
    tt = time0.elapsed().as_nanos();
    
    print!("g2 is "); 
    printbinary(&ecp2tobytes(&g2));
    print!("num is on "); 
    printbinary(&bigtobytes(&num));
    println!("g2mul time is: {}ns", fmt_time(&tt));

    time0 = Instant::now();
    g2 = ECP2::generator().mul(&num);
    tt = time0.elapsed().as_nanos();
    
    print!("g2 is "); 
    printbinary(&ecp2tobytes(&g2));
    print!("num is "); 
    printbinary(&bigtobytes(&num));
    println!("mul time is: {}ns", fmt_time(&tt));
    */

    println!();
}