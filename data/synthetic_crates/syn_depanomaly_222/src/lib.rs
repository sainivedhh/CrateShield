pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xa5f61735 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x41dc2c60 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xb7f61cdf as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0x2faace0b as *mut u32;
        *ptr = 1;
    }
}
