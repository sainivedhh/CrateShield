pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x6c007f61 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x2ef92276 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x474ecc19 as *mut u32;
        *ptr = 1;
    }
}
