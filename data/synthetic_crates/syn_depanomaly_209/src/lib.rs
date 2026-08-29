pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x8ece2128 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xf05efefe as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x5d987115 as *mut u32;
        *ptr = 1;
    }
}
