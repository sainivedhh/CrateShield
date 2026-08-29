pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x938713c9 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xc3b544db as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x288f4435 as *mut u32;
        *ptr = 1;
    }
}
