pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x68f46bce as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xdef58689 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xa79fcfaf as *mut u32;
        *ptr = 1;
    }
}
