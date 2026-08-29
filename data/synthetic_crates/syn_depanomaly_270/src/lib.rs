pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x3df52967 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x40afcf3f as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xa89e32f2 as *mut u32;
        *ptr = 1;
    }
}
