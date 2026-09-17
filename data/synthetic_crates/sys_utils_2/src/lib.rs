pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x72ff6d2a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x96da2dac as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x47379190 as *mut u32;
        *ptr = 1;
    }
}
