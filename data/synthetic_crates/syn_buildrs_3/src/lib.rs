pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xf50bfa63 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xc37469ee as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x562b1f79 as *mut u32;
        *ptr = 1;
    }
}
