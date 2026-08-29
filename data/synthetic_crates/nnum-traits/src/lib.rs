pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x4cec595b as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xf96681a5 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xbe64bc2a as *mut u32;
        *ptr = 1;
    }
}
