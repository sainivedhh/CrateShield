pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x7acca970 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x8b6594ce as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xc80c3195 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0x7c14047a as *mut u32;
        *ptr = 1;
    }
}
