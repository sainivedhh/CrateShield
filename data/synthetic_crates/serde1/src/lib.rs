pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0xf3f1f48 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0x59c2574 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x25d08461 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0x962c14dd as *mut u32;
        *ptr = 1;
    }
}
