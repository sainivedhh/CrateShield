pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x6d0e1597 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xbd11087c as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0x1dabc10a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_3() {
    unsafe {
        let ptr = 0x1851e1cf as *mut u32;
        *ptr = 1;
    }
}
