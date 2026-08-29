pub fn do_something_unsafe_0() {
    unsafe {
        let ptr = 0x45f51c52 as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_1() {
    unsafe {
        let ptr = 0xb3e4210a as *mut u32;
        *ptr = 1;
    }
}

pub fn do_something_unsafe_2() {
    unsafe {
        let ptr = 0xc32d5526 as *mut u32;
        *ptr = 1;
    }
}
