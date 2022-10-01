bitflags! {
    #[derive(Default)]
    pub(crate) struct MousePacketState: u8 {
        const LEFT_BUTTON = 1 << 0;
        const RIGHT_BUTTON = 1 << 1;
        const MIDDLE_BUTTON = 1 << 2;
        const ALWAYS_ONE  = 1 << 3;
        const X_SIGN = 1 << 4;
        const Y_SIGN = 1 << 5;
        const X_OVERFLOW = 1 << 6;
        const Y_OVERFLOW = 1 << 7;
    }
}
