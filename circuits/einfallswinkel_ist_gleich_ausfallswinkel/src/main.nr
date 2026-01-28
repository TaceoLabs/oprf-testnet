fn main(einfallswinkel: u64, ausfallswinkel: u64) -> pub bool {
    assert(einfallswinkel < 360);
    assert(ausfallswinkel < 360);
    einfallswinkel == ausfallswinkel
}
