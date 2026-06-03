use std::embedded_curve_ops::{EmbeddedCurveScalar, EmbeddedCurvePoint, multi_scalar_mul};

fn main(point_x: Field) {
    let point1 = EmbeddedCurvePoint {
        x: point_x,
        y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
    }; // coords in Fp
    let scalar = EmbeddedCurveScalar{ lo: 2, hi: 0 }; // in Fq
    let multiplied = multi_scalar_mul([point1], [scalar]);
    assert(multiplied.x == 56515219790691171413109057904011688695424810155802929973526481321309856242040);
    assert(multiplied.y == 3377031843712258259223711451491452598088675519751548567112458094635497583569);
}