use std::embedded_curve_ops::{EmbeddedCurvePoint, embedded_curve_add};

fn main(
    // make sure we have inputs so that the calls don't get optmizited out into simple asserts
    point_x: Field,
) {
    // using the generator of P-256 for an easily documented point that is sure to be on the curve
    let point1 = EmbeddedCurvePoint { x: point_x, y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 };
    let point2 = EmbeddedCurvePoint { x: point_x, y: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 };
    let result = embedded_curve_add(point1, point2);

    assert(result.x == 56515219790691171413109057904011688695424810155802929973526481321309856242040);
    assert(result.y == 3377031843712258259223711451491452598088675519751548567112458094635497583569);
}