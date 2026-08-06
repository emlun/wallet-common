import { CurvePoint, CurvePointCons } from "@noble/curves/abstract/curve";


export function sum<P extends CurvePoint<any, P>, G extends CurvePointCons<P>>(g: { Point: G }, points: P[]): P {
	return points.reduce((sum, P) => sum.add(P), g.Point.ZERO);
}

export function sumprod<P extends CurvePoint<any, P>, G extends CurvePointCons<P>>(g: { Point: G }, points: P[], scalars: bigint[]): P {
	if (points.length !== scalars.length) {
		throw new Error("Invalid input dimensions", { cause: { points, scalars } });
	}
	return sum(g, points.map((p, i) =>
		scalars[i] === 0n
			? g.Point.ZERO
			: p.multiply(scalars[i])
	));
}
