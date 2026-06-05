/** Implementation of https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/08/ */

import type { BlsCurvePair } from "@noble/curves/abstract/bls";
import type { Fp2 } from "@noble/curves/abstract/tower";
import { bls12_381 } from "@noble/curves/bls12-381.js";

import { concat, fromHex, I2OSP, OS2IP, split_at, split_sections, toHex, toU8, toUtf8 } from "../utils/util";
import { hashToCurve, sha256, HashToCurveSuite } from "../arkg/hash_to_curve";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";


function range(n: number): number[] {
	return Array(n).fill(0).map((_, i) => i);
}


function createSuite(suite: SuiteParams): CipherSuite {
	const {
		curves: { G1, G2, pairing: h, fields: { Fr, Fp12 } },
		P1,
		expand_len,
		hash_to_curve_g1,
		octet_point_length,
		octet_scalar_length,
		mocked_random_scalars_params,
	} = suite;
	const {
		sig_generator_seed,
		sig_generator_dst,
		message_generator_seed,
	} = suite.create_generators_dsts ?? {
		sig_generator_seed: toUtf8("SIG_GENERATOR_SEED_"),
		sig_generator_dst: toUtf8("SIG_GENERATOR_DST_"),
		message_generator_seed: toUtf8("MESSAGE_GENERATOR_SEED"),
	};

	const { expand_message, prime_subgroup_order } = suite.hash_to_curve_suite.suiteParams;

	function isG1(p: PointG1 | PointG2): p is PointG1 {
		return p instanceof G1.Point;
	}

	function isG2(p: PointG1 | PointG2): p is PointG2 {
		return p instanceof G2.Point;
	}

	function sum(points: PointG1[]): PointG1 {
		return points.reduce((sum, P) => sum.add(P), G1.Point.ZERO);
	}

	function sumprod(points: PointG1[], scalars: bigint[]): PointG1 {
		if (points.length !== scalars.length) {
			throw new Error("Invalid input dimensions", { cause: { points, scalars } });
		}
		return sum(points.map((Hi, i) => Hi.multiply(scalars[i])));
	}

	function matrix_mul(mat: PointG1[][], vec: bigint[]): PointG1[] {
		if (mat[0].length !== vec.length) {
			throw new Error("Invalid input dimensions", { cause: { mat, vec } });
		}
		if (!mat.every(mrow => mrow.length == mat[0].length)) {
			throw new Error("Invalid input dimensions", { cause: { mat, vec } });
		}
		return mat.map(mrow => sumprod(mrow, vec));
	}

	function all_eq(a: PointG1[], b: PointG1[]): boolean {
		return a.length === b.length && a.every((aa, i) => aa.equals(b[i]));
	}

	function get_random(n: number): BufferSource {
		return crypto.getRandomValues(new Uint8Array(n));
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-random-scalars */
	async function real_calculate_random_scalars(count: number): Promise<bigint[]> {
		return range(count).map(() => Fr.create(OS2IP(get_random(expand_len))));
	};

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-random-scalars */
	async function seeded_random_scalars(
		{ SEED, DST }: { SEED: BufferSource, DST: BufferSource },
		count: number,
	): Promise<bigint[]> {
		const out_len = expand_len * count;
		if (out_len > 65536) {
			throw new Error("Output length too high", { cause: { count, expand_len, out_len } });
		}
		const v = toU8(await expand_message(SEED, DST, out_len));
		return range(count).map(i => Fr.create(OS2IP(v.slice(i * expand_len, (i + 1) * expand_len))));
	};

	const calculate_random_scalars: (count: number) => Promise<bigint[]> = (
		mocked_random_scalars_params
			? (count: number) => seeded_random_scalars(mocked_random_scalars_params, count)
			: real_calculate_random_scalars
	);

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-hash-to-scalar */
	async function hash_to_scalar(msg_octets: BufferSource, dst: BufferSource): Promise<bigint> {
		const uniform_bytes = await expand_message(msg_octets, dst, suite.expand_len);
		return OS2IP(uniform_bytes) % prime_subgroup_order;
	};

	async function calculate_domain(
		PK: BufferSource,
		Q_1: PointG1,
		H_Points: PointG1[],
		header: BufferSource,
		api_id: BufferSource,
	): Promise<bigint> {
		const hash_to_scalar_dst = concat(api_id, toUtf8("H2S_"));
		const two64min1 = (1n << 64n) - 1n;
		const L = H_Points.length;
		if (header.byteLength > two64min1) {
			throw new Error(`header too long: expected length max ${two64min1}, got: ${header.byteLength}`, { cause: { header } });
		}
		if (H_Points.length > two64min1) {
			throw new Error(`H_Points too long: expected length max ${two64min1}, got: ${H_Points.length}`, { cause: { H_Points } });
		}

		const dom_array = [L, Q_1, ...H_Points];
		const dom_octs = concat(serialize(dom_array), api_id);
		const dom_input = concat(PK, dom_octs, I2OSP(BigInt(header.byteLength), 8), header);
		return hash_to_scalar(dom_input, hash_to_scalar_dst);
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#messages-to-scalars */
	function messages_to_scalars(
		messages: BufferSource[],
		api_id: BufferSource,
	): Promise<bigint[]> {
		if (messages.length >= Math.pow(2, 64)) {
			throw new Error(`Too many messages: ${messages.length} >= 2^64`, { cause: { length: messages.length } });
		}
		const map_msg_to_scalar_as_hash = toUtf8("MAP_MSG_TO_SCALAR_AS_HASH_");
		const map_dst = concat(api_id, map_msg_to_scalar_as_hash);

		return Promise.all(messages.map(message => hash_to_scalar(message, map_dst)));
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-generators-calculation */
	async function create_generators(count: number, api_id: BufferSource): Promise<PointG1[]> {
		if (count >= Math.pow(2, 64)) {
			throw new Error(`count too high: ${count} >= 2^64`, { cause: { count } });
		}
		const seed_dst = concat(api_id, sig_generator_seed);
		const generator_dst = concat(api_id, sig_generator_dst);
		const generator_seed = concat(api_id, message_generator_seed);
		let v = await expand_message(generator_seed, seed_dst, expand_len);
		const result = [];
		for (let i = 1; i <= count; ++i) {
			v = await expand_message(concat(v, I2OSP(BigInt(i), 8)), seed_dst, expand_len);
			result.push(hash_to_curve_g1(v, generator_dst));
		}
		return result;
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#secret-key */
	async function KeyGen(key_material: BufferSource, key_info: BufferSource | null, key_dst: BufferSource | null): Promise<bigint> {
		key_material = key_material ?? new Uint8Array([]);
		key_info = key_info ?? new Uint8Array([]);
		const dst = key_dst ?? toUtf8(suite.id + "KEYGEN_DST_");

		if (key_material.byteLength < 32) {
			throw new Error(`key_material too short: ${toHex(key_material)}`, { cause: { key_material } });
		}
		if (key_info.byteLength > 65535) {
			throw new Error(`key_info too long: expected length max 65535, got: ${key_info.byteLength}`, { cause: { key_info } });
		}
		const derive_input = concat(key_material, I2OSP(BigInt(key_info.byteLength), 2), key_info);
		const SK = await hash_to_scalar(derive_input, dst);
		return SK;
	}

	function SkToPk(SK: bigint): BufferSource {
		return point_to_octets_E2(G2.Point.BASE.multiply(SK));
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-serialize */
	function serialize(input_array: (PointG1 | PointG2 | bigint | number | BufferSource)[]): ArrayBuffer {
		return concat(...input_array.map(el => {
			switch (typeof el) {
				case 'number':
					return I2OSP(el, 8);

				case 'bigint':
					return I2OSP(el, octet_scalar_length);

				case 'object':
					if (el instanceof ArrayBuffer || ArrayBuffer.isView(el)) {
						return toU8(el);
					} else if (isG1(el)) {
						return point_to_octets_E1(el);
					} else if (isG2(el)) {
						return point_to_octets_E2(el);
					}

				default:
					throw new Error(`Invalid type of value: ${el}`, { cause: { el } });
			}
		}));
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-signature-to-octets */
	function signature_to_octets(A: PointG1, e: bigint): BufferSource {
		return serialize([A, e]);
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#section-4.2.4.3 */
	function octets_to_signature(signature_octets: BufferSource): [PointG1, bigint] {
		const expected_len = octet_point_length + octet_scalar_length;
		if (signature_octets.byteLength !== expected_len) {
			throw new Error(`Invalid length: expected ${expand_len}, got ${signature_octets.byteLength}`, { cause: { signature_octets } });
		}
		const signature_octets_u8 = toU8(signature_octets);
		const A_octets = signature_octets_u8.slice(0, octet_point_length);
		const A = octets_to_point_E1(A_octets);
		A.assertValidity();
		if (A.is0()) {
			throw new Error("A must not be the zero (infinity) point", { cause: { signature_octets, A } });
		}

		const e = OS2IP(signature_octets_u8.slice(octet_point_length));
		if (e === 0n || e >= Fr.ORDER) {
			throw new Error("e must be nonzero and less than curve order", { cause: { signature_octets, e } });
		}

		return [A, e];
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-proof-to-octets */
	function proof_to_octets(proof: [PointG1, PointG1, PointG1, bigint, bigint, bigint, bigint[], bigint]) {
		const [Abar, Bbar, D, ehat, r1hat, r3hat, mhatj, challenge] = proof;
		return serialize([Abar, Bbar, D, ehat, r1hat, r3hat, ...mhatj, challenge]);
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-octets-to-proof */
	function octets_to_proof(proof_octets: BufferSource): [PointG1, PointG1, PointG1, bigint, bigint, bigint, bigint[], bigint] {
		const proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length;
		if (proof_octets.byteLength < proof_len_floor) {
			throw new Error(`Proof too short: expected at least ${proof_len_floor} octets, was ${proof_octets.byteLength}`, { cause: { proof_octets, proof_len_floor } });
		}

		const proof_octets_u8 = toU8(proof_octets);

		const Ai = [0, 1, 2].map(i => {
			const index = i * octet_point_length;
			const end_index = index + octet_point_length;
			const Ai = octets_to_point_E1(proof_octets_u8.slice(index, end_index));
			if (Ai.is0()) {
				throw new Error("Proof point must not be the identity point", { cause: { index, proof_octets } });
			}
			subgroup_check_G1(Ai);
			return Ai;
		});

		const scalar_octets = proof_octets_u8.slice(octet_point_length * 3);
		const sj = range(scalar_octets.length / octet_scalar_length).map(j => {
			const index = j * octet_scalar_length;
			const end_index = index + octet_scalar_length;
			const sj = OS2IP(scalar_octets.slice(index, end_index));
			if (sj === 0n || sj >= Fr.ORDER) {
				throw new Error(`Scalar out of range: ${sj}`, { cause: { r: Fr.ORDER, sj } });
			}
			return sj;
		});

		if (scalar_octets.length !== sj.length * octet_scalar_length) {
			throw new Error("Trailing proof octets", { cause: { proof_octets, octet_point_length, octet_scalar_length } });
		}
		const msg_commitments = (
			sj.length > 4
				? sj.slice(3, sj.length - 1)
				: []
		);
		return [Ai[0], Ai[1], Ai[2], sj[0], sj[1], sj[2], msg_commitments, sj[sj.length - 1]];
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-notation */
	function octets_to_point_E1(ostr: BufferSource): PointG1 {
		return G1.Point.fromBytes(toU8(ostr));
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-notation */
	function point_to_octets_E1(P: PointG1): BufferSource {
		return P.toBytes();
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-notation */
	function subgroup_check_G1(P: PointG1): void {
		P.assertValidity();
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-notation */
	function octets_to_point_E2(ostr: BufferSource): PointG2 {
		return G2.Point.fromBytes(toU8(ostr));
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-notation */
	function point_to_octets_E2(Q: PointG2): BufferSource {
		return Q.toBytes();
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-notation */
	function subgroup_check_G2(Q: PointG2): void {
		Q.assertValidity();
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-octets-to-public-key */
	function octets_to_pubkey(PK: BufferSource): PointG2 {
		const W = octets_to_point_E2(PK);
		subgroup_check_G2(W);
		if (W.is0()) {
			throw new Error("Public key must not be the zero (infinity) point", { cause: { PK } });
		}
		return W;
	}

	function Bbs(api_id: BufferSource): BbsSuite {

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-signature-generation-sign */
		async function Sign(
			SK: bigint,
			PK: BufferSource,
			header: BufferSource | null,
			messages: BufferSource[] | null,
		): Promise<BufferSource> {
			header = header ?? new Uint8Array([]);
			messages = messages ?? [];
			const message_scalars = await messages_to_scalars(messages, api_id);
			const generators = await create_generators(messages.length + 1, api_id);
			const signature = await CoreSign(SK, PK, generators, header, message_scalars, api_id);
			return signature;
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-signature-verification-veri */
		async function Verify(
			PK: BufferSource,
			signature: BufferSource,
			header: BufferSource | null,
			messages: BufferSource[] | null,
		): Promise<true> {
			header = header ?? new Uint8Array([]);
			messages = messages ?? [];
			const message_scalars = await messages_to_scalars(messages, api_id);
			const generators = await create_generators(messages.length + 1, api_id);
			const result = await CoreVerify(PK, signature, generators, header, message_scalars, api_id);
			return result;
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-proof-generation-proofgen */
		async function ProofGen(
			PK: BufferSource,
			signature: BufferSource,
			header: BufferSource | null,
			ph: BufferSource | null,
			messages: BufferSource[] | null,
			disclosed_indexes: number[] | null,
		): Promise<BufferSource> {
			header = header ?? new Uint8Array([]);
			ph = ph ?? new Uint8Array([]);
			messages = messages ?? [];
			disclosed_indexes = disclosed_indexes ?? [];
			const message_scalars = await messages_to_scalars(messages, api_id);
			const generators = await create_generators(messages.length + 1, api_id);
			const proof = await CoreProofGen(PK, signature, generators, header, ph, message_scalars, disclosed_indexes, api_id);
			return proof;
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-proof-verification-proofver */
		async function ProofVerify(
			PK: BufferSource,
			proof: BufferSource,
			header: BufferSource | null,
			ph: BufferSource | null,
			disclosed_messages: BufferSource[] | null,
			disclosed_indexes: number[] | null,
		): Promise<true> {
			header = header ?? new Uint8Array([]);
			ph = ph ?? new Uint8Array([]);
			disclosed_messages = disclosed_messages ?? [];
			disclosed_indexes = disclosed_indexes ?? [];

			const proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length;
			if (proof.byteLength < proof_len_floor) {
				throw new Error(`Proof too short: expected at least ${proof_len_floor} octets, was ${proof.byteLength}`, { cause: { proof, proof_len_floor } });
			}
			const U = Math.floor((proof.byteLength - proof_len_floor) / octet_scalar_length);
			const R = disclosed_indexes.length;

			const message_scalars = await messages_to_scalars(disclosed_messages, api_id);
			const generators = await create_generators(U + R + 1, api_id);
			const result = await CoreProofVerify(PK, proof, generators, header, ph, message_scalars, disclosed_indexes, api_id);
			return result;
		}

		async function BbsSchnorr({ l, dpk_uses_h1 }: BbsSchnorrOptions): Promise<BbsSchnorrSuite> {
			// Domain(Q), dpk (H0), attributes (Hi)
			const generators = (await create_generators(1 + 1 + l, api_id));
			const H0 = dpk_uses_h1 ? generators[1] : G1.Point.BASE;
			const Hi = generators.slice(2);

			function or_rand(ikm: BufferSource | undefined, L: number): BufferSource {
				return ikm ?? crypto.getRandomValues(new Uint8Array(L));
			}

			function sample_scalar(dst: BufferSource, ikm?: BufferSource): Promise<bigint> {
				return hash_to_scalar(or_rand(ikm, octet_scalar_length), dst);
			}

			async function schnorr_KGen(ikm?: BufferSource): Promise<[bigint, PointG1]> {
				const sk = await sample_scalar(toUtf8("Schnorr.KGen"), ikm);
				const pk = H0.multiply(sk);
				return [sk, pk];
			}

			type SchnorrNizkProof1 = [bigint, bigint];
			function schnorr_encode_signature(sig: SchnorrNizkProof1): ArrayBuffer {
				const [c, s] = sig;
				return serialize([s, c]);
			}

			function schnorr_parse_signature(sig: BufferSource): SchnorrNizkProof1 {
				const s = OS2IP(toU8(sig).slice(0, octet_scalar_length));
				const c = OS2IP(toU8(sig).slice(octet_scalar_length));
				return [c, s];
			}

			/** Sign using SHA-256 as the hash function H, with rejection sampling to fall under the group order. */
			async function schnorr_sign_sha256(sk: bigint, m: BufferSource): Promise<SchnorrNizkProof1> {
				while (true) {
					const omega = await sample_scalar(toUtf8("Schnorr.Sign"));
					const r = H0.multiply(omega);
					const c = OS2IP(await sha256(serialize([r, m])));
					if (c < Fr.ORDER) {
						const s = (omega + c * sk) % Fr.ORDER;
						return [c, s];
					}
				}
			}

			async function schnorr_sign_sha256_encode(sk: bigint, m: BufferSource): Promise<ArrayBuffer> {
				return schnorr_encode_signature(await schnorr_sign_sha256(sk, m));
			}

			/** Verify using SHA-256 as the hash function H, rejecting is the hash is greater than the group order. */
			async function schnorr_verify_sha256(pk: PointG1, sig: SchnorrNizkProof1, m: BufferSource): Promise<true> {
				const [c, s] = sig;
				const c2 = OS2IP(await sha256(serialize([H0.multiply(s).subtract(pk.multiply(c)), m])));
				if (c2 < Fr.ORDER && c == c2) {
					return true;
				}
				throw new Error("Invalid signature", { cause: { pk, H0, sig, m } });
			}

			function schnorr_verify_sha256_encoded(pk: PointG1, sig: BufferSource, m: BufferSource): Promise<true> {
				return schnorr_verify_sha256(pk, schnorr_parse_signature(sig), m);
			}

			function schnorr_re_rand_pk(pk: PointG1, r_key: bigint): PointG1 {
				return pk.add(H0.multiply(r_key));
			}

			function schnorr_adapt_sig(sig: SchnorrNizkProof1, r_key: bigint, _m: BufferSource): [bigint, bigint] {
				const [c, s] = sig;
				return [c, (s + c * r_key) % Fr.ORDER];
			}

			type SchnorrNizkProof = [bigint, bigint[]];

			/**
				Schnorr NIZK as defined in appendix F.1 of https://eprint.iacr.org/2025/1995 ,
				using:

				- hash_to_field as the hash function H,
				- the curve point encoding `point_to_octets_E1` defined in https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-serialization
				- binary concatenation for combining hash function inputs.
				*/
			async function schnorr_nizk_prove(
				M: PointG1[][],
				Y: PointG1[],
				x: bigint[],
				ctx: BufferSource,
				ikm?: BufferSource,
			): Promise<SchnorrNizkProof> {
				const m = M.length;
				const n = M[0].length;
				if (Y.length !== m || x.length !== n) {
					throw new Error("Invalid input dimensions", { cause: { M, Y, x, m, n } });
				}
				if (!all_eq(matrix_mul(M, x), Y)) {
					throw new Error("Y does not equal Mx", { cause: { M, Y, x } });
				}
				const omega = await Promise.all(range(n).map(i =>
					sample_scalar(concat(toUtf8("Schnorr.NIZK.Prove.omega."), new Uint8Array([i])), ikm)
				));
				const R = matrix_mul(M, omega);
				const c = await hash_to_scalar(
					serialize([
						...M.flatMap(mrow => mrow),
						...Y,
						...R,
						ctx,
					]),
					toUtf8("Schnorr.NIZK.Proof"),
				);
				const s: bigint[] = omega.map((o, i) => (o + c * x[i]) % Fr.ORDER);
				return [c, s];
			}

			async function schnorr_nizk_verify(
				M: PointG1[][],
				Y: PointG1[],
				sig: SchnorrNizkProof,
				ctx: BufferSource,
			): Promise<true> {
				const [c, s] = sig;
				const Ms = matrix_mul(M, s);
				const Yc = Y.map(y => y.multiply(c));
				if (c === await hash_to_scalar(
					serialize([
						...M.flatMap(mrow => mrow),
						...Y,
						...Ms.map((Msi, i) => Msi.subtract(Yc[i])),
						ctx,
					]),
					toUtf8("Schnorr.NIZK.Proof"),
				)) {
					return true;
				}
				throw new Error("Invalid signature", { cause: { M, Y, sig, ctx } });
			}


			/** IssKGen procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995 */
			async function iss_kgen(ikm?: BufferSource): Promise<[bigint, PointG2]> {
				const isk = await sample_scalar(toUtf8("IssKGen"), ikm);
				const ipk = G2.Point.BASE.multiply(isk);
				return [isk, ipk];
			}

			/** DevKGen procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995 */
			async function dev_kgen(ikm?: BufferSource): Promise<[bigint, PointG1]> {
				const dsk = await sample_scalar(toUtf8("DevKGen"), ikm);
				const dpk = H0.multiply(dsk);
				return [dsk, dpk];
			}

			/** Issue procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995 */
			async function issue(
				isk: bigint,
				dpk: PointG1,
				attrs: bigint[],
				ikm?: BufferSource,
			): Promise<[PointG1, bigint]> {
				const e = await sample_scalar(toUtf8("Issue"), ikm);
				const C = G1.Point.BASE.add(dpk).add(sumprod(Hi, attrs));
				const A = C.multiply(Fr.inv(isk + e));
				return [A, e];
			}

			/** Verify procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995 */
			async function verify(
				ipk: PointG2,
				ctx: BufferSource,
				disclosed_idx: number[],
				disclosed_attrs: bigint[],
				tau: [
					PointG1,
					SchnorrNizkProof1,
					PointG1,
					PointG1,
					PointG1,
					SchnorrNizkProof,
				],
			): Promise<true> {
				const [dpkbar, pi_se, Abar, Bbar, Cbar, pi_bbs] = tau;
				const non_disclosed_idx = range(l).filter(i => !disclosed_idx.includes(i));
				if (!(await schnorr_verify_sha256(dpkbar, pi_se, serialize([dpkbar, ctx])))) {
					throw new Error("Invalid device binding signature", { cause: { dpkbar, pi_se, ctx } });
				}
				if (disclosed_idx.length !== disclosed_attrs.length) {
					throw new Error("Invalid attributes length", { cause: { disclosed_idx, disclosed_attrs } });
				}
				if (pi_bbs[1].length !== 4 + non_disclosed_idx.length) {
					throw new Error("Invalid proof length", { cause: { pi_bbs, non_disclosed_idx } });
				}

				const Y = G1.Point.BASE.add(dpkbar).add(sumprod(disclosed_idx.map(i => Hi[i]), disclosed_attrs));

				if (
					(!Abar.is0())
					&& Fp12.eql(h(Abar, ipk), h(Bbar, G2.Point.BASE))
					&& await schnorr_nizk_verify(
						[
							[
								Cbar,
								H0,
								...non_disclosed_idx.map(j => Hi[j].negate()),
								G1.Point.ZERO,
								G1.Point.ZERO,
							],
							[
								...range(2 + non_disclosed_idx.length).map(() => G1.Point.ZERO),
								Cbar,
								Abar.negate(),
							]
						],
						[Y, Bbar],
						pi_bbs,
						ctx,
					)
				) {
					return true;
				}
				throw new Error("Invalid proof", { cause: { ipk, ctx, disclosed_idx, disclosed_attrs, dpkbar, pi_se, Abar, Bbar, Cbar, pi_bbs } });
			}

			/** VfCred procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995 */
			function vf_cred(
				ipk: PointG2,
				sigma: [PointG1, bigint],
				dpk: PointG1,
				attrs: bigint[],
			): boolean {
				const [A, e] = sigma;
				const C = G1.Point.BASE.add(dpk).add(sumprod(Hi, attrs));
				return (
					(!A.is0()) && Fp12.eql(
						h(A, ipk.add(G2.Point.BASE.multiply(e))), h(C, G2.Point.BASE))
				);
			}

			/** ShowUser1 procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995 */
			async function show_user_1(
				ipk: PointG2,
				dpk: PointG1,
				sigma: [PointG1, bigint],
				attrs: bigint[],
				ctx: BufferSource,
				disclose_idx: number[],
				ikm?: BufferSource,
			): Promise<[BbsSchnorrUst, PointG1]> {
				if (attrs.length !== Hi.length) {
					throw new Error("Wrong number of attributes", { cause: { attrs, Hi } });
				}
				if (!disclose_idx.every(d => d >= 0 && d < attrs.length)) {
					throw new Error("Invalid disclosed indexes", { cause: { disclose_idx, attrs } });
				}

				const r_key = await sample_scalar(toUtf8("ShowUser1.r_key"), ikm);
				const dpkbar = schnorr_re_rand_pk(dpk, r_key);
				const umsg = dpkbar;
				const ust: BbsSchnorrUst = [ipk, dpk, dpkbar, r_key, sigma, attrs, ctx, disclose_idx, ikm];
				return [ust, umsg];
			}

			/** ShowSE1 procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995 */
			function show_se_1(
				_ipk: PointG2,
				dsk: bigint,
				umsg: PointG1,
				ctx: BufferSource,
			): Promise<BufferSource> {
				const smsg = schnorr_sign_sha256_encode(dsk, serialize([umsg, ctx]));
				return smsg
			}

			/** ShowUser2 procedure of BBS-Schnorr proposed in https://eprint.iacr.org/2025/1995 */
			async function show_user_2(
				ust: BbsSchnorrUst,
				smsg: BufferSource,
			): Promise<[PointG1, SchnorrNizkProof1, PointG1, PointG1, PointG1, SchnorrNizkProof]> {
				const [_ipk, dpk, dpkbar, r_key, sigma, attrs, ctx, disclose_idx, ikm] = ust;
				const non_disclose_idx = range(l).filter(i => !disclose_idx.includes(i));
				const pi_se = schnorr_adapt_sig(schnorr_parse_signature(smsg), r_key, serialize([dpkbar, ctx]));
				const [A, e] = sigma;
				const r1 = await sample_scalar(toUtf8("ShowUser2.r1"), ikm);
				const r2 = await sample_scalar(toUtf8("ShowUser2.r2"), ikm);
				const C = G1.Point.BASE.add(dpk).add(sumprod(Hi, attrs));
				const Cbar = C.multiply(r1);
				const Abar = A.multiply(r2).multiply(r1);
				const Bbar = Cbar.multiply(r2).subtract(Abar.multiply(e));
				const Y = (
					G1.Point.BASE.add(dpkbar)
						.add(sumprod(
							disclose_idx.map(i => Hi[i]),
							disclose_idx.map(i => attrs[i]),
						))
				);

				const pi_bbs = await schnorr_nizk_prove(
					[
						[
							Cbar,
							H0,
							...non_disclose_idx.map(j => Hi[j].negate()),
							G1.Point.ZERO,
							G1.Point.ZERO,
						],
						[...range(2 + non_disclose_idx.length).map(() => G1.Point.ZERO), Cbar, Abar.negate()],
					],
					[Y, Bbar],
					[Fr.inv(r1), r_key, ...non_disclose_idx.map(j => attrs[j]), r2, e],
					ctx,
				);
				return [dpkbar, pi_se, Abar, Bbar, Cbar, pi_bbs];
			}

			return {
				iss_kgen,
				dev_kgen,
				issue,
				verify,
				vf_cred,
				show_user_1,
				show_se_1,
				show_user_2,
				schnorr_verify_sha256_encoded,
			};
		}

		return { api_id, Sign, Verify, ProofGen, ProofVerify, BbsSchnorr };
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-scheme-definition */
	function BlindBbs(): BlindBbsSuite {
		const api_id = toUtf8(suite.id + "BLIND_H2G_HM2S_");
		const blind_api_id = concat(toUtf8("BLIND_"), api_id);

		function create_unblind_generators(count: number): Promise<PointG1[]> {
			return create_generators(count, api_id);
		}

		function create_blind_generators(count: number): Promise<PointG1[]> {
			return create_generators(count, blind_api_id);
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-commitment-validation-and-d */
		async function deserialize_and_validate_commit(
			commitment_with_proof: BufferSource,
			blind_generators: PointG1[],
			commit_header: BufferSource,
			api_id: BufferSource,
		): Promise<[PointG1, PointG1[]]> {
			if (commitment_with_proof.byteLength === 0) {
				return [G1.Point.ZERO, []];
			}

			const [commit, commit_proof] = octets_to_commitment_with_proof(toU8(commitment_with_proof));
			if (commit_proof[1].length + commit_proof[3].length + 1 !== blind_generators.length) {
				throw new Error(`Invalid proof length: expected ${blind_generators.length - 1} blind attributes, was ${commit_proof[1].length + commit_proof[3].length}`, { cause: { commit_proof, blind_generators } });
			}
			await CoreCommitVerify(commit, commit_proof, blind_generators, commit_header, api_id);
			return commit;
		}

		async function Commit(
			committed_messages: BufferSource[] | null,
			commit_header: BufferSource | null,
		): Promise<[BufferSource, bigint]> {
			committed_messages = committed_messages ?? [];
			commit_header = commit_header ?? new Uint8Array([]);
			const [state,] = await CommitInit(committed_messages, null, commit_header);
			return CommitFinalize(state, null);
		}

		type CommitState = [PointG1[], bigint, PointG1, bigint, bigint[], bigint];
		async function CommitInit(
			committed_messages: BufferSource[] | null,
			committed_points: BufferSource[] | null,
			commit_header: BufferSource | null,
		): Promise<[BufferSource, bigint]> {
			committed_messages = committed_messages ?? [];
			committed_points = committed_points ?? [];
			commit_header = commit_header ?? new Uint8Array([]);

			const committed_message_scalars = await messages_to_scalars(committed_messages, api_id);
			const blind_generators = await create_blind_generators(committed_message_scalars.length + 1);
			const [state, secret_prover_blind] = await CoreCommitInit(
				blind_generators,
				committed_message_scalars,
				committed_points.map(octets_to_point_E1),
				commit_header,
				api_id,
			);
			return [commit_state_to_octets(state), secret_prover_blind];
		}

		async function CommitFinalize(
			state: BufferSource,
			committed_point_proofs: BufferSource[] | null,
		): Promise<[BufferSource, bigint]> {
			committed_point_proofs = committed_point_proofs ?? [];
			return CoreCommitFinalize(
				octets_to_commit_state(state),
				committed_point_proofs.map(octs => {
					const [k_hat, c] = split_at(toU8(octs), octet_scalar_length);
					return [OS2IP(k_hat), OS2IP(c)];
				}),
			);
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-blind-signature-generation */
		async function BlindSign(
			SK: bigint,
			PK: BufferSource,
			commitment_with_proof: BufferSource | null,
			commit_header: BufferSource | null,
			header: BufferSource | null,
			messages: BufferSource[] | null,
		): Promise<BufferSource> {
			commitment_with_proof = commitment_with_proof ?? new Uint8Array([]);
			commit_header = commit_header ?? new Uint8Array([]);
			header = header ?? new Uint8Array([]);
			messages = messages ?? [];

			const L = messages.length;
			let M = commitment_with_proof.byteLength;
			if (M !== 0) {
				M = M - octet_point_length - 2 * octet_scalar_length;
			}
			M = M / octet_scalar_length;
			if (M < 0) {
				throw new Error(`Commitment too short: expected at least ${octet_point_length + octet_scalar_length} octets, was ${commitment_with_proof.byteLength}`, { cause: { commitment_with_proof } });
			}

			const generators = await create_unblind_generators(L + 1);
			const [Q_1, ...H_Points] = generators;
			const blind_generators = await create_blind_generators(M + 1);
			const [Q_2, ...J] = blind_generators;
			const domain = await calculate_domain(PK, Q_1, [...H_Points, Q_2, ...J], header, api_id);
			const [commit, committed_points] = await deserialize_and_validate_commit(commitment_with_proof, blind_generators, commit_header, api_id);
			const message_scalars = await messages_to_scalars(messages, api_id);
			const res = B_calculate(generators, domain, commit.add(sum(committed_points)), message_scalars);
			const [B] = res;
			// const blind_sig = FinalizeBlindSign(SK, PK, B, generators, blind_generators, header, api_id);
			const blind_sig = FinalizeBlindSign(SK, domain, B, api_id);
			return blind_sig;
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-blind-signature-verificatio */
		async function VerifyBlindSign(
			PK: BufferSource,
			signature: BufferSource,
			header: BufferSource | null,
			messages: BufferSource[] | null,
			committed_messages: BufferSource[] | null,
			committed_points: BufferSource[] | null,
			secret_prover_blind: bigint | null,
		): Promise<true> {
			header = header ?? new Uint8Array([]);
			messages = messages ?? [];
			committed_messages = committed_messages ?? [];
			committed_points = committed_points ?? [];
			secret_prover_blind = secret_prover_blind ?? 0n;
			const [message_scalars, generators] = await prepare_parameters(
				messages,
				committed_messages,
				messages.length + 1,
				committed_messages.length + committed_points.length + 1,
				secret_prover_blind,
				api_id,
			);
			const res = await BlindCoreVerify(
				PK,
				signature,
				generators,
				header,
				message_scalars,
				committed_points.map(octets_to_point_E1),
				api_id,
			);
			return res;
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-proof-generation */
		async function BlindProofGen(
			PK: BufferSource,
			signature: BufferSource,
			header: BufferSource | null,
			ph: BufferSource | null,
			messages: BufferSource[] | null,
			committed_messages: BufferSource[] | null,
			disclosed_indexes: number[] | null,
			disclosed_commitment_indexes: number[] | null,
			secret_prover_blind: bigint | null,
		): Promise<BufferSource> {
			header = header ?? new Uint8Array([]);
			ph = ph ?? new Uint8Array([]);
			messages = messages ?? [];
			committed_messages = committed_messages ?? [];
			disclosed_indexes = disclosed_indexes ?? [];
			disclosed_commitment_indexes = disclosed_commitment_indexes ?? [];
			secret_prover_blind = secret_prover_blind ?? 0n;

			const L = messages.length;
			const M = committed_messages.length;
			if (disclosed_indexes.length > L) {
				throw new Error("Too many disclosed indexes", { cause: { messages, disclosed_indexes } });
			}
			disclosed_indexes.forEach(i => {
				if (i < 0 || i >= L) {
					throw new Error(`Invalid disclosed index: ${i}`, { cause: { i, disclosed_indexes, messages } });
				}
			});
			if (disclosed_commitment_indexes.length > M) {
				throw new Error("Too many disclosed commitment indexes", { cause: { committed_messages, disclosed_commitment_indexes } });
			}
			disclosed_commitment_indexes.forEach(j => {
				if (j < 0 || j >= M) {
					throw new Error(`Invalid disclosed commitment index: ${j}`, { cause: { j, disclosed_commitment_indexes, committed_messages } });
				}
			});

			const [message_scalars, generators] = await prepare_parameters(
				messages,
				committed_messages,
				messages.length + 1,
				committed_messages.length + 1,
				secret_prover_blind,
				api_id,
			);
			const indexes = [
				...disclosed_indexes,
				...disclosed_commitment_indexes.map(j => j + L + 1),
			];
			const proof = await CoreProofGen(PK, signature, generators, header, ph, message_scalars, indexes, api_id);
			return proof;
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-proof-verification */
		async function BlindProofVerify(
			PK: BufferSource,
			proof: BufferSource,
			header: BufferSource | null,
			ph: BufferSource | null,
			L: number,
			disclosed_messages: BufferSource[] | null,
			disclosed_committed_messages: BufferSource[] | null,
			disclosed_indexes: number[] | null,
			disclosed_committed_indexes: number[] | null,
		): Promise<true> {
			header = header ?? new Uint8Array([]);
			ph = ph ?? new Uint8Array([]);
			disclosed_messages = disclosed_messages ?? [];
			disclosed_committed_messages = disclosed_committed_messages ?? [];
			disclosed_indexes = disclosed_indexes ?? [];
			disclosed_committed_indexes = disclosed_committed_indexes ?? [];

			const proof_len_floor = 3 * octet_point_length + 4 * octet_scalar_length;
			if (proof.byteLength < proof_len_floor) {
				throw new Error(`Proof too short: expected at least ${proof_len_floor} octets, was ${proof.byteLength}`, { cause: { proof, proof_len_floor } });
			}
			const U = Math.floor((proof.byteLength - proof_len_floor) / octet_scalar_length);
			const total_no_messages = disclosed_indexes.length + disclosed_committed_indexes.length + U;
			const M = total_no_messages - L;

			const [message_scalars, generators] = await prepare_parameters(
				disclosed_messages,
				disclosed_committed_messages,
				L + 1,
				M,
				null,
				api_id,
			);
			const indexes = [
				...disclosed_indexes,
				...disclosed_committed_indexes.map(j => j + L + 1),
			];
			const result = await CoreProofVerify(PK, proof, generators, header, ph, message_scalars, indexes, api_id);
			return result;
		}

		function commit_state_to_octets(state: CommitState): BufferSource {
			const [K, secret_prover_blind, C, s_hat, m_hat, challenge] = state;
			const M = m_hat.length;
			const N = K.length;
			return serialize([M, N, ...K, secret_prover_blind, C, s_hat, ...m_hat, challenge]);
		}

		function octets_to_commit_state(octets: BufferSource): CommitState {
			const state_len_floor = 8 + 8 + octet_point_length + 3 * octet_scalar_length;
			if (octets.byteLength < state_len_floor) {
				throw new Error(`State too short: expected at least ${state_len_floor} octets, was ${octets.byteLength}`, { cause: { octets } });
			}
			const [[M_octs, N_octs], rest] = split_sections(toU8(octets), [8, 8]);
			const M = Number(OS2IP(M_octs));
			const N = Number(OS2IP(N_octs));
			const state_len = state_len_floor + N * octet_point_length + M * octet_scalar_length;
			if (octets.byteLength !== state_len) {
				throw new Error(`Invalid state length: expected ${state_len} octets, was ${octets.byteLength}`, { cause: { octets, state_len } });
			}
			const [[K_octs, spb_octs, C_octs, s_hat_octs, m_hat_octs, challenge_octs], tail] = split_sections(
				rest,
				[N * octet_point_length, octet_scalar_length, octet_point_length, octet_scalar_length, M * octet_scalar_length, octet_scalar_length],
			);
			if (tail.byteLength !== 0) {
				throw new Error("Trailing octets", { cause: { octets, state_len, tail } });
			}

			return [
				split_sections(K_octs, range(N).map(() => octet_point_length))[0].map(octets_to_point_E1),
				OS2IP(spb_octs),
				octets_to_point_E1(C_octs),
				OS2IP(s_hat_octs),
				split_sections(m_hat_octs, range(M).map(() => octet_scalar_length))[0].map(OS2IP),
				OS2IP(challenge_octs),
			];
		}

		async function CoreCommitInit(
			blind_generators: PointG1[],
			committed_scalars: bigint[],
			committed_points: PointG1[],
			commit_header: BufferSource,
			api_id: BufferSource,
		): Promise<[CommitState, bigint]> {
			const M = committed_scalars.length;
			const N = committed_points.length;
			if (blind_generators.length !== M + N + 1) {
				throw new Error("Invalid number of generators, messages, or points", { cause: { blind_generators, committed_scalars, committed_points } });
			}
			// const [Q2, ...J] = blind_generators;
			const msg = committed_scalars;

			const [secret_prover_blind, s_tilde, ...m_tilde] = await calculate_random_scalars(M + 2);
			const C = sumprod(blind_generators.slice(0, M + 1), [secret_prover_blind, ...msg]);
			const Cbar = sumprod(blind_generators.slice(0, M + 1), [s_tilde, ...m_tilde]);
			const challenge = await calculate_blind_challenge(C, Cbar, blind_generators, committed_points, commit_header, api_id);
			const s_hat = Fr.add(s_tilde, Fr.mul(secret_prover_blind, challenge));
			const m_hat = m_tilde.map((m_tilde_i, i) => (Fr.add(m_tilde_i, Fr.mul(msg[i], challenge))));

			const state: CommitState = [
				committed_points,
				secret_prover_blind,
				C,
				s_hat,
				m_hat,
				challenge,
			];
			return [state, challenge];
		}

		async function CoreCommitProve(
			committed_point_secret: bigint,
			generator: PointG1,
			challenge: BufferSource,
		): Promise<[bigint, bigint]> {
			const challenge_dst = new Uint8Array([]);

			const [k_tilde] = await calculate_random_scalars(1);
			const R = generator.multiply(k_tilde);
			const c = await hash_to_scalar(serialize([R, challenge]), challenge_dst);
			const k_hat = Fr.add(k_tilde, Fr.mul(c, committed_point_secret));
			return [k_hat, c];
		}

		async function CoreCommitFinalize(
			state: CommitState,
			committed_point_proofs: [bigint, bigint][],
		): Promise<[BufferSource, bigint]> {
			const [committed_points, secret_prover_blind, C, s_hat, m_hat, challenge] = state;
			const N = committed_points.length;

			if (committed_point_proofs.length !== N) {
				throw new Error("Invalid number of point proofs", { cause: { committed_points, committed_point_proofs } });
			}

			const commit_with_proof = commitment_with_proof_to_octets(
				[C, committed_points],
				[s_hat, m_hat, challenge, committed_point_proofs],
			);
			return [commit_with_proof, secret_prover_blind];
		}

		async function CoreCommitVerify(
			[commitment, committed_points]: [PointG1, PointG1[]],
			commitment_proof: [bigint, bigint[], bigint, [bigint, bigint][]],
			blind_generators: PointG1[],
			commit_header: BufferSource,
			api_id: BufferSource,
		): Promise<true> {
			const [s_hat, commitments, cp, committed_point_proofs] = commitment_proof;
			const M = commitments.length;
			const N = committed_point_proofs.length;
			const m_hat = commitments;
			if (blind_generators.length !== M + N + 1) {
				throw new Error("Invalid number of generators, commitments or point proofs", { cause: { blind_generators, commitments, committed_point_proofs } });
			}

			const Cbar = sumprod([...blind_generators, commitment], [s_hat, ...m_hat, Fr.neg(cp)]);
			const cv = await calculate_blind_challenge(commitment, Cbar, blind_generators, committed_points, commit_header, api_id);
			if (cv === cp) {
				if (
					(await Promise.all(committed_point_proofs.map(async ([k_hat, c], j) => {
						const J = blind_generators[1 + M + j];
						const K = committed_points[j];
						const R_hat = J.multiply(k_hat).add(K.multiply(Fr.neg(c)));
						const cv = await hash_to_scalar(serialize([R_hat, cp]), new Uint8Array([]));
						if (cv === c) {
							return true;
						}
						throw new Error("Invalid point proof", { cause: { J, K, k_hat, c, R_hat, cv } });
					}))).every(result => result === true)
				) {
					return true;
				}
			}
			throw new Error("Invalid proof", { cause: { commitment, commitment_proof, blind_generators, committed_points, commit_header, api_id } });
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-finalize-blind-sign */
		async function FinalizeBlindSign(
			SK: bigint,
			// PK: BufferSource,
			domain: bigint,
			B: PointG1,
			// generators: PointG1[],
			// blind_generators: PointG1[],
			// header: BufferSource,
			api_id: BufferSource,
		): Promise<BufferSource> {
			const signature_dst = concat(api_id, toUtf8("H2S_"));

			// const L = generators.length - 1;
			// const M = blind_generators.length - 1;
			// if (L < 0 || M < 0) {
			// 	throw new Error("Invalid number of generators", { cause: { generators, blind_generators } });
			// }
			// const [Q_1, ...H_Points] = generators;
			// const [Q_2, ...J] = blind_generators;

			// const domain = await calculate_domain(PK, Q_1, [...H_Points, Q_2, ...J], header, api_id);
			const e_octs = serialize([SK, B, domain]);
			const e = await hash_to_scalar(e_octs, signature_dst);
			const A = B.multiply(Fr.inv(Fr.add(SK, e)));
			return signature_to_octets(A, e);
		}

		async function BlindCoreVerify(
			PK: BufferSource,
			signature: BufferSource,
			generators: PointG1[],
			header: BufferSource,
			messages: bigint[],
			committed_points: PointG1[],
			api_id: BufferSource,
		): Promise<true> {
			const [A, e] = octets_to_signature(signature);
			const W = octets_to_pubkey(PK);
			const M = messages.length;
			const N = committed_points.length;
			if (generators.length !== M + N + 1) {
				throw new Error("Messages, points and generators not of matching lengths", { cause: { messages, committed_points, generators } });
			}
			const Q_1 = generators[0];
			const H_Points = generators.slice(1);

			const domain = await calculate_domain(PK, Q_1, H_Points, header, api_id);
			const B = P1.add(Q_1.multiply(domain)).add(sumprod(H_Points, messages).add(sum(committed_points)));
			if (!Fp12.eql(
				Fp12.mul(h(A, W.add(G2.Point.BASE.multiply(e))), h(B, G2.Point.BASE.negate())),
				Fp12.ONE,
			)) {
				throw new Error("Invalid signature", { cause: { PK, signature, header, messages } });
			}
			return true;
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-prepare-parameters */
		async function prepare_parameters(
			messages: BufferSource[],
			committed_messages: BufferSource[],
			generators_number: number,
			blind_generators_number: number,
			secret_prover_blind: bigint | null,
			api_id: BufferSource,
		): Promise<[bigint[], PointG1[]]> {
			secret_prover_blind = secret_prover_blind ?? 0n;

			const message_scalars = await messages_to_scalars(messages, api_id);
			const committed_message_scalars = [
				...(
					secret_prover_blind !== 0n
						? [secret_prover_blind]
						: []
				),
				...await messages_to_scalars(committed_messages, api_id),
			];
			const generators = await create_unblind_generators(generators_number);
			const blind_generators = await create_blind_generators(blind_generators_number);
			return [
				[...message_scalars, ...committed_message_scalars],
				[...generators, ...blind_generators],
			];
		}

		/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-calculate-b-value */
		function B_calculate(
			generators: PointG1[],
			domain: bigint,
			commitment: PointG1,
			message_scalars: bigint[],
		): [PointG1] {
			const L = message_scalars.length;
			if (generators.length !== L + 1) {
				throw new Error("Messages and generators not of matching lengths", { cause: { message_scalars, generators } });
			}
			const [Q_1, ...H_Points] = generators;
			const msg = message_scalars;
			const B = sumprod([P1, Q_1, ...H_Points, commitment], [1n, domain, ...msg, 1n]);
			if (B.is0()) {
				throw new Error("B must not be Identity_G1", { cause: { generators, commitment, message_scalars } });
			}
			return [B];
		}

		function calculate_blind_challenge(
			C: PointG1,
			Cbar: PointG1,
			generators: PointG1[],
			committed_points: PointG1[],
			commit_header: BufferSource,
			api_id: BufferSource,
		): Promise<bigint> {
			const blind_challenge_dst = concat(api_id, toUtf8("H2S_"));

			if (generators.length === 0) {
				throw new Error("No generators", { cause: { generators } });
			}
			const N = committed_points.length;
			const M = generators.length - 1 - N;

			const c_arr = [
				M,
				N,
				...generators,
				...committed_points,
				C,
				Cbar,
				I2OSP(commit_header.byteLength, 8),
				commit_header,
			];
			const c_octs = serialize(c_arr);
			return hash_to_scalar(c_octs, blind_challenge_dst);
		}

		function commitment_with_proof_to_octets(
			commitment: [PointG1, PointG1[]],
			proof: [bigint, bigint[], bigint, [bigint, bigint][]],
		): BufferSource {
			const [C, K] = commitment;
			const [s_hat, m_hat, challenge, point_proofs] = proof;
			const proof_octs = serialize([
				m_hat.length,
				K.length,
				C,
				...K,
				s_hat,
				...m_hat,
				challenge,
				...point_proofs.flat(),
			]);
			return proof_octs;
		}

		function octets_to_commitment_with_proof(
			commitment_octs: Uint8Array,
		): [[PointG1, PointG1[]], [bigint, bigint[], bigint, [bigint, bigint][]]] {
			const commit_len_floor = octet_point_length + 2 * octet_scalar_length;
			if (commitment_octs.byteLength < commit_len_floor) {
				throw new Error(`Commitment with proof too short: expected at least ${commit_len_floor} octets, was ${commitment_octs.byteLength}`, { cause: { commitment_octs, commit_len_floor } });
			}

			const [[M_octs, N_octs], MN_tail] = split_sections(commitment_octs, [8, 8]);
			const M = Number(OS2IP(M_octs));
			const N = Number(OS2IP(N_octs));

			const commitment_length = (
				8 + 8
				+ octet_point_length
				+ N * octet_point_length
				+ octet_scalar_length
				+ M * octet_scalar_length
				+ octet_scalar_length
				+ N * 2 * octet_scalar_length
			);
			if (commitment_octs.byteLength !== commitment_length) {
				throw new Error(`Invalid length of commitment with proof: expected ${commitment_length} octets, was ${commitment_octs.byteLength}`, { cause: { commitment_octs } });
			}

			const [[C_octets, K_octets, s_hat_octs, m_hats_octs, challenge_octs, point_proofs_octs], tail] = split_sections(
				MN_tail,
				[
					octet_point_length,
					N * octet_point_length,
					octet_scalar_length,
					M * octet_scalar_length,
					octet_scalar_length,
					N * 2 * octet_point_length,
				],
			);
			if (tail.byteLength !== 0) {
				throw new Error("Trailing octets", { cause: { commitment_octs, tail } });
			}

			const C = octets_to_point_E1(C_octets);
			if (C.is0()) {
				throw new Error("C must not be Identity_G1", { cause: { commitment_octs } });
			}
			const K = split_sections(K_octets, range(N).map(() => octet_point_length))[0].map(octets_to_point_E1);

			const s_hat = OS2IP(s_hat_octs);
			const m_hat = split_sections(m_hats_octs, range(M).map(() => octet_scalar_length))[0].map(OS2IP);
			const challenge = OS2IP(challenge_octs);

			const [k_hat_and_c_octs,] = split_sections(point_proofs_octs, range(N).map(() => 2 * octet_scalar_length));
			const point_proofs: [bigint, bigint][] = k_hat_and_c_octs.map((octs) => {
				const [k_hat_octs, c_octs] = split_at(octs, octet_scalar_length);
				return [OS2IP(k_hat_octs), OS2IP(c_octs)];
			});

			return [[C, K], [s_hat, m_hat, challenge, point_proofs]];
		}

		return {
			api_id,
			Commit,
			CommitInit,
			CoreCommitProve,
			CommitFinalize,
			BlindSign,
			VerifyBlindSign,
			BlindProofGen,
			BlindProofVerify,
			create_unblind_generators,
			create_blind_generators,
		};
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-coresign */
	async function CoreSign(
		SK: bigint,
		PK: BufferSource,
		generators: PointG1[],
		header: BufferSource,
		messages: bigint[],
		api_id: BufferSource,
	): Promise<BufferSource> {
		const hash_to_scalar_dst = concat(api_id, toUtf8("H2S_"));

		const L = messages.length;
		if (generators.length !== L + 1) {
			throw new Error("Messages and generators not of matching lengths", { cause: { messages, generators } });
		}
		const Q_1 = generators[0];
		const H_Points = generators.slice(1);

		const domain = await calculate_domain(PK, Q_1, H_Points, header, api_id);
		const e = await hash_to_scalar(serialize([SK, ...messages, domain]), hash_to_scalar_dst);
		const B = P1.add(Q_1.multiply(domain)).add(sumprod(H_Points, messages));
		const A = B.multiply(Fr.inv(SK + e));
		return signature_to_octets(A, e);
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-coreverify */
	async function CoreVerify(
		PK: BufferSource,
		signature: BufferSource,
		generators: PointG1[],
		header: BufferSource,
		messages: bigint[],
		api_id: BufferSource,
	): Promise<true> {
		const [A, e] = octets_to_signature(signature);
		const W = octets_to_pubkey(PK);
		const L = messages.length;
		if (generators.length !== L + 1) {
			throw new Error("Messages and generators not of matching lengths", { cause: { messages, generators } });
		}
		const Q_1 = generators[0];
		const H_Points = generators.slice(1);

		const domain = await calculate_domain(PK, Q_1, H_Points, header, api_id);
		const B = P1.add(Q_1.multiply(domain)).add(sumprod(H_Points, messages));
		if (!Fp12.eql(
			Fp12.mul(h(A, W.add(G2.Point.BASE.multiply(e))), h(B, G2.Point.BASE.negate())),
			Fp12.ONE,
		)) {
			throw new Error("Invalid signature", { cause: { PK, signature, header, messages } });
		}
		return true;
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-coreproofgen */
	async function CoreProofGen(
		PK: BufferSource,
		signature: BufferSource,
		generators: PointG1[],
		header: BufferSource,
		ph: BufferSource,
		messages: bigint[],
		disclosed_indexes: number[],
		api_id: BufferSource,
	): Promise<BufferSource> {
		const signature_result = octets_to_signature(signature);
		const [_A, e] = signature_result;
		const L = messages.length;
		const R = disclosed_indexes.length;
		if (R > L) {
			throw new Error("Too many disclosed indexes", { cause: { messages, disclosed_indexes } });
		}
		const U = L - R;
		for (let i of disclosed_indexes) {
			if (i < 0 || i > L - 1) {
				throw new Error(`Invalid disclosed index: ${i}`, { cause: { messages, disclosed_indexes, i } });
			}
		}
		const disclosed_set = new Set(disclosed_indexes);
		const undisclosed_indexes = messages.map((_, i) => i).filter(i => !disclosed_set.has(i));
		const disclosed_messages = disclosed_indexes.map(i => messages[i]);
		const undisclosed_messages = undisclosed_indexes.map(i => messages[i]);

		const random_scalars = await calculate_random_scalars(5 + U);
		const init_res = await ProofInit(PK, signature_result, generators, random_scalars, header, messages, undisclosed_indexes, api_id);
		const challenge = await ProofChallengeCalculate(init_res, disclosed_messages, disclosed_indexes, ph, api_id);
		const proof = ProofFinalize(init_res, challenge, e, random_scalars, undisclosed_messages);
		return proof;
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-coreproofverify */
	async function CoreProofVerify(
		PK: BufferSource,
		proof: BufferSource,
		generators: PointG1[],
		header: BufferSource,
		ph: BufferSource,
		disclosed_messages: bigint[],
		disclosed_indexes: number[],
		api_id: BufferSource,
	): Promise<true> {
		const proof_result = octets_to_proof(proof);
		const [Abar, Bbar, _D, _ehat, _r1hat, _r3hat, _commitments, cp] = proof_result;
		const W = octets_to_pubkey(PK);

		const init_res = await ProofVerifyInit(PK, proof_result, generators, header, disclosed_messages, disclosed_indexes, api_id);
		const challenge = await ProofChallengeCalculate(init_res, disclosed_messages, disclosed_indexes, ph, api_id);
		if (cp !== challenge) {
			throw new Error(`Invalid proof: incorrect challenge: expected ${challenge}, was ${cp}`, { cause: { proof } })
		}
		if (!Fp12.eql(
			Fp12.mul(h(Abar, W), h(Bbar, G2.Point.BASE.negate())),
			Fp12.ONE,
		)) {
			throw new Error("Invalid proof: incorrect pairing", { cause: { proof } })
		}
		return true;
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-proof-initialization */
	async function ProofInit(
		PK: BufferSource,
		signature: [PointG1, bigint],
		generators: PointG1[],
		random_scalars: bigint[],
		header: BufferSource,
		messages: bigint[],
		undisclosed_indexes: number[],
		api_id: BufferSource,
	): Promise<[PointG1, PointG1, PointG1, PointG1, PointG1, bigint]> {
		const [A, e] = signature;
		const L = messages.length;
		const U = undisclosed_indexes.length;
		if (random_scalars.length !== U + 5) {
			throw new Error(`Wrong number of random scalars: expected ${U + 5}, got ${random_scalars.length}`, { cause: { random_scalars, undisclosed_indexes } });
		}
		const [r1, r2, etil, r1til, r3til] = random_scalars.slice(0, 5);
		const mtilj = random_scalars.slice(5);

		if (generators.length !== L + 1) {
			throw new Error(`Wrong number of generators: expected ${L + 1}, got ${generators.length}`, { cause: { generators, messages } });
		}
		const Q1 = generators[0];
		const MsgGenerators = generators.slice(1);
		const Hi = MsgGenerators;
		const Hj = undisclosed_indexes.map(j => MsgGenerators[j]);

		for (let i of undisclosed_indexes) {
			if (i < 0 || i > L - 1) {
				throw new Error(`Invalid undisclosed index: ${i}`, { cause: { messages, undisclosed_indexes, i } });
			}
		}
		if (U > L) {
			throw new Error("Invalid number of undisclosed indexes", { cause: { messages, undisclosed_indexes, L, U } });
		}
		const domain = await calculate_domain(PK, Q1, Hi, header, api_id);
		const B = P1.add(Q1.multiply(domain)).add(sumprod(Hi, messages));
		const D = B.multiply(r2);
		const Abar = A.multiply(Fr.mul(r1, r2));
		const Bbar = D.multiply(r1).subtract(Abar.multiply(e));

		const T1 = Abar.multiply(etil).add(D.multiply(r1til));
		const T2 = D.multiply(r3til).add(sumprod(Hj, mtilj));
		return [Abar, Bbar, D, T1, T2, domain];
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-proof-finalization */
	function ProofFinalize(
		init_res: [PointG1, PointG1, PointG1, PointG1, PointG1, bigint],
		challenge: bigint,
		e_value: bigint,
		random_scalars: bigint[],
		undisclosed_messages: bigint[],
	): BufferSource {
		const U = undisclosed_messages.length;
		if (random_scalars.length !== U + 5) {
			throw new Error(`Wrong number of random scalars: expected ${U + 5}, got ${random_scalars.length}`, { cause: { random_scalars, undisclosed_messages } });
		}
		const [r1, r2, etil, r1til, r3til] = random_scalars.slice(0, 5);
		const mtilj = random_scalars.slice(5);
		const [Abar, Bbar, D] = init_res;

		const r3 = Fr.inv(r2);
		const ehat = Fr.add(etil, Fr.mul(e_value, challenge));
		const r1hat = Fr.sub(r1til, Fr.mul(r1, challenge));
		const r3hat = Fr.sub(r3til, Fr.mul(r3, challenge));
		const mhatj = mtilj.map((mtilj, j) => Fr.add(mtilj, Fr.mul(undisclosed_messages[j], challenge)));
		const proof: [PointG1, PointG1, PointG1, bigint, bigint, bigint, bigint[], bigint] = [Abar, Bbar, D, ehat, r1hat, r3hat, mhatj, challenge];
		return proof_to_octets(proof);
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-proof-verification-initiali */
	async function ProofVerifyInit(
		PK: BufferSource,
		proof: [PointG1, PointG1, PointG1, bigint, bigint, bigint, bigint[], bigint],
		generators: PointG1[],
		header: BufferSource,
		disclosed_messages: bigint[],
		disclosed_indexes: number[],
		api_id: BufferSource,
	): Promise<[PointG1, PointG1, PointG1, PointG1, PointG1, bigint]> {
		const [Abar, Bbar, D, ehat, r1hat, r3hat, commitments, c] = proof;
		const U = commitments.length;
		const R = disclosed_indexes.length;
		const L = R + U;
		for (let i of disclosed_indexes) {
			if (i < 0 || i > L - 1) {
				throw new Error(`Invalid disclosed index: ${i}`, { cause: { disclosed_indexes, i } });
			}
		}
		const disclosed_indexes_set = new Set(disclosed_indexes);
		const undisclosed_indexes = [...commitments, ...disclosed_messages].map((_, j) => j).filter(j => !disclosed_indexes_set.has(j));
		if (disclosed_messages.length !== R) {
			throw new Error("Disclosed messages and indexes not of matching lengths", { cause: { disclosed_messages, disclosed_indexes } });
		}

		if (generators.length !== L + 1) {
			throw new Error("Messages and generators not of matching lengths", { cause: { proof, generators } });
		}
		const Q1 = generators[0];
		const MsgGenerators = generators.slice(1);
		const H_Points = MsgGenerators;
		const Hi_Points = disclosed_indexes.map(i => MsgGenerators[i]);
		const Hj_Points = undisclosed_indexes.map(j => MsgGenerators[j]);

		const domain = await calculate_domain(PK, Q1, H_Points, header, api_id);

		const T1 = Bbar.multiply(c).add(Abar.multiply(ehat)).add(D.multiply(r1hat));
		const Bv = P1.add(Q1.multiply(domain)).add(sumprod(Hi_Points, disclosed_messages));
		const T2 = Bv.multiply(c).add(D.multiply(r3hat)).add(sumprod(Hj_Points, commitments));

		return [Abar, Bbar, D, T1, T2, domain];
	}

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-challenge-calculation */
	async function ProofChallengeCalculate(
		init_res: [PointG1, PointG1, PointG1, PointG1, PointG1, bigint],
		disclosed_messages: bigint[],
		disclosed_indexes: number[],
		ph: BufferSource,
		api_id: BufferSource,
	): Promise<bigint> {
		const hash_to_scalar_dst = concat(api_id, toUtf8("H2S_"));

		const R = disclosed_indexes.length;
		if (disclosed_messages.length !== R) {
			throw new Error("Disclosed messages and indexes not of matching lengths", { cause: { disclosed_messages, disclosed_indexes } });
		}
		const [Abar, Bbar, D, T1, T2, domain] = init_res;

		if (R > Math.pow(2, 64) - 1) {
			throw new Error("Too many disclosed indexes", { cause: { disclosed_indexes } });
		}
		if (ph.byteLength > Math.pow(2, 64) - 1) {
			throw new Error("Presentation header too long", { cause: { ph } });
		}

		const i_msg = disclosed_indexes.map((i, j) => [i, disclosed_messages[j]]).flat(1);
		const c_arr = [R, ...i_msg, Abar, Bbar, D, T1, T2, domain];
		const c_octs = concat(serialize(c_arr), I2OSP(ph.byteLength, 8), ph);
		return await hash_to_scalar(c_octs, hash_to_scalar_dst);
	}


	return {
		params: suite,
		hash_to_scalar,
		messages_to_scalars,
		create_generators,
		KeyGen,
		SkToPk,
		Bbs: Bbs(toUtf8(suite.id + "H2G_HM2S_")),
		BlindBbs: BlindBbs(),
	};
}

export type PointG1 = WeierstrassPoint<bigint>;
type PointG2 = WeierstrassPoint<Fp2>;
type HashToScalarFunc = (msg_octets: BufferSource, dst: BufferSource) => Promise<bigint>;
type MessagesToScalarsFunc = (messages: BufferSource[], api_id: BufferSource) => Promise<bigint[]>;
type CreateGeneratorsFunc = (count: number, api_id: BufferSource) => Promise<PointG1[]>;
type KeyGenFunction = (key_material: BufferSource, key_info: BufferSource | null, key_dst: BufferSource | null) => Promise<bigint>;
type SkToPkFunction = (SK: bigint) => BufferSource;
type SignFunction = (SK: bigint, PK: BufferSource, header: BufferSource | null, messages: BufferSource[] | null) => Promise<BufferSource>;
type VerifyFunction = (PK: BufferSource, signature: BufferSource, header: BufferSource | null, messages: BufferSource[] | null) => Promise<true>;
type ProofGenFunction = (PK: BufferSource, signature: BufferSource, header: BufferSource | null, ph: BufferSource | null, messages: BufferSource[] | null, disclosed_indexes: number[] | null) => Promise<BufferSource>;
type ProofVerifyFunction = (PK: BufferSource, proof: BufferSource, header: BufferSource | null, ph: BufferSource | null, disclosed_messages: BufferSource[] | null, disclosed_indexes: number[] | null) => Promise<true>;


export type SuiteId = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';

type CreateGeneratorsDsts = {
	sig_generator_seed: BufferSource,
	sig_generator_dst: BufferSource,
	message_generator_seed: BufferSource,
};

export type SuiteParams = {
	id: SuiteId,
	octet_scalar_length: number,
	octet_point_length: number,
	hash_to_curve_suite: HashToCurveSuite,
	hash_to_curve_g1: (msg: BufferSource, DST: BufferSource) => PointG1,
	expand_len: number,
	curves: BlsCurvePair,
	P1: PointG1,
	create_generators_dsts?: CreateGeneratorsDsts,
	mocked_random_scalars_params?: { SEED: BufferSource, DST: BufferSource },
}

type SchnorrNizkProof1 = [bigint, bigint];
type SchnorrNizkProof = [bigint, bigint[]];

type BbsSuite = {
	api_id: BufferSource,

	Sign: SignFunction,
	Verify: VerifyFunction,
	ProofGen: ProofGenFunction,
	ProofVerify: ProofVerifyFunction,

	BbsSchnorr: (options: BbsSchnorrOptions) => Promise<BbsSchnorrSuite>,
}

type BlindBbsSuite = {
	api_id: BufferSource,

	Commit(
		committed_messages: BufferSource[] | null,
		commit_header: BufferSource | null,
	): Promise<[BufferSource, bigint]>;

	CommitInit(
		committed_messages: BufferSource[] | null,
		committed_points: BufferSource[] | null,
		commit_header: BufferSource | null,
	): Promise<[BufferSource, bigint]>;

	CoreCommitProve(
		committed_point_secret: bigint,
		generator: PointG1,
		challenge: BufferSource,
	): Promise<[bigint, bigint]>;

	CommitFinalize(
		state: BufferSource,
		committed_point_proofs: BufferSource[] | null,
	): Promise<[BufferSource, bigint]>;

	BlindSign(
		SK: bigint,
		PK: BufferSource,
		commitment_with_proof: BufferSource | null,
		commit_header: BufferSource | null,
		header: BufferSource | null,
		messages: BufferSource[] | null,
	): Promise<BufferSource>;

	VerifyBlindSign(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		messages: BufferSource[] | null,
		committed_messages: BufferSource[] | null,
		committed_points: BufferSource[] | null,
		secret_prover_blind: bigint | null,
	): Promise<true>;

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-proof-generation */
	BlindProofGen(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		messages: BufferSource[] | null,
		committed_messages: BufferSource[] | null,
		disclosed_indexes: number[] | null,
		disclosed_commitment_indexes: number[] | null,
		secret_prover_blind: bigint | null,
	): Promise<BufferSource>;

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-proof-verification */
	BlindProofVerify(
		PK: BufferSource,
		proof: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		L: number,
		disclosed_messages: BufferSource[] | null,
		disclosed_committed_messages: BufferSource[] | null,
		disclosed_indexes: number[] | null,
		disclosed_committed_indexes: number[] | null,
	): Promise<true>;

	create_unblind_generators(count: number): Promise<PointG1[]>,
	create_blind_generators(count: number): Promise<PointG1[]>,
}

type BbsSchnorrUst = [
	PointG2,
	PointG1,
	PointG1,
	bigint,
	[PointG1, bigint],
	bigint[],
	BufferSource,
	number[],
	BufferSource | undefined,
];
type BbsSchnorrProof = [
	PointG1,
	SchnorrNizkProof1,
	PointG1,
	PointG1,
	PointG1,
	SchnorrNizkProof,
];

export type BbsSchnorrOptions = {
	l: number,
	dpk_uses_h1?: boolean,
}
export type BbsSchnorrSuite = {
	iss_kgen(ikm?: BufferSource): Promise<[bigint, PointG2]>,
	dev_kgen(ikm?: BufferSource): Promise<[bigint, PointG1]>,
	issue(isk: bigint, dpk: PointG1, attrs: bigint[], ikm?: BufferSource): Promise<[PointG1, bigint]>,

	verify(
		ipk: PointG2,
		ctx: BufferSource,
		disclosed_idx: number[],
		disclosed_attrs: bigint[],
		tau: BbsSchnorrProof,
	): Promise<true>,

	vf_cred(ipk: PointG2, sigma: [PointG1, bigint], dpk: PointG1, attrs: bigint[]): boolean,

	show_user_1(
		ipk: PointG2,
		dpk: PointG1,
		sigma: [PointG1, bigint],
		attrs: bigint[],
		ctx: BufferSource,
		disclose_idx: number[],
		ikm?: BufferSource,
	): Promise<[BbsSchnorrUst, PointG1]>,

	show_se_1(ipk: PointG2, dsk: bigint, umsg: PointG1, ctx: BufferSource): Promise<BufferSource>,
	show_user_2(ust: BbsSchnorrUst, smsg: BufferSource): Promise<BbsSchnorrProof>,

	schnorr_verify_sha256_encoded(pk: PointG1, sig: BufferSource, m: BufferSource): Promise<true>,
};

type CipherSuite = {
	params: SuiteParams,
	hash_to_scalar: HashToScalarFunc,
	messages_to_scalars: MessagesToScalarsFunc,
	create_generators: CreateGeneratorsFunc,
	KeyGen: KeyGenFunction,
	SkToPk: SkToPkFunction,
	Bbs: BbsSuite,
	BlindBbs: BlindBbsSuite,
}


export function getCipherSuite(
	suiteId: SuiteId,
	overrides?: {
		mocked_random_scalars_params?: { SEED: BufferSource, DST: BufferSource },
		create_generators_dsts?: CreateGeneratorsDsts,
	},
): CipherSuite {

	switch (suiteId) {
		case 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_':
			// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-bls12-381-sha-256
			return createSuite({
				id: 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_',
				octet_scalar_length: 32,
				octet_point_length: 48,
				hash_to_curve_suite: hashToCurve('BLS12381G1_XMD:SHA-256_SSWU_RO_', toUtf8('Irrelevant, unused')),
				hash_to_curve_g1: (msg: BufferSource, DST: BufferSource) =>
					(bls12_381.G1.hashToCurve(toU8(msg), { DST: toU8(DST) }) as PointG1),
				expand_len: 48,
				curves: bls12_381,
				P1: bls12_381.G1.Point.fromBytes(fromHex("a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9")),
				create_generators_dsts: overrides?.create_generators_dsts,
				mocked_random_scalars_params: overrides?.mocked_random_scalars_params,
			});

		default:
			throw new Error(`Unknown suite: ${suiteId}`, { cause: { suiteId } });
	}
}
