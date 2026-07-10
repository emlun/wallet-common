/** Implementation of https://datatracker.ietf.org/doc/draft-irtf-cfrg-bbs-signatures/08/ */

import type { BlsCurvePair } from "@noble/curves/abstract/bls";
import type { Fp2 } from "@noble/curves/abstract/tower";
import { bls12_381 } from "@noble/curves/bls12-381.js";

import { concat, fromHex, I2OSP, isStrictlyIncreasing, OS2IP, range, toHex, toU8, toUtf8 } from "../utils/util";
import { hashToCurve, HashToCurveSuite } from "../arkg/hash_to_curve";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";


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
		return sum(points.map((Hi, i) =>
			scalars[i] === 0n
				? G1.Point.ZERO
				: Hi.multiply(scalars[i])
		));
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

		return { api_id, Sign, Verify, ProofGen, ProofVerify };
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

		async function deserialize_and_validate_commit(
			commitment_with_proof: BufferSource,
			blind_generators: PointG1[],
			api_id: BufferSource,
		): Promise<PointG1> {
			if (commitment_with_proof.byteLength === 0) {
				return G1.Point.ZERO;
			}

			const [commit, commit_proof] = octets_to_commitment_with_proof(toU8(commitment_with_proof));
			if (commit_proof[1].length + 1 !== blind_generators.length) {
				throw new Error(`Invalid proof length: expected ${blind_generators.length - 1} blind attributes, was ${commit_proof[1].length}`, { cause: { commit_proof, blind_generators } });
			}
			await CoreCommitVerify(commit, commit_proof, blind_generators, api_id);
			return commit;
		}

		async function Commit(
			committed_messages: BufferSource[],
		): Promise<[BufferSource, bigint]> {
			committed_messages = committed_messages ?? [];

			const committed_message_scalars = await messages_to_scalars(committed_messages, api_id);
			const blind_generators = await create_blind_generators(committed_message_scalars.length + 1);
			return CoreCommit(blind_generators, committed_message_scalars, api_id);
		}

		async function BlindSign(
			SK: bigint,
			PK: BufferSource,
			commitment_with_proof: BufferSource | null,
			header: BufferSource | null,
			messages: BufferSource[] | null,
		): Promise<BufferSource> {
			commitment_with_proof = commitment_with_proof ?? new Uint8Array([]);
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
			// const [Q_1, ...H_Points] = generators;
			const blind_generators = await create_blind_generators(M + 1);
			// const [Q_2, ...J] = blind_generators;
			const commitment = await deserialize_and_validate_commit(commitment_with_proof, blind_generators, api_id);
			const message_scalars = await messages_to_scalars(messages, api_id);
			const res = await B_calculate(PK, generators, blind_generators, commitment, message_scalars, header, api_id);
			const [B] = res;
			const blind_sig = FinalizeBlindSign(SK, B, api_id);
			return blind_sig;
		}

		async function VerifyBlindSign(
			PK: BufferSource,
			signature: BufferSource,
			header: BufferSource | null,
			messages: BufferSource[] | null,
			issuer_known_messages_no: number | null,
			secret_prover_blind: bigint | null,
		): Promise<true> {
			header = header ?? new Uint8Array([]);
			messages = messages ?? [];
			issuer_known_messages_no = issuer_known_messages_no ?? 0;
			secret_prover_blind = secret_prover_blind ?? 0n;
			const L = messages.length;
			if (issuer_known_messages_no > L) {
				throw new Error("Too many issuer-known messages", { cause: { messages, issuer_known_messages_no } });
			}

			const generators = await create_unblind_generators(issuer_known_messages_no + 1);
			const blind_generators = await create_blind_generators(L - issuer_known_messages_no + 1);
			const message_scalars = await messages_to_scalars(messages, api_id);
			const signer_scalars = message_scalars.slice(0, issuer_known_messages_no);
			const committed_message_scalars = message_scalars.slice(issuer_known_messages_no);
			const proof_scalars = [...signer_scalars, secret_prover_blind, ...committed_message_scalars];
			const res = await CoreVerify(
				PK,
				signature,
				[...generators, ...blind_generators],
				header,
				proof_scalars,
				api_id,
			);
			return res;
		}

		async function BlindProofGen(
			PK: BufferSource,
			signature: BufferSource,
			header: BufferSource | null,
			ph: BufferSource | null,
			messages: BufferSource[] | null,
			issuer_known_messages_no: number | null,
			message_disclosures: DisclosureChoice[] | null,
			secret_prover_blind: bigint | null,
		): Promise<[BufferSource, [bigint[], bigint[]]]> {
			header = header ?? new Uint8Array([]);
			ph = ph ?? new Uint8Array([]);
			messages = messages ?? [];
			issuer_known_messages_no = issuer_known_messages_no ?? 0;
			message_disclosures = message_disclosures ?? [],
			secret_prover_blind = secret_prover_blind ?? 0n;

			const L = messages.length;
			if (message_disclosures.length !== L) {
				throw new Error("Invalid disclosure map", { cause: { messages, message_disclosures } });
			}
			if (issuer_known_messages_no > L) {
				throw new Error("Too many issuer-known messages", { cause: { messages, issuer_known_messages_no } });
			}
			const disclosed_indexes = range(L).filter(i => message_disclosures[i] === "DISCLOSE");
			const commitment_indexes = range(L).filter(i => message_disclosures[i] === "COMMIT");

			const generators = await create_unblind_generators(issuer_known_messages_no + 1);
			const blind_generators = await create_blind_generators(L - issuer_known_messages_no + 1);
			const message_scalars = await messages_to_scalars(messages, api_id);
			const signer_scalars = message_scalars.slice(0, issuer_known_messages_no);
			const committed_message_scalars = message_scalars.slice(issuer_known_messages_no);
			const proof_scalars = [...signer_scalars, secret_prover_blind, ...committed_message_scalars];
			const proof_index = range(L).map(i => i < issuer_known_messages_no ? i : i + 1);
			const proof_disclosed_indexes = disclosed_indexes.map(i => proof_index[i]);
			const proof_commitment_indexes = commitment_indexes.map(i => proof_index[i]);
			const proof_with_add_zkp_info = await BlindCoreProofGen(
				PK,
				signature,
				[...generators, ...blind_generators],
				header,
				ph,
				proof_scalars,
				proof_disclosed_indexes,
				proof_commitment_indexes,
				api_id,
			);
			return proof_with_add_zkp_info;
		}

		async function BlindProofVerify(
			PK: BufferSource,
			proof: BufferSource,
			header: BufferSource | null,
			ph: BufferSource | null,
			issuer_known_messages_no: number | null,
			disclosed_messages: BufferSource[] | null,
			message_disclosures: DisclosureChoice[] | null,
		): Promise<true> {
			header = header ?? new Uint8Array([]);
			ph = ph ?? new Uint8Array([]);
			disclosed_messages = disclosed_messages ?? [];
			issuer_known_messages_no = issuer_known_messages_no ?? 0;
			disclosed_messages = disclosed_messages ?? [];
			message_disclosures = message_disclosures ?? [];

			const bbs_proof_len = Number(OS2IP(toU8(proof).slice(0, 8)));
			const undisclosed_msgs_no = (
				bbs_proof_len
					- 3 * octet_point_length
					- 4 * octet_scalar_length
			) / octet_scalar_length;
			const proof_msgs_no = undisclosed_msgs_no + disclosed_messages.length;
			if (proof_msgs_no === 0) {
				throw new Error("Too few messages", { cause: { proof, undisclosed_msgs_no, proof_msgs_no } });
			}
			const total_msgs_no = proof_msgs_no - 1;
			if (issuer_known_messages_no > total_msgs_no) {
				throw new Error("Too many issuer-known messages", { cause: { total_msgs_no, issuer_known_messages_no } });
			}
			if (message_disclosures.length !== total_msgs_no) {
				throw new Error("Invalid disclosures", { cause: { total_msgs_no, message_disclosures } });
			}
			const disclosed_indexes = range(total_msgs_no).filter(i => message_disclosures[i] === "DISCLOSE");
			const commitment_indexes = range(total_msgs_no).filter(i => message_disclosures[i] === "COMMIT");
			if (disclosed_indexes.length !== disclosed_messages.length) {
				throw new Error("Invalid disclosures", { cause: { disclosed_indexes, disclosed_messages } });
			}
			const proof_index = range(total_msgs_no).map(i => i < issuer_known_messages_no ? i : i + 1);
			const proof_disclosed_indexes = disclosed_indexes.map(i => proof_index[i]);
			const proof_commitment_indexes = commitment_indexes.map(i => proof_index[i]);

			const generators = await create_unblind_generators(issuer_known_messages_no + 1);
			const blind_generators = await create_blind_generators(total_msgs_no - issuer_known_messages_no + 1);
			const message_scalars = await messages_to_scalars(disclosed_messages, api_id);
			const result = await BlindCoreProofVerify(
				PK,
				proof,
				[...generators, ...blind_generators],
				header,
				ph,
				message_scalars,
				proof_disclosed_indexes,
				proof_commitment_indexes,
				api_id,
			);
			return result;
		}

		async function CoreCommit(
			blind_generators: PointG1[],
			committed_message_scalars: bigint[],
			api_id: BufferSource,
		): Promise<[BufferSource, bigint]> {
			const M = committed_message_scalars.length;
			if (blind_generators.length !== M + 1) {
				throw new Error("Invalid number of generators or messages", { cause: { blind_generators, committed_scalars: committed_message_scalars } });
			}
			// const [Q2, ...J] = blind_generators;
			const msg = committed_message_scalars;

			const [secret_prover_blind, s_tilde, ...m_tilde] = await calculate_random_scalars(M + 2);
			const C = sumprod(blind_generators, [secret_prover_blind, ...msg]);
			const Cbar = sumprod(blind_generators, [s_tilde, ...m_tilde]);
			const challenge = await calculate_blind_challenge(C, Cbar, blind_generators, api_id);
			const s_hat = Fr.add(s_tilde, Fr.mul(secret_prover_blind, challenge));
			const m_hat = m_tilde.map((m_tilde_i, i) => (Fr.add(m_tilde_i, Fr.mul(msg[i], challenge))));

			const proof: [bigint, bigint[], bigint] = [s_hat, m_hat, challenge];
			const commit_with_proof = commitment_with_proof_to_octets(C, proof);
			return [commit_with_proof, secret_prover_blind];
		}

		async function CoreCommitVerify(
			commitment: PointG1,
			commitment_proof: [bigint, bigint[], bigint],
			blind_generators: PointG1[],
			api_id: BufferSource,
		): Promise<true> {
			const [s_hat, commitments, cp] = commitment_proof;
			const M = commitments.length;
			const m_hat = commitments;
			if (blind_generators.length !== M + 1) {
				throw new Error("Invalid number of generators or commitments", { cause: { blind_generators, commitments } });
			}
			// const [Q2, ...J] = blind_generators;

			const Cbar = sumprod([...blind_generators, commitment], [s_hat, ...m_hat, Fr.neg(cp)]);
			const cv = await calculate_blind_challenge(commitment, Cbar, blind_generators, api_id);
			if (cv === cp) {
				return true;
			}
			throw new Error("Invalid proof", { cause: { commitment, commitment_proof, blind_generators, api_id } });
		}

		async function FinalizeBlindSign(
			SK: bigint,
			// PK: BufferSource,
			// domain: bigint,
			B: PointG1,
			// generators: PointG1[],
			// blind_generators: PointG1[],
			// header: BufferSource,
			api_id: BufferSource,
		): Promise<BufferSource> {
			const signature_dst = concat(api_id, toUtf8("H2S_"));

			if (B.is0()) {
				throw new Error("B must not be identity_G1");
			}

			// const L = generators.length - 1;
			// const M = blind_generators.length - 1;
			// if (L < 0 || M < 0) {
			// 	throw new Error("Invalid number of generators", { cause: { generators, blind_generators } });
			// }
			// const [Q_1, ...H_Points] = generators;
			// const [Q_2, ...J] = blind_generators;

			// const domain = await calculate_domain(PK, Q_1, [...H_Points, Q_2, ...J], header, api_id);
			const e_octs = serialize([SK, B]);
			const e = await hash_to_scalar(e_octs, signature_dst);
			const A = B.multiply(Fr.inv(Fr.add(SK, e)));
			return signature_to_octets(A, e);
		}

		async function BlindCoreProofGen(
			PK: BufferSource,
			signature: BufferSource,
			generators: PointG1[],
			header: BufferSource,
			ph: BufferSource,
			messages: bigint[],
			disclosed_indexes: number[],
			commitment_indexes: number[],
			api_id: BufferSource,
		): Promise<[BufferSource, [bigint[], bigint[]]]> {
			const [Y_0, Y_1] = await create_generators(2, concat(toUtf8("COM_DIS_"), api_id));

			const signature_result = octets_to_signature(signature);
			const [_A, e] = signature_result;
			const L = messages.length;
			if (!(isStrictlyIncreasing(commitment_indexes) && commitment_indexes.every(i => i >= 0 && i < L))) {
				throw new Error("Invalid commitment_indexes", { cause: { commitment_indexes } });
			}
			if (!(isStrictlyIncreasing(disclosed_indexes) && disclosed_indexes.every(i => i >= 0 && i < L))) {
				throw new Error("Invalid disclosed_indexes", { cause: { disclosed_indexes } });
			}
			const disclosed_set = new Set(disclosed_indexes);
			if (commitment_indexes.some(i => disclosed_set.has(i))) {
				throw new Error("Non-disjoint disclosed_indexes and commitment_indexes", { cause: { disclosed_indexes, commitment_indexes } });
			}
			const N = commitment_indexes.length;
			const R = disclosed_indexes.length;
			const U = L - R;
			const disclosed_messages = disclosed_indexes.map(i => messages[i]);
			const undisclosed_indexes = range(L).filter(i => !disclosed_set.has(i));
			const ji = undisclosed_indexes;
			const undisclosed_messages = undisclosed_indexes.map(i => messages[i]);

			const init_random_scalars = await calculate_random_scalars(5 + U);
			const [_r1, _r2, _r_tilde, _r1_tilde, _r3_tilde, ...m_tilde] = init_random_scalars;
			const init_res = await ProofInit(
				PK,
				signature_result,
				generators,
				init_random_scalars,
				header,
				messages,
				undisclosed_indexes,
				api_id,
			);

			const s_and_s_tilde = await calculate_random_scalars(2 * N);
			const s = s_and_s_tilde.slice(0, N);
			const s_tilde = s_and_s_tilde.slice(N);
			const Cs_and_C_tildes = commitment_indexes.map((idx, i) => {
				const Ci = Y_0.multiply(s[i]).add(Y_1.multiply(messages[idx]));
				const k = ji.indexOf(idx);
				const C_tilde_i = Y_0.multiply(s_tilde[i]).add(Y_1.multiply(m_tilde[ji[k]]));
				return [Ci, C_tilde_i];
			});

			const commitment_init_res = {
				commitments: Cs_and_C_tildes.map(([Ci, _]) => Ci),
				commitments_proofs: Cs_and_C_tildes.map(([_, C_tilde_i]) => C_tilde_i),
				commitment_indexes,
			};

			const challenge = await BlindProofChallengeCalculate(
				init_res,
				commitment_init_res,
				disclosed_messages,
				disclosed_indexes,
				ph,
				api_id,
			);

			const bbs_proof = ProofFinalize(init_res, challenge, e, init_random_scalars, undisclosed_messages);

			const s_hat = s_tilde.map((s_tilde, i) => Fr.add(s_tilde, Fr.mul(challenge, s[i])));
			const commitments_proof: [PointG1[], bigint[]] = [commitment_init_res.commitments, s_hat];

			const proof = blind_proof_to_octets(toU8(serialize([bbs_proof])).length, bbs_proof, N, commitments_proof);
			const add_zkp_info: [bigint[], bigint[]] = [
				commitment_indexes.map(i => messages[i]),
				s,
			];
			return [proof, add_zkp_info];
		}

		async function BlindCoreProofVerify(
			PK: BufferSource,
			proof: BufferSource,
			generators: PointG1[],
			header: BufferSource,
			ph: BufferSource,
			disclosed_messages: bigint[],
			disclosed_indexes: number[],
			commitment_indexes: number[],
			api_id: BufferSource,
		): Promise<true> {
			const [Y_0, Y_1] = await create_generators(2, concat(toUtf8("COM_DIS_"), api_id));

			const W = octets_to_pubkey(PK);

			const proof_res = blind_octets_to_proof(proof);
			const [bbs_proof_res, commitments_proof_res] = proof_res;
			const [Abar, Bbar, _D, _ehat, _r1hat, _r3hat, hats, cp] = bbs_proof_res;
			const [commitments, commitments_proof] = commitments_proof_res;

			const N = commitments.length;
			if (commitments_proof.length !== N) {
				throw new Error("Invalid commitments_proof length", { cause: { commitments, commitments_proof } });
			}
			if (commitment_indexes.length !== N) {
				throw new Error("Invalid commitments_indexes length", { cause: { commitments, commitment_indexes } });
			}
			const U = hats.length;
			const R = disclosed_indexes.length;
			if (disclosed_messages.length !== R) {
				throw new Error("Invalid disclosed_messages length", { cause: { R, disclosed_messages } });
			}
			const L = R + U;

			if (!(isStrictlyIncreasing(commitment_indexes) && commitment_indexes.every(i => i >= 0 && i < L))) {
				throw new Error("Invalid commitment_indexes", { cause: { commitment_indexes } });
			}
			if (!(isStrictlyIncreasing(disclosed_indexes) && disclosed_indexes.every(i => i >= 0 && i < L))) {
				throw new Error("Invalid disclosed_indexes", { cause: { disclosed_indexes } });
			}
			const disclosed_set = new Set(disclosed_indexes);
			if (commitment_indexes.some(i => disclosed_set.has(i))) {
				throw new Error("Non-disjoint disclosed_indexes and commitment_indexes", { cause: { disclosed_indexes, commitment_indexes } });
			}

			const undisclosed_indexes = range(L).filter(i => !disclosed_set.has(i));
			const ji = undisclosed_indexes;
			const m_hat = hats;
			const C = commitments;
			const s_hat = commitments_proof;

			const init_res = await ProofVerifyInit(PK, bbs_proof_res, generators, header, disclosed_messages, disclosed_indexes, api_id);

			const C_hat = commitment_indexes.map((idx, i) => {
				const k = ji.indexOf(idx);
				const C_hat_i = Y_0.multiply(s_hat[i]).add(Y_1.multiply(m_hat[ji[k]])).subtract(C[i].multiply(cp));
				return C_hat_i;
			});

			const commitment_init_res = {
				commitments: C,
				commitments_proofs: C_hat,
				commitment_indexes,
			};

			const challenge = await BlindProofChallengeCalculate(
				init_res,
				commitment_init_res,
				disclosed_messages,
				disclosed_indexes,
				ph,
				api_id,
			);
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

		async function B_calculate(
			PK: BufferSource,
			generators: PointG1[],
			blind_generators: PointG1[],
			commitment: PointG1,
			message_scalars: bigint[],
			header: BufferSource,
			api_id: BufferSource,
		): Promise<[PointG1]> {
			const L = message_scalars.length;
			const M = blind_generators.length - 1;
			if (generators.length !== L + 1) {
				throw new Error("Messages and generators not of matching lengths", { cause: { message_scalars, generators } });
			}
			if (M < 0) {
				throw new Error("Not enough blind_generators", { cause: { M, blind_generators } });
			}
			const [Q_1, ...H_Points] = generators;
			const msg = message_scalars;
			const [Q_2, ...J_Points] = blind_generators;
			const domain = await calculate_domain(PK, Q_1, [...H_Points, Q_2, ...J_Points], header, api_id);
			const B = sumprod([P1, Q_1, ...H_Points, commitment], [1n, domain, ...msg, 1n]);
			if (B.is0()) {
				throw new Error("B must not be Identity_G1", { cause: { generators, blind_generators, commitment, message_scalars, header, api_id } });
			}
			return [B];
		}

		function calculate_blind_challenge(
			C: PointG1,
			Cbar: PointG1,
			generators: PointG1[],
			api_id: BufferSource,
		): Promise<bigint> {
			const blind_challenge_dst = concat(api_id, toUtf8("H2S_"));

			if (generators.length === 0) {
				throw new Error("No generators", { cause: { generators } });
			}
			const M = generators.length - 1;

			const c_arr = [M, ...generators];
			const c_octs = serialize([...c_arr, C, Cbar]);
			return hash_to_scalar(c_octs, blind_challenge_dst);
		}

		async function BlindProofChallengeCalculate(
			init_res: [PointG1, PointG1, PointG1, PointG1, PointG1, bigint],
			commitment_init_res: { commitments: PointG1[], commitments_proofs: PointG1[], commitment_indexes: number[] },
			disclosed_messages: bigint[],
			disclosed_indexes: number[],
			ph: BufferSource,
			api_id: BufferSource,
		): Promise<bigint> {
			const hash_to_scalar_dst = concat(api_id, toUtf8("H2S_"));

			const [Abar, Bbar, D, T1, T2, domain] = init_res;

			const R = disclosed_indexes.length;
			const ii = disclosed_indexes;
			if (disclosed_messages.length !== R) {
				throw new Error("Disclosed messages and indexes not of matching lengths", { cause: { disclosed_messages, disclosed_indexes } });
			}
			const msg = disclosed_messages;

			const N = commitment_init_res.commitments.length;
			if (commitment_init_res.commitments_proofs.length !== N) {
				throw new Error("Wrong length of commitments_proofs", { cause: { commitment_init_res } });
			}
			if (commitment_init_res.commitment_indexes.length !== N) {
				throw new Error("Wrong length of commitment_indexes", { cause: { commitment_init_res } });
			}
			const C = commitment_init_res.commitments;
			const C_tilde = commitment_init_res.commitments_proofs;
			const i_i = commitment_init_res.commitment_indexes;

			if (R > Math.pow(2, 64) - 1) {
				throw new Error("Too many disclosed indexes", { cause: { disclosed_indexes } });
			}
			if (ph.byteLength > Math.pow(2, 64) - 1) {
				throw new Error("Presentation header too long", { cause: { ph } });
			}

			const c_arr = [R, ...ii.flatMap((ii, i) => [ii, msg[i]]), Abar, Bbar, D, T1, T2, domain];
			const commitment_arr = [N, ...i_i.flatMap((i_i, i) => [i_i, C[i], C_tilde[i]])];
			const c_octs = concat(serialize(c_arr), serialize(commitment_arr), I2OSP(ph.byteLength, 8), ph);
			return await hash_to_scalar(c_octs, hash_to_scalar_dst);
		}


		function commitment_with_proof_to_octets(
			commitment: PointG1,
			proof: [bigint, bigint[], bigint],
		): BufferSource {
			const commitment_octs = serialize([commitment]);
			const [s_hat, m_hat, challenge] = proof;
			const proof_octs = serialize([s_hat, ...m_hat, challenge]);
			return concat(commitment_octs, proof_octs);
		}

		function octets_to_commitment_with_proof(
			commitment_octs: Uint8Array,
		): [PointG1, [bigint, bigint[], bigint]] {
			const commit_len_floor = octet_point_length + 2 * octet_scalar_length;
			if (commitment_octs.byteLength < commit_len_floor) {
				throw new Error(`Commitment with proof too short: expected at least ${commit_len_floor} octets, was ${commitment_octs.byteLength}`, { cause: { commitment_octs, commit_len_floor } });
			}
			const C_octets = commitment_octs.slice(0, octet_point_length);
			const C = octets_to_point_E1(C_octets);
			if (C.is0()) {
				throw new Error("C must not be Identity_G1", { cause: { commitment_octs } });
			}

			let s = [];
			let j = 0;
			let index = octet_point_length;
			while (index < commitment_octs.length) {
				const end_index = index + octet_scalar_length;
				const s_j = OS2IP(commitment_octs.slice(index, end_index));
				if (s_j === 0n || s_j >= Fr.ORDER) {
					throw new Error(`Scalar out of range: ${s_j}`, { cause: { s_j, j, index, commitment_octs } });
				}
				s.push(s_j);
				index += octet_scalar_length;
				j += 1;
			}

			if (index !== commitment_octs.length) {
				throw new Error("Trailing octets", { cause: { index, commitment_octs } });
			}
			if (j < 2) {
				throw new Error("Too few scalars", { cause: { j, commitment_octs } });
			}
			const msg_commitment = (
				j >= 3
				? s.slice(1, j - 1)
				: []
			);
			return [C, [s[0], msg_commitment, s[j - 1]]];
		}

		function blind_proof_to_octets(
			bbs_proof_len: number,
			bbs_proof: BufferSource,
			commitments_count: number,
			commitments_proof: [PointG1[], bigint[]],
		) {
			const oct = concat(
				I2OSP(bbs_proof_len, 8),
				bbs_proof,
				I2OSP(commitments_count, 8),
				serialize(commitments_proof.flat()),
			);
			return oct;
		}

		function blind_octets_to_proof(proof_octets: BufferSource): [
			[PointG1, PointG1, PointG1, bigint, bigint, bigint, bigint[], bigint],
			[PointG1[], bigint[]],
		] {
			const int_octet_length = 8;
			const r = Fr.ORDER;

			const proof_octets_u8 = toU8(proof_octets);
			let sidx = 0;
			let eidx = int_octet_length;
			if (proof_octets.byteLength < eidx) {
				throw new Error("Proof too short", { cause: { proof_octets_u8 } });
			}
			const bbs_proof_len = Number(OS2IP(proof_octets_u8.slice(sidx, eidx)));

			sidx = eidx;
			eidx = sidx + bbs_proof_len;
			if (proof_octets.byteLength < eidx) {
				throw new Error(`Proof too short: expected at least ${eidx} octets, was ${proof_octets.byteLength}`, { cause: { proof_octets, eidx } });
			}
			const bbs_proof_octs = proof_octets_u8.slice(sidx, eidx);
			const bbs_proof = octets_to_proof(bbs_proof_octs);

			sidx = eidx;
			eidx = sidx + int_octet_length;
			if (proof_octets.byteLength < eidx) {
				throw new Error(`Proof too short: expected at least ${eidx} octets, was ${proof_octets.byteLength}`, { cause: { proof_octets, eidx } });
			}
			const N = Number(OS2IP(proof_octets_u8.slice(sidx, eidx)));

			const len_floor = eidx + N * (octet_point_length + octet_scalar_length);
			if (proof_octets.byteLength < len_floor) {
				throw new Error(`Proof too short: expected at least ${len_floor} octets, was ${proof_octets.byteLength}`, { cause: { proof_octets, len_floor } });
			}

			const C = range(N).map(() => {
				sidx = eidx;
				eidx = sidx + octet_point_length;
				// TODO: Check that @noble/curves does the subgroup check
				return octets_to_point_E1(proof_octets_u8.slice(sidx, eidx));
			});

			const s = range(N).map(() => {
				sidx = eidx;
				eidx = sidx + octet_scalar_length;
				const s = OS2IP(proof_octets_u8.slice(sidx, eidx));
				if (s <= 0n || s >= r) {
					throw new Error(`Scalar out of range: ${s}`, { cause: { s, r } });
				}
				return s;
			});

			const commitments_proof: [PointG1[], bigint[]] = [C, s];

			if (proof_octets.byteLength !== eidx) {
				throw new Error("Trailing octets", { cause: { proof_octets, eidx } });
			}

			return [bbs_proof, commitments_proof];
		}

		return {
			api_id,
			Commit,
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

export type DisclosureChoice = "DISCLOSE" | "HIDE" | "COMMIT";


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

type BbsSuite = {
	api_id: BufferSource,

	Sign: SignFunction,
	Verify: VerifyFunction,
	ProofGen: ProofGenFunction,
	ProofVerify: ProofVerifyFunction,
}

type BlindBbsSuite = {
	api_id: BufferSource,

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-commitment-computation */
	Commit(
		committed_messages: BufferSource[],
	): Promise<[BufferSource, bigint]>;

	/** https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-blind-signature-generation */
	BlindSign(
		SK: bigint,
		PK: BufferSource,
		commitment_with_proof: BufferSource | null,
		header: BufferSource | null,
		messages: BufferSource[] | null,
	): Promise<BufferSource>;

	VerifyBlindSign(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		messages: BufferSource[] | null,
		issuer_known_messages_no: number | null,
		secret_prover_blind: bigint | null,
	): Promise<true>;

	BlindProofGen(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		messages: BufferSource[] | null,
		issuer_known_messages_no: number | null,
		message_disclosures: DisclosureChoice[] | null,
		secret_prover_blind: bigint | null,
	): Promise<[BufferSource, [bigint[], bigint[]]]>;

	BlindProofVerify(
		PK: BufferSource,
		proof: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		issuer_known_messages_no: number | null,
		disclosed_messages: BufferSource[] | null,
		message_disclosures: DisclosureChoice[] | null,
	): Promise<true>;

	create_unblind_generators(count: number): Promise<PointG1[]>,
	create_blind_generators(count: number): Promise<PointG1[]>,
}

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
