import type { Fp2 } from "@noble/curves/abstract/tower";

import { concat, I2OSP, isStrictlyIncreasing, OS2IP, range, split_at, split_sections, toU8, toUtf8 } from "../utils/util";
import { sha256 } from "../arkg/hash_to_curve";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import * as Bbs from ".";
import * as util from "./util";


function createSuite(Bbs: Bbs.CipherSuite): BlindBbsSuite {
	const suite = Bbs.params;
	const {
		curves: { G1, G2, pairing: h, fields: { Fr, Fp12 } },
		P1,
		octet_point_length,
		octet_scalar_length,
	} = suite;

	const sum = (points: PointG1[]) => util.sum(G1, points);
	const sumprod = (points: PointG1[], scalars: bigint[]) => util.sumprod(G1, points, scalars);

	const api_id = toUtf8(suite.id + "BLIND_H2G_HM2S_");
	const blind_api_id = concat(toUtf8("BLIND_"), api_id);
	const keybind_api_id = concat(toUtf8("KEYBIND_"), api_id);

	function create_unblind_generators(count: number): Promise<PointG1[]> {
		return Bbs.create_generators(count, api_id);
	}

	function create_blind_generators(count: number): Promise<PointG1[]> {
		return Bbs.create_generators(count, blind_api_id);
	}

	function create_keybind_generators(count: number): Promise<PointG1[]> {
		return Bbs.create_generators(count, keybind_api_id);
	}

	async function Commit(
		committed_messages: BufferSource[] | null,
	): Promise<[BufferSource, bigint]> {
		committed_messages = committed_messages ?? [];

		const [state, secret_prover_blind,] = await CommitInit(committed_messages, null);
		return [await CommitFinalize(state, null), secret_prover_blind];
	}

	async function CommitInit(
		committed_messages: BufferSource[] | null,
		committed_points: BufferSource[] | null,
	): Promise<[BufferSource, bigint, BufferSource]> {
		committed_messages = committed_messages ?? [];
		committed_points = committed_points ?? [];

		const committed_message_scalars = await Bbs.messages_to_scalars(committed_messages, api_id);
		const blind_generators = await create_blind_generators(committed_message_scalars.length + 1);
		const keybind_generators = await create_keybind_generators(committed_points.length);
		const [state, challenge, secret_prover_blind] = await CoreCommitInit(
			blind_generators,
			keybind_generators,
			committed_message_scalars,
			committed_points.map(Bbs.octets_to_point_E1),
			api_id,
		);
		return [commit_state_to_octets(state), secret_prover_blind, Bbs.serialize([challenge])];
	}

	async function CommitFinalize(
		state: BufferSource,
		committed_point_proofs: BufferSource[] | null,
	): Promise<BufferSource> {
		committed_point_proofs = committed_point_proofs ?? [];

		return commitment_with_proof_to_octets(
			...await CoreCommitFinalize(
			octets_to_commit_state(state),
			committed_point_proofs.map(octs => {
				const [k_hat, c] = split_at(toU8(octs), octet_scalar_length);
				return [OS2IP(k_hat), OS2IP(c)];
			}),
			)
		);
	}

	async function deserialize_and_validate_commit(
		commitment_with_proof: BufferSource,
		api_id: BufferSource,
	): Promise<[PointG1, PointG1[], PointG1, PointG1[], PointG1[]]> {
		if (commitment_with_proof.byteLength === 0) {
			return [G1.Point.ZERO, [], (await create_blind_generators(1))[0], [], []];
		}

		const [commitment, commitment_proof] = octets_to_commitment_with_proof(toU8(commitment_with_proof));
		const [, message_proofs, , point_proofs] = commitment_proof;
		const blind_generators = await create_blind_generators(1 + message_proofs.length);
		const keybind_generators = await create_keybind_generators(point_proofs.length);
		const [Q2, ...blind_msg_generators] = blind_generators;
		await CoreCommitVerify(commitment, commitment_proof, blind_generators, keybind_generators, api_id);
		return [...commitment, Q2, blind_msg_generators, keybind_generators];
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
		const [commitment, committed_points, Q2, blind_msg_generators, keybind_generators] = await deserialize_and_validate_commit(commitment_with_proof, api_id);
		// const [Q_2, ...J] = blind_generators;
		const message_scalars = await Bbs.messages_to_scalars(messages, api_id);
		const res = await B_calculate(PK, generators, [Q2, ...blind_msg_generators,  ...keybind_generators], commitment.add(sum(committed_points)), message_scalars, header, api_id);
		const [B] = res;
		const blind_sig = FinalizeBlindSign(SK, B, committed_points, api_id);
		return blind_sig;
	}

	async function VerifyBlindSign(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		messages: BufferSource[] | null,
		committed_points: BufferSource[] | null,
		issuer_known_messages_no: number | null,
		secret_prover_blind: bigint | null,
	): Promise<true> {
		header = header ?? new Uint8Array([]);
		messages = messages ?? [];
		committed_points = committed_points ?? [];
		issuer_known_messages_no = issuer_known_messages_no ?? 0;
		secret_prover_blind = secret_prover_blind ?? 0n;
		const L = messages.length;
		if (issuer_known_messages_no > L) {
			throw new Error("Too many issuer-known messages", { cause: { messages, issuer_known_messages_no } });
		}

		const generators = await create_unblind_generators(issuer_known_messages_no + 1);
		const blind_generators = await create_blind_generators(L - issuer_known_messages_no + 1);
		const keybind_generators = await create_keybind_generators(committed_points.length);
		const message_scalars = await Bbs.messages_to_scalars(messages, api_id);
		const signer_scalars = message_scalars.slice(0, issuer_known_messages_no);
		const committed_message_scalars = message_scalars.slice(issuer_known_messages_no);
		const proof_scalars = [...signer_scalars, secret_prover_blind, ...committed_message_scalars];
		const res = await CoreVerify(
			PK,
			signature,
			generators,
			blind_generators,
			keybind_generators,
			header,
			proof_scalars,
			committed_points.map(Bbs.octets_to_point_E1),
			api_id,
		);
		return res;
	}

	async function BlindProofGen(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		signer_messages: BufferSource[] | null,
		prover_messages: BufferSource[] | null,
		signer_message_disclosures: DisclosureChoice[] | null,
		prover_message_disclosures: DisclosureChoice[] | null,
		secret_prover_blind: bigint | null,
	): Promise<[BufferSource, [bigint[], bigint[]]]> {
		const [state, add_zkp_info,] = await BlindProofGenInit(
			PK,
			signature,
			header,
			ph,
			signer_messages,
			prover_messages,
			null,
			signer_message_disclosures,
			prover_message_disclosures,
			secret_prover_blind,
		);
		return [
			toU8(state).slice(0, state.byteLength - octet_scalar_length),
			add_zkp_info,
		];
	}

	async function BlindProofGenInit(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		signer_messages: BufferSource[] | null,
		prover_messages: BufferSource[] | null,
		prover_binding_keys: BufferSource[] | null,
		signer_message_disclosures: DisclosureChoice[] | null,
		prover_message_disclosures: DisclosureChoice[] | null,
		secret_prover_blind: bigint | null,
	): Promise<[BufferSource, [bigint[], bigint[]], BufferSource[]]> {
		header = header ?? new Uint8Array([]);
		ph = ph ?? new Uint8Array([]);
		signer_messages = signer_messages ?? [];
		prover_messages = prover_messages ?? [];
		prover_binding_keys = prover_binding_keys ?? [];
		signer_message_disclosures = signer_message_disclosures ?? [];
		prover_message_disclosures = prover_message_disclosures ?? [];
		secret_prover_blind = secret_prover_blind ?? 0n;

		const N = signer_messages.length;
		const K = prover_binding_keys.length;
		const L = N + prover_messages.length;
		if (signer_message_disclosures.length !== signer_messages.length) {
			throw new Error("Invalid disclosures", { cause: { signer_messages, signer_message_disclosures } });
		}
		if (prover_message_disclosures.length !== prover_messages.length) {
			throw new Error("Invalid disclosures", { cause: { prover_messages, prover_message_disclosures } });
		}
		const messages = [...signer_messages, ...prover_messages];
		const message_disclosures = [...signer_message_disclosures, ...prover_message_disclosures];
		const disclosed_indexes = range(L).filter(i => message_disclosures[i] === "DISCLOSE");
		const commitment_indexes = range(L).filter(i => message_disclosures[i] === "COMMIT");

		const generators = await create_unblind_generators(N + 1);
		const blind_generators = await create_blind_generators(L - N + 1);
		const keybind_generators = await create_keybind_generators(K);
		const message_scalars = await Bbs.messages_to_scalars(messages, api_id);
		const signer_scalars = message_scalars.slice(0, N);
		const committed_message_scalars = message_scalars.slice(N);
		const proof_scalars = [...signer_scalars, secret_prover_blind, ...committed_message_scalars];
		const proof_index = range(L).map(i => i < N ? i : i + 1);
		const proof_disclosed_indexes = disclosed_indexes.map(i => proof_index[i]);
		const proof_commitment_indexes = commitment_indexes.map(i => proof_index[i]);
		const state_and_add_zkp_info_and_dpk_challenges = await CoreProofGenInit(
			PK,
			signature,
			generators,
			blind_generators,
			keybind_generators,
			header,
			ph,
			proof_scalars,
			prover_binding_keys.map(Bbs.octets_to_point_E1),
			proof_disclosed_indexes,
			proof_commitment_indexes,
			api_id,
		);
		return state_and_add_zkp_info_and_dpk_challenges;
	}

	async function BlindProofGenFinalize(
		state: BufferSource,
		prover_binding_signatures: BufferSource[] | null,
	): Promise<BufferSource> {
		prover_binding_signatures = prover_binding_signatures ?? [];

		const [incomplete_proof, challenge, r_key] = octets_to_blind_proof_gen_state(state);
		const randomized_keys = incomplete_proof_octets_to_randomized_keys(incomplete_proof);

		const adapted_sigs: KeyBindingSignature[] = prover_binding_signatures.map((sig, i) => {
			switch (sig.byteLength) {
				case 2 * octet_scalar_length:
					const [s, c] = schnorr_parse_signature(sig);
					return ["SCHNORR", schnorr_encode_signature([Fr.add(s, Fr.mul(r_key[i], c)), c])];

				case 2 * octet_point_length:
					return [
						"BLS",
						Bbs.serialize([
							Bbs.octets_to_point_E2(sig).add(
								G2.hashToCurve(toU8(Bbs.serialize([randomized_keys[i], challenge])))
									.multiply(r_key[i])),
						]),
					];

				default:
					throw new Error("Unknown signature length: " + sig.byteLength);
			}
		});

		return concat(incomplete_proof, key_bind_sigs_to_octets(adapted_sigs));
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

		const proof_u8 = toU8(proof);
		const bbs_proof_len = Number(OS2IP(proof_u8.slice(0, 8)));
		const K = Number(OS2IP(proof_u8.slice(8, 16)));
		const undisclosed_msgs_no = (
			bbs_proof_len
				- 3 * octet_point_length
				- 4 * octet_scalar_length
		) / octet_scalar_length;
		const proof_msgs_no = undisclosed_msgs_no + disclosed_messages.length;
		if (proof_msgs_no === 0) {
			throw new Error("Too few messages", { cause: { proof, undisclosed_msgs_no, proof_msgs_no } });
		}
		const total_msgs_no = proof_msgs_no - 1 - K;
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
		const keybind_generators = await create_keybind_generators(K);
		const message_scalars = await Bbs.messages_to_scalars(disclosed_messages, api_id);
		const result = await CoreProofVerify(
			PK,
			proof_u8,
			generators,
			blind_generators,
			keybind_generators,
			header,
			ph,
			message_scalars,
			proof_disclosed_indexes,
			proof_commitment_indexes,
			api_id,
		);
		return result;
	}

	async function CoreCommitInit(
		blind_generators: PointG1[],
		keybind_generators: PointG1[],
		committed_scalars: bigint[],
		committed_points: PointG1[],
		api_id: BufferSource,
	): Promise<[CommitState, BufferSource, bigint]> {
		const M = committed_scalars.length;
		const K = committed_points.length;
		if (blind_generators.length !== M + 1) {
			throw new Error("Invalid number of blind message generators or messages", { cause: { blind_generators, committed_scalars } });
		}
		if (keybind_generators.length !== K) {
			throw new Error("Invalid number of key binding generators or points", { cause: { keybind_generators, committed_points } });
		}
		const msg = committed_scalars;

		const [secret_prover_blind, s_tilde, ...m_tilde] = await Bbs.calculate_random_scalars(M + 2);
		const C = sumprod(blind_generators, [secret_prover_blind, ...msg]);
		const Cbar = sumprod(blind_generators, [s_tilde, ...m_tilde]);
		const challenge = await calculate_blind_challenge(C, Cbar, [...blind_generators, ...keybind_generators], committed_points, api_id);
		const s_hat = Fr.add(s_tilde, Fr.mul(secret_prover_blind, challenge));
		const m_hat = m_tilde.map((m_tilde_i, i) => (Fr.add(m_tilde_i, Fr.mul(msg[i], challenge))));

		const state: CommitState = [
			committed_points,
			C,
			s_hat,
			m_hat,
			challenge,
		];
		return [state, Bbs.serialize([challenge]), secret_prover_blind];
	}

	async function CoreCommitProve(
		committed_point_secret: bigint,
		generator: PointG1,
		challenge: BufferSource,
	): Promise<[bigint, bigint]> {
		const challenge_dst = new Uint8Array([]);

		const [k_tilde] = await Bbs.calculate_random_scalars(1);
		const R = generator.multiply(k_tilde);
		const c = await Bbs.hash_to_scalar(Bbs.serialize([R, challenge]), challenge_dst);
		const k_hat = Fr.add(k_tilde, Fr.mul(c, committed_point_secret));
		return [k_hat, c];
	}

	async function CoreCommitFinalize(
		state: CommitState,
		committed_point_proofs: [bigint, bigint][],
	): Promise<[[PointG1, PointG1[]], [bigint, bigint[], bigint, [bigint, bigint][]]]> {
		const [committed_points, C, s_hat, m_hat, challenge] = state;
		const N = committed_points.length;

		if (committed_point_proofs.length !== N) {
			throw new Error("Invalid number of point proofs", { cause: { committed_points, committed_point_proofs } });
		}

		return [
			[C, committed_points],
			[s_hat, m_hat, challenge, committed_point_proofs],
		];
	}

	async function CoreCommitVerify(
		[commitment, committed_points]: [PointG1, PointG1[]],
		commitment_proof: [bigint, bigint[], bigint, [bigint, bigint][]],
		blind_generators: PointG1[],
		keybind_generators: PointG1[],
		api_id: BufferSource,
	): Promise<true> {
		const [s_hat, commitments, cp, committed_point_proofs] = commitment_proof;
		const M = commitments.length;
		const K = committed_point_proofs.length;
		const m_hat = commitments;
		if (blind_generators.length !== M + 1) {
			throw new Error("Invalid number of message generators or commitments", {
				cause: { blind_generators, commitments }
			});
		}
		if (keybind_generators.length !== K) {
			throw new Error("Invalid number of key binding generators or point proofs", {
				cause: { keybind_generators, committed_point_proofs }
			});
		}

		const Cbar = sumprod([...blind_generators, commitment], [s_hat, ...m_hat, Fr.neg(cp)]);
		const cv = await calculate_blind_challenge(commitment, Cbar, [...blind_generators, ...keybind_generators], committed_points, api_id);
		if (cv === cp) {
			if (
				(await Promise.all(committed_point_proofs.map(async ([k_hat, c], j) => {
					const Jj = keybind_generators[j];
					const K = committed_points[j];
					const R_hat = Jj.multiply(k_hat).add(K.multiply(Fr.neg(c)));
					const cv = await Bbs.hash_to_scalar(Bbs.serialize([R_hat, cp]), new Uint8Array([]));
					if (cv === c) {
						return true;
					}
					throw new Error("Invalid point proof", { cause: { Jj, K, k_hat, c, R_hat, cv } });
				}))).every(result => result === true)
			) {
				return true;
			}
		}
		throw new Error("Invalid proof", { cause: { commitment, commitment_proof, blind_generators, committed_points, api_id } });
	}

	async function FinalizeBlindSign(
		SK: bigint,
		// PK: BufferSource,
		// domain: bigint,
		B: PointG1,
		committed_points: PointG1[],
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
		const e_octs = Bbs.serialize([SK, B, ...committed_points]);
		const e = await Bbs.hash_to_scalar(e_octs, signature_dst);
		const A = B.multiply(Fr.inv(Fr.add(SK, e)));
		return Bbs.signature_to_octets(A, e);
	}

	async function CoreVerify(
		PK: BufferSource,
		signature: BufferSource,
		generators: PointG1[],
		blind_generators: PointG1[],
		keybind_generators: PointG1[],
		header: BufferSource,
		messages: bigint[],
		committed_points: PointG1[],
		api_id: BufferSource,
	): Promise<true> {
		const [A, e] = Bbs.octets_to_signature(signature);
		const W = Bbs.octets_to_pubkey(PK);
		const M = messages.length;
		const K = committed_points.length;
		if (generators.length + blind_generators.length !== M + 1) {
			throw new Error("Messages and generators not of matching lengths", { cause: { messages, generators, blind_generators } });
		}
		if (keybind_generators.length !== K) {
			throw new Error("Points and key binding generators not of matching lengths", { cause: { committed_points, keybind_generators } });
		}
		const [Q_1, ...H_Points] = generators;
		const [Q_2, ...J_Points] = blind_generators;

		const domain = await Bbs.calculate_domain(PK, Q_1, [...H_Points, ...blind_generators, ...keybind_generators], header, api_id);
		const B = P1
			.add(Q_1.multiply(domain))
			.add(sumprod([...H_Points, Q_2, ...J_Points], messages))
			.add(sum(committed_points));
		if (!Fp12.eql(
			Fp12.mul(h(A, W.add(G2.Point.BASE.multiply(e))), h(B, G2.Point.BASE.negate())),
			Fp12.ONE,
		)) {
			throw new Error("Invalid signature", { cause: { PK, signature, header, messages } });
		}
		return true;
	}

	async function CoreProofGenInit(
		PK: BufferSource,
		signature: BufferSource,
		generators: PointG1[],
		blind_generators: PointG1[],
		keybind_generators: PointG1[],
		header: BufferSource,
		ph: BufferSource,
		messages: bigint[],
		prover_binding_keys: PointG1[],
		disclosed_indexes: number[],
		commitment_indexes: number[],
		api_id: BufferSource,
	): Promise<[BufferSource, [bigint[], bigint[]], BufferSource[]]> {
		const [Y_0, Y_1] = await Bbs.create_generators(2, concat(toUtf8("COM_DIS_"), api_id));

		const signature_result = Bbs.octets_to_signature(signature);
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
		const K = prover_binding_keys.length;
		const disclosed_messages = disclosed_indexes.map(i => messages[i]);
		const undisclosed_indexes = range(L).filter(i => !disclosed_set.has(i));
		const ji = undisclosed_indexes;
		const undisclosed_messages = undisclosed_indexes.map(i => messages[i]);

		const init_random_scalars = await Bbs.calculate_random_scalars(5 + U + 2 * K);
		const [r1, r2, _e_tilde, r1_tilde, r3_tilde, ...message_randoms] = init_random_scalars;
		const m_tilde = message_randoms.slice(0, U);
		const r_key = message_randoms.slice(U + K);

		const [Q1, ...Hi] = generators;
		const MsgGenerators = [...Hi, ...blind_generators];

		const dpk = prover_binding_keys;
		const dpkbar = dpk.map((dpk, i) => dpk.add(keybind_generators[i].multiply(r_key[i])));

		const [Abar, Bbar_init, D_init, T1_init, T2_init, domain] = await Bbs.ProofInit(
			PK,
			signature_result,
			[...generators, ...blind_generators, ...keybind_generators],
			init_random_scalars.slice(0, 5 + U + K),
			header,
			[...messages, ...range(K).map(() => 0n)],
			[...undisclosed_indexes, ...range(K).map(i => i + L)],
			api_id,
		);
		const D_add = sum(dpk).multiply(r2);
		const D = D_init.add(D_add);
		const Bbar = Bbar_init.add(D_add.multiply(r1));
		const Y = P1.add(Q1.multiply(domain))
			.add(sum(dpkbar))
			.add(sumprod(disclosed_indexes.map(i => MsgGenerators[i]), disclosed_indexes.map(i => messages[i])))
			;
		const T1 = T1_init.add(D_add.multiply(r1_tilde));
		const T2 = T2_init.add(D_add.multiply(r3_tilde));

		const s_and_s_tilde = await Bbs.calculate_random_scalars(2 * N);
		const s = s_and_s_tilde.slice(0, N);
		const s_tilde = s_and_s_tilde.slice(N);
		const Cs_and_C_tildes = commitment_indexes.map((idx, i) => {
			const Ci = Y_0.multiply(s[i]).add(Y_1.multiply(messages[idx]));
			const k = ji.indexOf(idx);
			const C_tilde_i = Y_0.multiply(s_tilde[i]).add(Y_1.multiply(m_tilde[k]));
			return [Ci, C_tilde_i];
		});

		const commitment_init_res = {
			commitments: Cs_and_C_tildes.map(([Ci, _]) => Ci),
			commitments_proofs: Cs_and_C_tildes.map(([_, C_tilde_i]) => C_tilde_i),
			commitment_indexes,
		};

		const challenge = await ProofChallengeCalculate(
			[Abar, Bbar, D, Y, T1, T2, domain],
			commitment_init_res,
			disclosed_messages,
			disclosed_indexes,
			ph,
			api_id,
		);

		const bbs_proof = Bbs.ProofFinalize(
			[Abar, Bbar, D, T1, T2, domain],
			challenge,
			e,
			init_random_scalars.slice(0, 5 + U + K),
			[...undisclosed_messages, ...r_key.map(rk => Fr.neg(rk))],
		);

		const s_hat = s_tilde.map((s_tilde, i) => Fr.add(s_tilde, Fr.mul(challenge, s[i])));
		const commitments_proof: [PointG1[], bigint[]] = [commitment_init_res.commitments, s_hat];

		const proof = incomplete_blind_proof_to_octets(
			toU8(Bbs.serialize([bbs_proof])).length,
			bbs_proof,
			N,
			commitments_proof,
			dpkbar,
		);
		const state = blind_proof_gen_state_to_octets(proof, challenge, r_key);
		const r_key_challenges = dpkbar.map(dpkbar => Bbs.serialize([dpkbar, challenge]));
		const add_zkp_info: [bigint[], bigint[]] = [
			commitment_indexes.map(i => messages[i]),
			s,
		];
		return [state, add_zkp_info, r_key_challenges];
	}

	async function BlindProofGenKeyProve(
		generator: PointG1,
		sk: bigint,
		challenge: BufferSource,
	): Promise<BufferSource> {
		return schnorr_sign_sha256_encode(generator, sk, challenge);
	}

	async function BlindProofGenKeyProveBls(
		sk: bigint,
		challenge: BufferSource,
	): Promise<BufferSource> {
		return Bbs.serialize([
			G2.hashToCurve(
				toU8(challenge),
				{ DST: toUtf8('BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_') },
			).multiply(sk),
		]);
	}

	type SchnorrNizkProof1 = [bigint, bigint];
	function schnorr_encode_signature(sig: SchnorrNizkProof1): ArrayBuffer {
		const [s, c] = sig;
		return Bbs.serialize([s, c]);
	}

	async function schnorr_sign_sha256(generator: PointG1, sk: bigint, m: BufferSource): Promise<SchnorrNizkProof1> {
		while (true) {
			const [omega] = await Bbs.real_calculate_random_scalars(1);
			const r = generator.multiply(omega);
			const c = OS2IP(await sha256(Bbs.serialize([r, m])));
			if (c < Fr.ORDER) {
				const s = Fr.add(omega, Fr.mul(c, sk));
				return [s, c];
			}
		}
	}

	async function schnorr_sign_sha256_encode(generator: PointG1, sk: bigint, m: BufferSource): Promise<ArrayBuffer> {
		return schnorr_encode_signature(await schnorr_sign_sha256(generator, sk, m));
	}

	async function CoreProofVerify(
		PK: BufferSource,
		proof: BufferSource,
		generators: PointG1[],
		blind_generators: PointG1[],
		keybind_generators: PointG1[],
		header: BufferSource,
		ph: BufferSource,
		disclosed_messages: bigint[],
		disclosed_indexes: number[],
		commitment_indexes: number[],
		api_id: BufferSource,
	): Promise<true> {
		const [Y_0, Y_1] = await Bbs.create_generators(2, concat(toUtf8("COM_DIS_"), api_id));

		const W = Bbs.octets_to_pubkey(PK);

		const proof_res = blind_octets_to_proof(proof);
		const [bbs_proof_res, commitments_proof_res, [randomized_keys, r_key_sig]] = proof_res;
		const [Abar, Bbar, D, ehat, r1hat, r3hat, hats, cp] = bbs_proof_res;
		const [commitments, commitments_proof] = commitments_proof_res;

		const N = commitments.length;
		const K = randomized_keys.length;
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
		if (!(keybind_generators.length === K && r_key_sig.length === K)) {
			throw new Error("Invalid key binding proofs or generators length", { cause: { K, keybind_generators, randomized_keys, r_key_sig } });
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

		const [Q1, ...Hi] = generators;
		const MsgGenerators = [...Hi, ...blind_generators];

		const [_Abar, _Bbar, _D, T1, T2_init, domain] = await Bbs.ProofVerifyInit(
			PK,
			[Abar, Bbar, D, ehat, r1hat, r3hat, hats, cp],
			[...generators, ...blind_generators, ...keybind_generators],
			header,
			disclosed_messages,
			disclosed_indexes,
			api_id,
		);

		const Bv = P1.add(Q1.multiply(domain)).add(sumprod(disclosed_indexes.map(i => MsgGenerators[i]), disclosed_messages));
		const Bv_add = sum(randomized_keys);
		const Y = Bv.add(Bv_add);
		const T2 = T2_init.add(Bv_add.multiply(cp))

		const C_hat = commitment_indexes.map((idx, i) => {
			const k = ji.indexOf(idx);
			const C_hat_i = Y_0.multiply(s_hat[i]).add(Y_1.multiply(m_hat[k])).subtract(C[i].multiply(cp));
			return C_hat_i;
		});

		const commitment_init_res = {
			commitments: C,
			commitments_proofs: C_hat,
			commitment_indexes,
		};

		const challenge = await ProofChallengeCalculate(
			[Abar, Bbar, D, Y, T1, T2, domain],
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

		if (!
			(await Promise.all(r_key_sig.map(([typ, sig], i) => {
				switch (typ) {
					case "SCHNORR":
						return schnorr_verify_sha256_encoded(keybind_generators[i], randomized_keys[i], sig, Bbs.serialize([randomized_keys[i], challenge]));

					case "BLS":
						return bls_verify_h2c_sha256_encoded(keybind_generators[i], randomized_keys[i], sig, Bbs.serialize([randomized_keys[i], challenge]));

					default:
						throw new Error("Unknown signature type: " + typ);
				}
			}))).every(valid => valid)
		) {
			throw new Error("Invalid proof: invalid key binding signature", { cause: { proof } })
		}
		return true;
	}

	function schnorr_parse_signature(sig: BufferSource): SchnorrNizkProof1 {
		const s = OS2IP(toU8(sig).slice(0, octet_scalar_length));
		const c = OS2IP(toU8(sig).slice(octet_scalar_length));
		return [s, c];
	}

	async function schnorr_verify_sha256(generator: PointG1, pk: PointG1, sig: SchnorrNizkProof1, m: BufferSource): Promise<true> {
		const [s, c] = sig;
		const c2 = OS2IP(await sha256(Bbs.serialize([generator.multiply(s).subtract(pk.multiply(c)), m])));
		if (c2 < Fr.ORDER && c == c2) {
			return true;
		}
		throw new Error("Invalid signature", { cause: { generator, pk, sig, m } });
	}

	function schnorr_verify_sha256_encoded(generator: PointG1, pk: PointG1, sig: BufferSource, m: BufferSource): Promise<true> {
		return schnorr_verify_sha256(generator, pk, schnorr_parse_signature(sig), m);
	}

	function bls_verify_h2c_sha256_encoded(generator: PointG1, pk: PointG1, sig: BufferSource, m: BufferSource): true {
		const sig_point = Bbs.octets_to_point_E2(sig);
		if (Fp12.eql(
			h(generator, sig_point),
			h(pk, G2.hashToCurve(toU8(m))),
		)) {
			return true;
		}
		throw new Error("Invalid BLS signature", { cause: { generator, pk, sig, m } });
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
		const domain = await Bbs.calculate_domain(PK, Q_1, [...H_Points, Q_2, ...J_Points], header, api_id);
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
		committed_points: PointG1[],
		api_id: BufferSource,
	): Promise<bigint> {
		const blind_challenge_dst = concat(api_id, toUtf8("H2S_"));

		if (generators.length === 0) {
			throw new Error("No generators", { cause: { generators } });
		}
		const N = committed_points.length;
		const M = generators.length - 1 - N;

		const c_arr = [M, N, ...generators, ...committed_points];
		const c_octs = Bbs.serialize([...c_arr, C, Cbar]);
		return Bbs.hash_to_scalar(c_octs, blind_challenge_dst);
	}

	async function ProofChallengeCalculate(
		init_res: [PointG1, PointG1, PointG1, PointG1, PointG1, PointG1, bigint],
		commitment_init_res: { commitments: PointG1[], commitments_proofs: PointG1[], commitment_indexes: number[] },
		disclosed_messages: bigint[],
		disclosed_indexes: number[],
		ph: BufferSource,
		api_id: BufferSource,
	): Promise<bigint> {
		const hash_to_scalar_dst = concat(api_id, toUtf8("H2S_"));

		const [Abar, Bbar, D, Y, T1, T2, domain] = init_res;

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

		const c_arr = [R, ...ii.flatMap((ii, i) => [ii, msg[i]]), Abar, Bbar, D, Y, T1, T2, domain];
		const commitment_arr = [N, ...i_i.flatMap((i_i, i) => [i_i, C[i], C_tilde[i]])];
		const c_octs = concat(Bbs.serialize(c_arr), Bbs.serialize(commitment_arr), I2OSP(ph.byteLength, 8), ph);
		return await Bbs.hash_to_scalar(c_octs, hash_to_scalar_dst);
	}

	function commit_state_to_octets(state: CommitState): BufferSource {
		const [K, C, s_hat, m_hat, challenge] = state;
		const M = m_hat.length;
		const N = K.length;
		return Bbs.serialize([M, N, ...K, C, s_hat, ...m_hat, challenge]);
	}

	function octets_to_commit_state(octets: BufferSource): CommitState {
		const state_len_floor = 8 + 8 + octet_point_length + 2 * octet_scalar_length;
		if (octets.byteLength < state_len_floor) {
			throw new Error(`State too short: expected at least ${state_len_floor} octets, was ${octets.byteLength}`, {
				cause:
					{ octets }
			});
		}
		const [[M_octs, N_octs], rest] = split_sections(toU8(octets), [8, 8]);
		const M = Number(OS2IP(M_octs));
		const N = Number(OS2IP(N_octs));
		const state_len = state_len_floor + N * octet_point_length + M * octet_scalar_length;
		if (octets.byteLength !== state_len) {
			throw new Error(`Invalid state length: expected ${state_len} octets, was ${octets.byteLength}`, {
				cause: {
					octets,
					state_len
				}
			});
		}
		const [[K_octs, C_octs, s_hat_octs, m_hat_octs, challenge_octs], tail] = split_sections(
			rest,
			[N * octet_point_length, octet_point_length, octet_scalar_length, M * octet_scalar_length, octet_scalar_length],
		);
		if (tail.byteLength !== 0) {
			throw new Error("Trailing octets", { cause: { octets, state_len, tail } });
		}

		return [
			split_sections(K_octs, range(N).map(() => octet_point_length))[0].map(Bbs.octets_to_point_E1),
			Bbs.octets_to_point_E1(C_octs),
			OS2IP(s_hat_octs),
			split_sections(m_hat_octs, range(M).map(() => octet_scalar_length))[0].map(OS2IP),
			OS2IP(challenge_octs),
		];
	}

	function commitment_with_proof_to_octets(
		commitment: [PointG1, PointG1[]],
		proof: [bigint, bigint[], bigint, [bigint, bigint][]],
	): BufferSource {
		const [C, K] = commitment;
		const [s_hat, m_hat, challenge, point_proofs] = proof;
		const proof_octs = Bbs.serialize([
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
			8 + 8 // M and N
			+ octet_point_length // Signer-blind commitment
			+ N * octet_point_length // Holder-blind commitments
			+ octet_scalar_length // Signer-blind commitment proof
			+ M * octet_scalar_length // Signer-known messages
			+ octet_scalar_length // Holder-known commitment challenge
			+ N * 2 * octet_scalar_length // Holder-blind commitment proofs
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

		const C = Bbs.octets_to_point_E1(C_octets);
		if (C.is0()) {
			throw new Error("C must not be Identity_G1", { cause: { commitment_octs } });
		}
		const K = split_sections(K_octets, range(N).map(() => octet_point_length))[0].map(Bbs.octets_to_point_E1);

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

	function blind_proof_gen_state_to_octets(
		incomplete_proof: BufferSource,
		challenge: bigint,
		r_key: bigint[],
	): BufferSource {
		return Bbs.serialize([
			incomplete_proof,
			challenge,
			...r_key,
		]);
	}

	function octets_to_blind_proof_gen_state(
		octs: BufferSource,
	): [BufferSource, BufferSource, bigint[]] {
		const octs_u8 = toU8(octs);
		const K = Number(OS2IP(octs_u8.slice(8, 16)));

		let sidx = octs_u8.byteLength - K * octet_scalar_length;
		const r_key = range(K).map(i => OS2IP(octs_u8.slice(
			sidx + i * octet_scalar_length,
			sidx + (i + 1) * octet_scalar_length,
		)));

		const challenge_len = octet_scalar_length;
		sidx = sidx - challenge_len;
		const challenge = octs_u8.slice(sidx, sidx + challenge_len);

		const incomplete_proof = octs_u8.slice(0, sidx);
		return [incomplete_proof, challenge, r_key];
	}

	function incomplete_proof_octets_to_randomized_keys(
		incomplete_proof: BufferSource,
	): PointG1[] {
		const incomplete_proof_u8 = toU8(incomplete_proof);
		const K = Number(OS2IP(incomplete_proof_u8.slice(8, 16)));
		const sidx = incomplete_proof.byteLength - K * octet_point_length;
		return range(K).map(i => Bbs.octets_to_point_E1(incomplete_proof_u8.slice(
			sidx + i * octet_point_length,
			sidx + (i + 1) * octet_point_length,
		)));
	}

	function incomplete_blind_proof_to_octets(
		bbs_proof_len: number,
		bbs_proof: BufferSource,
		commitments_count: number,
		commitments_proof: [PointG1[], bigint[]],
		randomized_keys: PointG1[],
	): BufferSource {
		const oct = concat(
			I2OSP(bbs_proof_len, 8),
			I2OSP(randomized_keys.length, 8),
			bbs_proof,
			I2OSP(commitments_count, 8),
			Bbs.serialize(commitments_proof.flat()),
			Bbs.serialize(randomized_keys),
		);
		return oct;
	}

	function key_bind_sigs_to_octets(
		sigs: KeyBindingSignature[],
	): BufferSource {
		return Bbs.serialize(sigs.flatMap(([typ, sig]) =>
			[["SCHNORR", "BLS"].indexOf(typ), sig]
		));
	}

	function blind_octets_to_proof(proof_octets: BufferSource): [
		[PointG1, PointG1, PointG1, bigint, bigint, bigint, bigint[], bigint],
		[PointG1[], bigint[]],
		KeyBindingProof,
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
		eidx = sidx + 8;
		const K = Number(OS2IP(proof_octets_u8.slice(sidx, eidx)));

		sidx = eidx;
		eidx = sidx + bbs_proof_len;
		if (proof_octets.byteLength < eidx) {
			throw new Error(`Proof too short: expected at least ${eidx} octets, was ${proof_octets.byteLength}`, { cause: { proof_octets, eidx } });
		}
		const bbs_proof_octs = proof_octets_u8.slice(sidx, eidx);
		const bbs_proof = Bbs.octets_to_proof(bbs_proof_octs);

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
			return Bbs.octets_to_point_E1(proof_octets_u8.slice(sidx, eidx));
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

		const randomized_keys = range(K).map(() => {
			sidx = eidx;
			eidx = sidx + octet_point_length;
			return Bbs.octets_to_point_E1(proof_octets_u8.slice(sidx, eidx));
		});
		const [r_key_sigs, deidx] = octets_to_key_bind_sigs(K, proof_octets_u8.slice(eidx));
		eidx = eidx + deidx;

		const key_binding_proof: KeyBindingProof = [randomized_keys, r_key_sigs];

		if (proof_octets.byteLength !== eidx) {
			throw new Error(
				proof_octets.byteLength > eidx ? "Trailing octets" : "Insufficcient octets",
				{ cause: { proof_octets, eidx } },
			);
		}

		return [bbs_proof, commitments_proof, key_binding_proof];
	}

	type KeyBindingProof = [PointG1[], KeyBindingSignature[]];
	type KeyBindingSignature = ["SCHNORR" | "BLS", BufferSource];

	function octets_to_key_bind_sigs(
		K: number,
		octs: BufferSource,
	): [KeyBindingSignature[], number] {
		let tail = toU8(octs);
		let sigs: ["SCHNORR" | "BLS", BufferSource][] = [];
		for (let i = 0; i < K; ++i) {
			const typ = Number(OS2IP(tail.slice(0, 8)));
			let L;
			let tag: "SCHNORR" | "BLS" | undefined;
			switch (typ) {
				case 0:
					L = 2 * octet_scalar_length;
					tag = "SCHNORR";
					break;

				case 1:
					L = 2 * octet_point_length;
					tag = "BLS";
					break;

				default:
					throw new Error("Unkown signature type:" + typ);
			}
			sigs.push([tag, tail.slice(8, 8 + L)]);
			tail = tail.slice(8 + L);
		}
		return [sigs, octs.byteLength - tail.byteLength];
	}

	return {
		api_id,
		Commit,
		BlindSign,
		VerifyBlindSign,
		BlindProofGen,
		BlindProofGenInit,
		BlindProofGenFinalize,
		BlindProofGenKeyProve,
		BlindProofGenKeyProveBls,
		BlindProofVerify,
		CommitInit,
		CommitFinalize,
		CommitVerify: (commitment_with_proof) => deserialize_and_validate_commit(commitment_with_proof, api_id),
		CoreCommitInit,
		CoreCommitProve,
		CoreCommitFinalize,
		CoreCommitVerify,
		create_unblind_generators,
		create_blind_generators,
		create_keybind_generators,
	};
}

export type PointG1 = WeierstrassPoint<bigint>;
type PointG2 = WeierstrassPoint<Fp2>;

export type DisclosureChoice = "DISCLOSE" | "HIDE" | "COMMIT";

type CommitState = [PointG1[], PointG1, bigint, bigint[], bigint];
type BlindBbsSuite = {
	api_id: BufferSource,

	Commit(
		committed_messages: BufferSource[],
	): Promise<[BufferSource, bigint]>;

	CommitInit(
		committed_messages: BufferSource[] | null,
		committed_points: BufferSource[] | null,
	): Promise<[BufferSource, bigint, BufferSource]>;

	CommitFinalize(
		state: BufferSource,
		committed_point_proofs: BufferSource[] | null,
	): Promise<BufferSource>;

	CommitVerify(
		commitment_with_proof: BufferSource,
	): Promise<[PointG1, PointG1[], PointG1, PointG1[], PointG1[]]>;

	CoreCommitInit(
		blind_generators: PointG1[],
		keybind_generators: PointG1[],
		committed_scalars: bigint[],
		committed_points: PointG1[],
		api_id: BufferSource,
	): Promise<[CommitState, BufferSource, bigint]>;

	CoreCommitProve(
		committed_point_secret: bigint,
		generator: PointG1,
		challenge: BufferSource,
	): Promise<[bigint, bigint]>;

	CoreCommitFinalize(
		state: CommitState,
		committed_point_proofs: [bigint, bigint][],
	): Promise<[[PointG1, PointG1[]], [bigint, bigint[], bigint, [bigint, bigint][]]]>;

	CoreCommitVerify(
		[commitment, committed_points]: [PointG1, PointG1[]],
		commitment_proof: [bigint, bigint[], bigint, [bigint, bigint][]],
		blind_generators: PointG1[],
		keybind_generators: PointG1[],
		api_id: BufferSource,
	): Promise<true>;

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
		committed_points: BufferSource[] | null,
		issuer_known_messages_no: number | null,
		secret_prover_blind: bigint | null,
	): Promise<true>;

	BlindProofGen(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		signer_messages: BufferSource[] | null,
		prover_messages: BufferSource[] | null,
		signer_message_disclosures: DisclosureChoice[] | null,
		prover_message_disclosures: DisclosureChoice[] | null,
		secret_prover_blind: bigint | null,
	): Promise<[BufferSource, [bigint[], bigint[]]]>;

	BlindProofGenInit(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		signer_messages: BufferSource[] | null,
		prover_messages: BufferSource[] | null,
		prover_binding_public_keys: BufferSource[] | null,
		signer_message_disclosures: DisclosureChoice[] | null,
		prover_message_disclosures: DisclosureChoice[] | null,
		secret_prover_blind: bigint | null,
	): Promise<[BufferSource, [bigint[], bigint[]], BufferSource[]]>;

	BlindProofGenFinalize(
		state: BufferSource,
		prover_binding_signatures: BufferSource[] | null,
	): Promise<BufferSource>;

	BlindProofGenKeyProve(
		generator: PointG1,
		sk: bigint,
		challenge: BufferSource,
	): Promise<BufferSource>;

	BlindProofGenKeyProveBls(
		sk: bigint,
		challenge: BufferSource,
	): Promise<BufferSource>;

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
	create_keybind_generators(count: number): Promise<PointG1[]>,
}

type CipherSuite = {
	params: Bbs.SuiteParams,
	Bbs: Bbs.CipherSuite,
	BlindBbs: BlindBbsSuite,
}


export function getCipherSuite(
	suiteId: Bbs.SuiteId,
	overrides?: {
		mocked_random_scalars_params?: { SEED: BufferSource, DST: BufferSource },
		create_generators_dsts?: Bbs.CreateGeneratorsDsts,
	},
): CipherSuite {
	const BbsSuite = Bbs.getCipherSuite(suiteId, overrides);
	if (BbsSuite) {
		return {
			params: BbsSuite.params,
			Bbs: BbsSuite,
			BlindBbs: createSuite(BbsSuite),
		};
	} else {
		throw new Error(`Unknown suite: ${suiteId}`, { cause: { suiteId } });
	}
}
