import type { Fp2 } from "@noble/curves/abstract/tower";

import { concat, I2OSP, isStrictlyIncreasing, OS2IP, range, toHex, toU8, toUtf8 } from "../utils/util";
import { sha256 } from "../arkg/hash_to_curve";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import * as Bbs from ".";
import * as util from "./util";


function createSuite(suite_id: SuiteId, Bbs: Bbs.CipherSuite, Sig: SignatureScheme): BlindBbsSuite {
	const suite = Bbs.params;
	const {
		curves: { G1, G2, pairing: h, fields: { Fr, Fp12 } },
		P1,
		octet_point_length,
		octet_scalar_length,
	} = suite;

	const sum = (points: PointG1[]) => util.sum(G1, points);
	const sumprod = (points: PointG1[], scalars: bigint[]) => util.sumprod(G1, points, scalars);

	const api_id = toUtf8(suite_id + "BLIND_H2G_HM2S_");

	async function Commit(
		committed_messages: BufferSource[] | null,
	): Promise<[BufferSource, bigint]> {
		committed_messages = committed_messages ?? [];

		const [state, secret_prover_blind,] = await CommitInit(committed_messages, []);
		const commitment_with_proof = await CommitFinalize(state, null);
		return [commitment_with_proof, secret_prover_blind];
	}

	async function CommitInit(
		committed_messages: BufferSource[] | null,
		keybind_public_keys: BufferSource[] | null,
	): Promise<[BufferSource, bigint, BufferSource]> {
		committed_messages = committed_messages ?? [];
		keybind_public_keys = keybind_public_keys ?? [];

		const K = keybind_public_keys.length;
		const PKs = keybind_public_keys.map(octs => {
			const PK_i = Bbs.octets_to_point_E1(octs);
			if (PK_i.is0()) {
				throw new Error("Invalid public key");
			}
			return PK_i;
		});
		const committed_message_scalars = await Bbs.messages_to_scalars(committed_messages, api_id);
		const blind_generators = await Bbs.create_generators(committed_message_scalars.length + 1, concat(toUtf8("BLIND_"), api_id));
		const keybind_generators = [G1.Point.BASE, ...await Bbs.create_generators(K - 1, concat(toUtf8("KEYBIND_"), api_id))].slice(0, K);
		const [state, secret_prover_blind, challenge] = await CoreCommitInit(
			[...blind_generators, ...keybind_generators],
			committed_message_scalars,
			PKs,
			api_id,
		);
		return [commitment_state_to_octets(state), secret_prover_blind, Bbs.serialize([challenge])];
	}

	async function CommitFinalize(
		state: BufferSource,
		keybind_signatures: BufferSource[] | null,
	): Promise<BufferSource> {
		keybind_signatures = keybind_signatures ?? [];

		const state_res = octets_to_commitment_state(state);
		const [_C, _s_hat, _m_hat, _challenge, keybind_public_keys] = state_res;
		const K = keybind_public_keys.length;
		if (keybind_signatures.length !== K) {
			throw new Error("Invalid keybind_signatures length");
		}

		const [commitment, commitment_proof] = await CoreCommitFinalize(state_res, keybind_signatures);
		return commitment_with_proof_to_octets(commitment, commitment_proof);
	}

	async function deserialize_and_validate_commit(
		commitment_with_proof: BufferSource,
		api_id: BufferSource,
	): Promise<[[PointG1, PointG1[]], PointG1[]]> {
		if (commitment_with_proof.byteLength === 0) {
			return [[G1.Point.ZERO, []], await Bbs.create_generators(1, concat(toUtf8("BLIND_"), api_id))];
		}

		const com_res = octets_to_commitment_with_proof(toU8(commitment_with_proof));
		const [[commitment, keybind_public_keys], commitment_proof] = com_res;
		const [_s_hat, m_hat, _challenge, keybind_signatures] = commitment_proof;
		const blind_generators = await Bbs.create_generators(m_hat.length + 1, concat(toUtf8("BLIND_"), api_id));
		const keybind_generators = [G1.Point.BASE, ...await Bbs.create_generators(keybind_signatures.length - 1, concat(toUtf8("KEYBIND_"), api_id))].slice(0, keybind_signatures.length);
		const generators = [...blind_generators, ...keybind_generators];
		await CoreCommitVerify(commitment, keybind_public_keys, commitment_proof, generators, api_id);
		return [[commitment, keybind_public_keys], generators];
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
		const deserialize_res = await deserialize_and_validate_commit(commitment_with_proof, api_id);
		const [[commitment, keybind_public_keys], blind_generators] = deserialize_res;

		const message_scalars = await Bbs.messages_to_scalars(messages, api_id);
		const generators = await Bbs.create_generators(L + 1, api_id);
		const res = await B_calculate(PK, generators, blind_generators,
			commitment.add(sum(keybind_public_keys)),
			message_scalars, header, api_id);
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
		keybind_public_keys: BufferSource[] | null,
		secret_prover_blind: bigint | null,
	): Promise<true> {
		header = header ?? new Uint8Array([]);
		messages = messages ?? [];
		keybind_public_keys = keybind_public_keys ?? [];
		issuer_known_messages_no = issuer_known_messages_no ?? 0;
		secret_prover_blind = secret_prover_blind ?? 0n;
		const L = messages.length;
		if (issuer_known_messages_no > L) {
			throw new Error("Too many issuer-known messages", { cause: { messages, issuer_known_messages_no } });
		}
		const K = keybind_public_keys.length;
		const PKs = keybind_public_keys.map(octs => {
			const PK_i = Bbs.octets_to_point_E1(octs);
			if (PK_i.is0()) {
				throw new Error("Invalid public key");
			}
			return PK_i;
		});

		const generators = await Bbs.create_generators(issuer_known_messages_no + 1, api_id);
		const blind_generators = await Bbs.create_generators(L - issuer_known_messages_no + 1, concat(toUtf8("BLIND_"), api_id));
		const keybind_generators = [G1.Point.BASE, ...await Bbs.create_generators(K - 1, concat(toUtf8("KEYBIND_"), api_id))].slice(0, K);
		const message_scalars = await Bbs.messages_to_scalars(messages, api_id);
		const signer_scalars = message_scalars.slice(0, issuer_known_messages_no);
		const committed_message_scalars = message_scalars.slice(issuer_known_messages_no);
		const proof_scalars = [...signer_scalars, secret_prover_blind, ...committed_message_scalars];
		const res = await CoreVerify(
			PK,
			signature,
			[...generators, ...blind_generators, ...keybind_generators],
			header,
			proof_scalars,
			PKs,
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
		const [state, add_zkp_info, _keybind_challenges] = await BlindProofGenInit(
			PK,
			signature,
			header,
			ph,
			messages,
			issuer_known_messages_no,
			message_disclosures,
			[],
			secret_prover_blind,
		);
		const proof = await BlindProofGenFinalize(state, []);
		return [proof, add_zkp_info];
	}

	async function BlindProofGenInit(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		messages: BufferSource[] | null,
		issuer_known_messages_no: number | null,
		message_disclosures: DisclosureChoice[] | null,
		keybind_public_keys: BufferSource[] | null,
		secret_prover_blind: bigint | null,
	): Promise<[BufferSource, [bigint[], bigint[]], BufferSource[]]> {
		header = header ?? new Uint8Array([]);
		ph = ph ?? new Uint8Array([]);
		messages = messages ?? [];
		issuer_known_messages_no = issuer_known_messages_no ?? 0;
		keybind_public_keys = keybind_public_keys ?? [];
		message_disclosures = message_disclosures ?? [];
		secret_prover_blind = secret_prover_blind ?? 0n;

		const L = messages.length;
		if (message_disclosures.length !== L) {
			throw new Error("Invalid message disclosures length");
		}
		if (issuer_known_messages_no > L) {
			throw new Error("Invalid issuer_known_messages_no");
		}
		const disclosed_indexes = range(L).filter(i => message_disclosures[i] === "DISCLOSE");
		const commitment_indexes = range(L).filter(i => message_disclosures[i] === "COMMIT");
		const K = keybind_public_keys.length;
		const PKs = keybind_public_keys.map(octs => {
			const PK_i = Bbs.octets_to_point_E1(octs);
			if (PK_i.is0()) {
				throw new Error("Invalid public key");
			}
			return PK_i;
		});

		const generators = await Bbs.create_generators(issuer_known_messages_no + 1, api_id);
		const blind_generators = await Bbs.create_generators(L - issuer_known_messages_no + 1, concat(toUtf8("BLIND_"), api_id));
		const keybind_generators = [G1.Point.BASE, ...await Bbs.create_generators(K - 1, concat(toUtf8("KEYBIND_"), api_id))].slice(0, K);
		const message_scalars = await Bbs.messages_to_scalars(messages, api_id);
		const signer_scalars = message_scalars.slice(0, issuer_known_messages_no);
		const committed_message_scalars = message_scalars.slice(issuer_known_messages_no);
		const proof_scalars = [...signer_scalars, secret_prover_blind, ...committed_message_scalars];
		const proof_index = range(L).map(i => i < issuer_known_messages_no ? i : i + 1);
		const proof_disclosed_indexes = disclosed_indexes.map(i => proof_index[i]);
		const proof_commitment_indexes = commitment_indexes.map(i => proof_index[i]);
		const state_and_add_zkp_info_and_keybind_challenges = await CoreProofGenInit(
			PK,
			signature,
			[...generators, ...blind_generators, ...keybind_generators],
			header,
			ph,
			proof_scalars,
			proof_disclosed_indexes,
			proof_commitment_indexes,
			PKs,
			api_id,
		);
		return state_and_add_zkp_info_and_keybind_challenges;
	}

	async function BlindProofGenFinalize(
		state: BufferSource,
		keybind_signatures: BufferSource[] | null,
	): Promise<BufferSource> {
		keybind_signatures = keybind_signatures ?? [];

		const state_res = octets_to_proof_gen_state(state);
		const [incomplete_proof, challenge, keybind_randomized_keys, r_key] = state_res;
		const K = keybind_randomized_keys.length;
		if (keybind_signatures.length !== K) {
			throw new Error("Invalid key binding signatures length");
		}

		let proof = incomplete_proof;
		const PK_tilde_octs = [];
		for (let i = 1; i <= K; ++i) {
			PK_tilde_octs.push(Bbs.serialize([keybind_randomized_keys[i - 1]]));
			proof = concat(proof, PK_tilde_octs[i - 1]);
		}
		for (let i = 1; i <= K; ++i) {
			proof = concat(proof, await Sig.AdaptSig(
				keybind_signatures[i - 1],
				r_key[i - 1],
				await sha256(concat(PK_tilde_octs[i - 1], Bbs.serialize([challenge])))));
		}
		return proof;
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
		const N = Number(OS2IP(proof_u8.slice(8, 16)));
		const K = Number(OS2IP(proof_u8.slice(16, 24)));
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
		if (commitment_indexes.length !== N) {
			throw new Error("Invalid commitments", { cause: { commitment_indexes, N } });
		}
		const proof_index = range(total_msgs_no).map(i => i < issuer_known_messages_no ? i : i + 1);
		const proof_disclosed_indexes = disclosed_indexes.map(i => proof_index[i]);
		const proof_commitment_indexes = commitment_indexes.map(i => proof_index[i]);

		const generators = await Bbs.create_generators(issuer_known_messages_no + 1, api_id);
		const blind_generators = await Bbs.create_generators(total_msgs_no - issuer_known_messages_no + 1, concat(toUtf8("BLIND_"), api_id));
		const keybind_generators = [G1.Point.BASE, ...await Bbs.create_generators(K - 1, concat(toUtf8("KEYBIND_"), api_id))].slice(0, K);
		const message_scalars = await Bbs.messages_to_scalars(disclosed_messages, api_id);
		const result = await CoreProofVerify(
			PK,
			proof_u8,
			[...generators, ...blind_generators, ...keybind_generators],
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
		committed_message_scalars: bigint[],
		keybind_public_keys: PointG1[],
		api_id: BufferSource,
	): Promise<[CommitState, bigint, bigint]> {
		const M = committed_message_scalars.length;
		const K = keybind_public_keys.length;
		if (blind_generators.length !== M + K + 1) {
			throw new Error("Invalid number blind generators", { cause: { blind_generators, committed_scalars: committed_message_scalars } });
		}
		const [Q_2, ...Js_and_KJs] = blind_generators;
		const Js = Js_and_KJs.slice(0, M);
		const msg = committed_message_scalars;

		const [secret_prover_blind, s_tilde, ...m_tilde] = await Bbs.calculate_random_scalars(M + 2);
		const C = sumprod([...Js, Q_2], [...msg, secret_prover_blind]);
		const Cbar = sumprod([...Js, Q_2], [...m_tilde, s_tilde]);
		const challenge = await calculate_blind_challenge(C, Cbar, blind_generators, keybind_public_keys, api_id);
		const s_hat = Fr.add(s_tilde, Fr.mul(secret_prover_blind, challenge));
		const m_hat = m_tilde.map((m_tilde_i, i) => (Fr.add(m_tilde_i, Fr.mul(msg[i], challenge))));

		const state: CommitState = [C, s_hat, m_hat, challenge, keybind_public_keys];
		return [state, secret_prover_blind, challenge];
	}

	async function CoreCommitFinalize(
		state: CommitState,
		keybind_signatures: BufferSource[],
	): Promise<[[PointG1, PointG1[]], [bigint, bigint[], bigint, BufferSource[]]]> {
		const [C, s_hat, m_hat, challenge, keybind_public_keys] = state;
		const K = keybind_public_keys.length;
		if (keybind_signatures.length !== K) {
			throw new Error("Invalid number of keybind_signatures", { cause: { committed_points: keybind_public_keys, committed_point_proofs: keybind_signatures } });
		}
		return [
			[C, keybind_public_keys],
			[s_hat, m_hat, challenge, keybind_signatures],
		];
	}

	async function CoreCommitVerify(
		commitment: PointG1,
		keybind_public_keys: PointG1[],
		commitment_proof: [bigint, bigint[], bigint, BufferSource[]],
		blind_generators: PointG1[],
		api_id: BufferSource,
	): Promise<true> {
		const [s_hat, commitments, cp, keybind_signatures] = commitment_proof;

		const M = commitments.length;
		const K = keybind_public_keys.length;
		const m_hat = commitments;

		if (blind_generators.length !== M + K + 1) {
			throw new Error("Invalid number of generators", {
				cause: { blind_generators, commitments }
			});
		}
		if (keybind_signatures.length !== K) {
			throw new Error("Invalid number of key binding signatures", {
				cause: { keybind_public_keys, keybind_signatures }
			});
		}

		const [Q_2, ...Js_and_KJs] = blind_generators;
		const Js = Js_and_KJs.slice(0, M);
		const KJs = Js_and_KJs.slice(M);

		const Cbar = sumprod([...Js, Q_2, commitment], [...m_hat, s_hat, Fr.neg(cp)]);
		const cv = await calculate_blind_challenge(commitment, Cbar, blind_generators, keybind_public_keys, api_id);
		if (cv === cp) {
			if (
				(await Promise.all(keybind_signatures.map(async (sig, i) => {
					if (await Sig.Verify(KJs[i], keybind_public_keys[i], sig, Bbs.serialize([cp]))) {
						return true;
					}
					throw new Error("Invalid key binding signature");
				}))).every(result => result === true)
			) {
				return true;
			}
		}
		throw new Error("Invalid proof", { cause: { commitment, commitment_proof, blind_generators, committed_points: keybind_public_keys, api_id } });
	}

	async function FinalizeBlindSign(
		SK: bigint,
		B: PointG1,
		api_id: BufferSource,
	): Promise<BufferSource> {
		const signature_dst = concat(api_id, toUtf8("H2S_"));

		if (B.is0()) {
			throw new Error("B must not be identity_G1");
		}
		const e_octs = Bbs.serialize([SK, B]);
		const e = await Bbs.hash_to_scalar(e_octs, signature_dst);
		const A = B.multiply(Fr.inv(Fr.add(SK, e)));
		return Bbs.signature_to_octets(A, e);
	}

	async function CoreVerify(
		PK: BufferSource,
		signature: BufferSource,
		generators: PointG1[],
		header: BufferSource,
		messages: bigint[],
		keybind_public_keys: PointG1[],
		api_id: BufferSource,
	): Promise<true> {
		const signature_result = Bbs.octets_to_signature(signature);
		const [A, e] = signature_result;
		const W = Bbs.octets_to_pubkey(PK);
		const L = messages.length;
		const K = keybind_public_keys.length;
		if (generators.length !== L + K + 1) {
			throw new Error("Messages, public keys and generators not of matching lengths", { cause: { messages, keybind_public_keys, generators } });
		}
		const msg = messages;
		const [Q_1, ...Hs_and_KJs] = generators;
		const Hs = Hs_and_KJs.slice(0, L);

		const domain = await Bbs.calculate_domain(PK, Q_1, Hs_and_KJs, header, api_id);
		const B = P1
			.add(Q_1.multiply(domain))
			.add(sumprod(Hs, msg))
			.add(sum(keybind_public_keys));
		if (Fp12.eql(
			Fp12.mul(h(A, W), h(A.multiply(e).subtract(B), G2.Point.BASE)),
			Fp12.ONE,
		)) {
			return true;
		}
		throw new Error("Invalid signature", { cause: { PK, signature, header, messages } });
	}

	async function CoreProofGenInit(
		PK: BufferSource,
		signature: BufferSource,
		generators: PointG1[],
		header: BufferSource,
		ph: BufferSource,
		messages: bigint[],
		disclosed_indexes: number[],
		commitment_indexes: number[],
		keybind_public_keys: PointG1[],
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
		const K = keybind_public_keys.length;
		const disclosed_messages = disclosed_indexes.map(i => messages[i]);
		const undisclosed_indexes = range(L).filter(i => !disclosed_set.has(i));
		const ji = undisclosed_indexes;
		const undisclosed_messages = undisclosed_indexes.map(i => messages[i]);
		const PKs = keybind_public_keys;

		const init_random_scalars = await Bbs.calculate_random_scalars(5 + U + 2 * K);
		const [r1, r2, e_tilde, r1_tilde, r3_tilde, ...m_tilde_and_r_key_tilde_and_r_key] = init_random_scalars;
		const m_tilde = m_tilde_and_r_key_tilde_and_r_key.slice(0, U);
		const m_tilde_and_r_key_tilde = m_tilde_and_r_key_tilde_and_r_key.slice(0, U + K);
		const r_key = m_tilde_and_r_key_tilde_and_r_key.slice(U + K);

		const init_res = await Bbs.ProofInit(
			PK,
			signature_result,
			generators,
			[r1, r2, e_tilde, r1_tilde, r3_tilde, ...m_tilde_and_r_key_tilde],
			header,
			[...messages, ...range(K).map(() => 0n)],
			[...undisclosed_indexes, ...range(K).map(i => L + i)],
			api_id,
		);
		const [Abar, Bbar_init, D_init, T1_init, T2_init, domain] = init_res;
		const D_add = sum(PKs).multiply(r2);
		const D = D_init.add(D_add);
		const Bbar = Bbar_init.add(D_add.multiply(r1));
		const T1 = T1_init.add(D_add.multiply(r1_tilde));
		const T2 = T2_init.add(D_add.multiply(r3_tilde));
		const PK_tildes = range(K).map(i => i + 1).map(i => PKs[i - 1].add(generators[L + 1 + i - 1].multiply(r_key[i - 1])));

		const s_and_s_tilde = await Bbs.calculate_random_scalars(2 * N);
		const s = s_and_s_tilde.slice(0, N);
		const s_tilde = s_and_s_tilde.slice(N);
		const Cs_and_C_tildes = range(N).map(i => i + 1).map(i => {
			const idx = commitment_indexes[i - 1];
			const Ci = Y_0.multiply(s[i - 1]).add(Y_1.multiply(messages[idx]));
			const k = ji.indexOf(idx) + 1;
			const C_tilde_i = Y_0.multiply(s_tilde[i - 1]).add(Y_1.multiply(m_tilde[k - 1]));
			return [Ci, C_tilde_i];
		});

		const commitment_init_res = {
			commitments: Cs_and_C_tildes.map(([Ci, _]) => Ci),
			commitments_proofs: Cs_and_C_tildes.map(([_, C_tilde_i]) => C_tilde_i),
			commitment_indexes,
		};

		const challenge = await ProofChallengeCalculate(
			[Abar, Bbar, D, T1, T2, domain],
			commitment_init_res,
			PK_tildes,
			disclosed_messages,
			disclosed_indexes,
			ph,
			api_id,
		);

		const bbs_proof = Bbs.ProofFinalize(
			[Abar, Bbar, D, T1, T2, domain],
			challenge,
			e,
			[r1, r2, e_tilde, r1_tilde, r3_tilde, ...m_tilde_and_r_key_tilde],
			[...undisclosed_messages, ...r_key.map(rk => Fr.neg(rk))],
		);

		const s_hat = s_tilde.map((s_tilde, i) => Fr.add(s_tilde, Fr.mul(challenge, s[i])));
		const commitments_proof: [PointG1[], bigint[]] = [commitment_init_res.commitments, s_hat];

		const state = proof_gen_state_to_octets(bbs_proof, challenge, commitments_proof, PK_tildes, r_key);
		const c_r_key = await Promise.all(range(K).map(i => sha256(Bbs.serialize([PK_tildes[i], challenge]))));
		const add_zkp_info: [bigint[], bigint[]] = [
			commitment_indexes.map(i => messages[i]),
			s,
		];
		return [state, add_zkp_info, c_r_key];
	}

	async function CoreProofVerify(
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
		const [Y_0, Y_1] = await Bbs.create_generators(2, concat(toUtf8("COM_DIS_"), api_id));

		const W = Bbs.octets_to_pubkey(PK);

		const proof_res = octets_to_proof(proof);
		const [bbs_proof_res, commitments_proof_res, [keybind_randomized_keys, keybind_signatures]] = proof_res;

		const [_Abar, _Bbar, _D, _ehat, _r1hat, _r3hat, hats, cp] = bbs_proof_res;
		const [commitments, commitments_proof] = commitments_proof_res;

		const N = commitments.length;
		const K = keybind_randomized_keys.length;
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
		if (generators.length !== L + 1) {
			throw new Error("Invalid generators length", { cause: { L, generators } });
		}
		if (keybind_signatures.length !== K) {
			throw new Error("Invalid key binding signatures length", { cause: { K, keybind_randomized_keys, keybind_signatures } });
		}

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
		const PK_tildes = keybind_randomized_keys;

		const init_res = await Bbs.ProofVerifyInit(
			PK,
			bbs_proof_res,
			generators,
			header,
			disclosed_messages,
			disclosed_indexes,
			api_id,
		);
		const [Abar, Bbar, D, T1, T2_init, domain] = init_res;
		const T2 = T2_init.add(sum(PK_tildes).multiply(cp))

		const C_hat = range(N).map(i => i + 1).map(i => {
			const idx = commitment_indexes[i - 1];
			const k = ji.indexOf(idx) + 1;
			const C_hat_i = Y_0.multiply(s_hat[i - 1]).add(Y_1.multiply(m_hat[k - 1])).subtract(C[i - 1].multiply(cp));
			return C_hat_i;
		});

		const commitment_init_res = {
			commitments: C,
			commitments_proofs: C_hat,
			commitment_indexes,
		};

		const challenge = await ProofChallengeCalculate(
			[Abar, Bbar, D, T1, T2, domain],
			commitment_init_res,
			keybind_randomized_keys,
			disclosed_messages,
			disclosed_indexes,
			ph,
			api_id,
		);
		if (cp !== challenge) {
			throw new Error(`Invalid proof: incorrect challenge: expected ${challenge}, was ${cp}`, { cause: { proof } })
		}

		if (!
			(await Promise.all(keybind_signatures.map(async (sig, i) => {
				if (await Sig.Verify(
					generators[L + 1 - K + i],
					keybind_randomized_keys[i],
					sig,
					await sha256(Bbs.serialize([keybind_randomized_keys[i], challenge])),
				)) {
					return true;
				}
				throw new Error("Invalid signature");
			}))).every(valid => valid)
		) {
			throw new Error("Invalid proof: invalid key binding signature", { cause: { proof } })
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
		keybind_public_keys: PointG1[],
		api_id: BufferSource,
	): Promise<bigint> {
		const blind_challenge_dst = concat(api_id, toUtf8("H2S_"));

		if (generators.length === 0) {
			throw new Error("No generators", { cause: { generators } });
		}
		const K = keybind_public_keys.length;
		const M = generators.length - 1 - K;

		const c_arr = [M, K, ...generators, ...keybind_public_keys];
		const c_octs = Bbs.serialize([...c_arr, C, Cbar]);
		return Bbs.hash_to_scalar(c_octs, blind_challenge_dst);
	}

	async function ProofChallengeCalculate(
		init_res: [PointG1, PointG1, PointG1, PointG1, PointG1, bigint],
		commitment_init_res: { commitments: PointG1[], commitments_proofs: PointG1[], commitment_indexes: number[] },
		keybind_randomized_keys: PointG1[],
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
		const K = keybind_randomized_keys.length;

		if (R > Math.pow(2, 64) - 1) {
			throw new Error("Too many disclosed indexes", { cause: { disclosed_indexes } });
		}
		if (ph.byteLength > Math.pow(2, 64) - 1) {
			throw new Error("Presentation header too long", { cause: { ph } });
		}

		const c_arr = [R, ...ii.flatMap((ii, i) => [ii, msg[i]]), Abar, Bbar, D, T1, T2, domain];
		const commitment_arr = [N, ...i_i.flatMap((i_i, i) => [i_i, C[i], C_tilde[i]])];
		const c_octs = concat(
			Bbs.serialize(c_arr),
			Bbs.serialize(commitment_arr),
			Bbs.serialize([K, ...keybind_randomized_keys]),
			I2OSP(ph.byteLength, 8),
			ph
		);
		return await Bbs.hash_to_scalar(c_octs, hash_to_scalar_dst);
	}

	function commitment_state_to_octets(state: CommitState): BufferSource {
		const [C, s_hat, m_hat, challenge, keybind_public_keys] = state;
		const M = m_hat.length;
		const K = keybind_public_keys.length;
		return Bbs.serialize([M, K, C, s_hat, ...m_hat, challenge, ...keybind_public_keys]);
	}

	function octets_to_commitment_state(state_octs: BufferSource): CommitState {
		if (state_octs.byteLength < 16) {
			throw new Error("Invalid commitment state");
		}
		const state_octs_u8 = toU8(state_octs);
		const M = Number(OS2IP(state_octs_u8.slice(0, 8)));
		const K = Number(OS2IP(state_octs_u8.slice(8, 16)));
		if (state_octs.byteLength !== (16 + (1 + K) * octet_point_length + (2 + M) * octet_scalar_length)) {
			throw new Error("Invalid commitment state");
		}

		let sidx = 16;
		let eidx = sidx + octet_point_length;
		const C_octets = state_octs_u8.slice(sidx, eidx);
		const C = Bbs.octets_to_point_E1(C_octets);
		if (C.is0()) {
			throw new Error("Invalid commitment");
		}
		sidx = eidx;

		const s = [];
		for (let j = 0; j <= M + 1; ++j) {
			eidx = sidx + octet_scalar_length;
			const s_j = OS2IP(state_octs_u8.slice(sidx, eidx));
			if (s_j === 0n || s_j >= Fr.ORDER) {
				throw new Error("Invalid scalar");
			}
			s.push(s_j);
			sidx = eidx;
		}

		const PKs = [];
		for (let i = 1; i <= K; ++i) {
			eidx = sidx + octet_point_length;
			const PK_i_octs = state_octs_u8.slice(sidx, eidx);
			const PK_i = Bbs.octets_to_point_E1(PK_i_octs);
			if (PK_i.is0()) {
				throw new Error("Invalid public key");
			}
			PKs.push(PK_i);
			sidx = eidx;
		}

		const m_hat = s.slice(1, 1+M);
		const challenge = s[M + 1];
		return [C, s[0], m_hat, challenge, PKs];
	}

	function commitment_with_proof_to_octets(
		commitment: [PointG1, PointG1[]],
		proof: [bigint, bigint[], bigint, BufferSource[]],
	): BufferSource {
		const [C, keybind_public_keys] = commitment;
		const [s_hat, m_hat, challenge, keybind_signatures] = proof;
		const M = m_hat.length;
		const K = keybind_public_keys.length;
		if (keybind_signatures.length !== K) {
			throw new Error("Invalid keybind_signatures length");
		}

		const proof_octs = concat(
			Bbs.serialize([
				M, K, C, ...keybind_public_keys,
				s_hat, ...m_hat, challenge,
			]),
			...keybind_signatures,
		);
		return proof_octs;
	}

	function octets_to_commitment_with_proof(
		commitment_octs: Uint8Array,
	): [[PointG1, PointG1[]], [bigint, bigint[], bigint, BufferSource[]]] {
		if (commitment_octs.byteLength < 16) {
			throw new Error("Invalid commitment");
		}
		const commitment_octs_u8 = toU8(commitment_octs);
		const M = Number(OS2IP(commitment_octs_u8.slice(0, 8)));
		const K = Number(OS2IP(commitment_octs_u8.slice(8, 16)));
		const expect_len = 16
			+ (1 + K) * octet_point_length
			+ (2 + M) * octet_scalar_length
			+ K * Sig.signature_length;
		if (commitment_octs.byteLength !== expect_len) {
			throw new Error(`Invalid commitment length: expected ${expect_len} octets (M=${M}, K=${K}, Sig=${Sig.signature_length}), was ${commitment_octs.byteLength}`);
		}

		let sidx = 16;
		const C_octets = commitment_octs_u8.slice(sidx, sidx + octet_point_length);
		const C = Bbs.octets_to_point_E1(C_octets);
		if (C.is0()) {
			throw new Error("Invalid commitment");
		}
		sidx = sidx + octet_point_length;

		const PKs = [];
		for (let i = 1; i <= K; ++i) {
			const eidx = sidx + octet_point_length;
			const PK_i_octs = commitment_octs_u8.slice(sidx, eidx);
			const PK_i = Bbs.octets_to_point_E1(PK_i_octs);
			if (PK_i.is0()) {
				throw new Error("Invalid public key");
			}
			PKs.push(PK_i);
			sidx = eidx;
		}

		const s = [];
		for (let j = 0; j <= M + 1; ++j) {
			const eidx = sidx + octet_scalar_length;
			const s_j = OS2IP(commitment_octs_u8.slice(sidx, eidx));
			if (s_j === 0n || s_j >= Fr.ORDER) {
				throw new Error("Invalid scalar");
			}
			s.push(s_j);
			sidx = eidx;
		}

		const keybind_signatures = [];
		for (let i = 1; i <= K; ++i) {
			const eidx = sidx + Sig.signature_length;
			keybind_signatures.push(commitment_octs_u8.slice(sidx, eidx));
			sidx = eidx;
		}

		const msg_commitments = s.slice(1, M + 1);
		const challenge = s[M + 1];
		return [[C, PKs], [s[0], msg_commitments, challenge, keybind_signatures]];
	}

	function proof_gen_state_to_octets(
		bbs_proof: BufferSource,
		challenge: bigint,
		commitments_proof: [PointG1[], bigint[]],
		keybind_randomized_keys: PointG1[],
		keybind_randomizers: bigint[],
	): BufferSource {
		const [commitments, commitment_proofs] = commitments_proof;
		const N = commitments.length;
		if (commitment_proofs.length !== N) {
			throw new Error("Invalid commitment_proofs");
		}
		const K = keybind_randomized_keys.length;
		if (keybind_randomizers.length !== K) {
			throw new Error("Invalid keybind_randomizers");
		}
		return concat(
			Bbs.serialize([bbs_proof.byteLength, N, K]),
			bbs_proof,
			Bbs.serialize([
				...commitments, ...commitment_proofs,
				challenge, ...keybind_randomized_keys, ...keybind_randomizers]),
		);
	}

	function octets_to_proof_gen_state(
		state_octets: BufferSource,
	): [BufferSource, bigint, PointG1[], bigint[]] {
		if (state_octets.byteLength < 24) {
			throw new Error("Invalid proof generation state");
		}
		const state_octets_u8 = toU8(state_octets);
		const bbs_proof_len = Number(OS2IP(state_octets_u8.slice(0, 8)));
		const N = Number(OS2IP(state_octets_u8.slice(8, 16)));
		const K = Number(OS2IP(state_octets_u8.slice(16, 24)));
		const expect_len = 24 + bbs_proof_len + (N + K) * octet_point_length + (1 + N + K) * octet_scalar_length;
		if (state_octets.byteLength !== expect_len) {
			throw new Error(`Invalid proof generation state length: expected ${expect_len} octets (BBS=${bbs_proof_len}, N=${N}, K=${K}), was ${state_octets.byteLength}`);
		}

		let sidx = state_octets_u8.byteLength - K * (octet_point_length + octet_scalar_length);
		const incomplete_proof = state_octets_u8.slice(0, sidx - octet_scalar_length);
		const challenge = OS2IP(state_octets_u8.slice(sidx - octet_scalar_length, sidx));
		if (challenge === 0n || challenge >= Fr.ORDER) {
			throw new Error("Invalid scalar");
		}

		const PK_tildes = [];
		for (let i = 1; i <= K; ++i) {
			const eidx = sidx + octet_point_length;
			const PK_tilde_i = Bbs.octets_to_point_E1(state_octets_u8.slice(sidx, eidx));
			if (PK_tilde_i.is0()) {
				throw new Error("Invalid public key");
			}
			PK_tildes.push(PK_tilde_i);
			sidx = eidx;
		}

		const r_key = [];
		for (let i = 1; i <= K; ++i) {
			const eidx = sidx + octet_scalar_length;
			const r_key_i = OS2IP(state_octets_u8.slice(sidx, eidx));
			if (r_key_i === 0n || r_key_i >= Fr.ORDER) {
				throw new Error("Invalid scalar");
			}
			r_key.push(r_key_i);
			sidx = eidx;
		}

		return [incomplete_proof, challenge, PK_tildes, r_key];
	}

	function octets_to_proof(proof_octets: BufferSource): [
		[PointG1, PointG1, PointG1, bigint, bigint, bigint, bigint[], bigint],
		[PointG1[], bigint[]],
		[PointG1[], BufferSource[]],
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
		eidx = sidx + int_octet_length;
		if (proof_octets.byteLength < eidx) {
			throw new Error(`Proof too short: expected at least ${eidx} octets, was ${proof_octets.byteLength}`, { cause: { proof_octets, eidx } });
		}
		const N = Number(OS2IP(proof_octets_u8.slice(sidx, eidx)));

		sidx = eidx;
		eidx = sidx + int_octet_length;
		if (proof_octets.byteLength < eidx) {
			throw new Error("Proof too short", { cause: { proof_octets_u8 } });
		}
		const K = Number(OS2IP(proof_octets_u8.slice(sidx, eidx)));

		const expect_len = 3 * int_octet_length + bbs_proof_len
			+ N * (octet_point_length + octet_scalar_length)
			+ K * (octet_point_length + Sig.signature_length);
		if (proof_octets.byteLength !== expect_len) {
			throw new Error(`Invalid proof: expected ${expect_len} octets (BBS=${bbs_proof_len}, N=${N}, K=${K}), was ${proof_octets.byteLength}`, { cause: { proof_octets, expect_len } });
		}

		sidx = eidx;
		eidx = sidx + bbs_proof_len;
		if (proof_octets.byteLength < eidx) {
			throw new Error(`Proof too short: expected at least ${eidx} octets, was ${proof_octets.byteLength}`, { cause: { proof_octets, eidx } });
		}
		const bbs_proof_octs = proof_octets_u8.slice(sidx, eidx);
		const bbs_proof = Bbs.octets_to_proof(bbs_proof_octs);

		const C = [];
		for (let i = 1; i <= N; ++i) {
			sidx = eidx;
			eidx = sidx + octet_point_length;
			const C_i = Bbs.octets_to_point_E1(proof_octets_u8.slice(sidx, eidx));
			if (C_i.is0()) {
				throw new Error("Invalid commitment");
			}
			// TODO: Check that @noble/curves does the subgroup check
			C.push(C_i);
		}

		const s = [];
		for (let i = 1; i <= N; ++i) {
			sidx = eidx;
			eidx = sidx + octet_scalar_length;
			const s_i = OS2IP(proof_octets_u8.slice(sidx, eidx));
			if (s_i <= 0n || s_i >= r) {
				throw new Error(`Scalar out of range: ${s_i}`, { cause: { s_i, r } });
			}
			s.push(s_i);
		}

		const commitments_proof: [PointG1[], bigint[]] = [C, s];

		const PK_tildes = [];
		for (let i = 1; i <= K; ++i) {
			sidx = eidx;
			eidx = sidx + octet_point_length;
			const PK_tilde_i = Bbs.octets_to_point_E1(proof_octets_u8.slice(sidx, eidx));
			if (PK_tilde_i.is0()) {
				throw new Error("Invalid public key");
			}
			// TODO: Check that @noble/curves does the subgroup check
			PK_tildes.push(PK_tilde_i);
		}

		const keybind_signatures = [];
		for (let i = 1; i <= K; ++i) {
			sidx = eidx;
			eidx = sidx + Sig.signature_length;
			keybind_signatures.push(proof_octets_u8.slice(sidx, eidx));
		}

		if (proof_octets.byteLength !== eidx) {
			throw new Error(
				proof_octets.byteLength > eidx ? "Trailing octets" : "Insufficcient octets",
				{ cause: { proof_octets, eidx } },
			);
		}

		return [bbs_proof, commitments_proof, [PK_tildes, keybind_signatures]];
	}

	return {
		api_id,
		Commit,
		BlindSign,
		VerifyBlindSign,
		BlindProofGen,
		BlindProofGenInit,
		BlindProofGenFinalize,
		BlindProofVerify,
		CommitInit,
		CommitFinalize,
		CommitVerify: (commitment_with_proof) => deserialize_and_validate_commit(commitment_with_proof, api_id),
		CoreCommitInit,
		CoreCommitFinalize,
		CoreCommitVerify,
		Sig,
	};
}

export type PointG1 = WeierstrassPoint<bigint>;
type PointG2 = WeierstrassPoint<Fp2>;

export type DisclosureChoice = "DISCLOSE" | "HIDE" | "COMMIT";

type CommitState = [PointG1, bigint, bigint[], bigint, PointG1[]];
type BlindBbsSuite = {
	api_id: BufferSource,

	Commit(
		committed_messages: BufferSource[],
	): Promise<[BufferSource, bigint]>;

	CommitInit(
		committed_messages: BufferSource[] | null,
		keybind_public_keys: BufferSource[] | null,
	): Promise<[BufferSource, bigint, BufferSource]>;

	CommitFinalize(
		state: BufferSource,
		keybind_signatures: BufferSource[] | null,
	): Promise<BufferSource>;

	CommitVerify(
		commitment_with_proof: BufferSource,
	): Promise<[[PointG1, PointG1[]], PointG1[]]>;

	CoreCommitInit(
		blind_generators: PointG1[],
		committed_scalars: bigint[],
		keybind_public_keys: PointG1[],
		api_id: BufferSource,
	): Promise<[CommitState, bigint, bigint]>;

	CoreCommitFinalize(
		state: CommitState,
		keybind_signatures: BufferSource[],
	): Promise<[[PointG1, PointG1[]], [bigint, bigint[], bigint, BufferSource[]]]>;

	CoreCommitVerify(
		commitment: PointG1,
		keybind_public_keys: PointG1[],
		commitment_proof: [bigint, bigint[], bigint, BufferSource[]],
		blind_generators: PointG1[],
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
		issuer_known_messages_no: number | null,
		keybind_public_keys: BufferSource[] | null,
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

	BlindProofGenInit(
		PK: BufferSource,
		signature: BufferSource,
		header: BufferSource | null,
		ph: BufferSource | null,
		messages: BufferSource[] | null,
		issuer_known_messages_no: number | null,
		message_disclosures: DisclosureChoice[] | null,
		keybind_public_keys: BufferSource[] | null,
		secret_prover_blind: bigint | null,
	): Promise<[BufferSource, [bigint[], bigint[]], BufferSource[]]>;

	BlindProofGenFinalize(
		state: BufferSource,
		keybind_signatures: BufferSource[] | null,
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

	Sig: SignatureScheme,
}

export type SignatureScheme = {
	KeyGen(Hk: PointG1): Promise<[bigint, PointG1]>,
	Sign(Hk: PointG1, SK: bigint, message: BufferSource): Promise<BufferSource>,
	Verify(Hk: PointG1, PK: PointG1, sig: BufferSource, message: BufferSource): Promise<true>,
	AdaptSig(sig: BufferSource, r_key: bigint, message: BufferSource): Promise<BufferSource>,
	signature_length: number,
}

function NullSignatureScheme(): SignatureScheme {
	return {
		async KeyGen(_Hk: PointG1): Promise<[bigint, PointG1]> {
			throw new Error("Invalid");
		},
		async Sign(_Hk: PointG1, _SK: bigint, _message: BufferSource): Promise<BufferSource> {
			throw new Error("Invalid");
		},
		async Verify(_Hk: PointG1, _PK: PointG1, _sig: BufferSource, _message: BufferSource): Promise<true> {
			throw new Error("Invalid");
		},
		async AdaptSig(_sig: BufferSource, _r_key: bigint, _message: BufferSource): Promise<BufferSource> {
			throw new Error("Invalid");
		},
		signature_length: 0,
	};
}

export function SchnorrSignatureScheme(
	Bbs: Bbs.CipherSuite,
	hash: (msg: BufferSource) => Promise<bigint>,
	calculate_random_scalar: () => Promise<bigint>,
	calculate_random_nonce: ((Hk: PointG1, SK: bigint, message: BufferSource, i: number) => Promise<bigint>) | null,
): SignatureScheme {
	const { params: { curves: { fields: { Fp, Fr } }, octet_scalar_length } } = Bbs;
	calculate_random_nonce = calculate_random_nonce || calculate_random_scalar;

	// const serializeNoncePoint = (r: PointG1) => Bbs.serialize([r]);
	const serializeNoncePoint = (r: PointG1) => concat(
		new Uint8Array([0x04]),
		Fp.toBytes(r.toAffine().x),
		Fp.toBytes(r.toAffine().y),
	);

	return {
		async KeyGen(Hk: PointG1): Promise<[bigint, PointG1]> {
			const SK = await calculate_random_scalar();
			return [SK, Hk.multiply(SK)];
		},

		async Sign(Hk: PointG1, SK: bigint, message: BufferSource): Promise<BufferSource> {
			for (let i = 0; true; ++i) {
				const k_tilde = await calculate_random_nonce(Hk, SK, message, i);
				const R = Hk.multiply(k_tilde);
				const c = await hash(concat(serializeNoncePoint(R), message));
				if (c < Fr.ORDER) {
					const k_hat = Fr.add(k_tilde, Fr.mul(SK, c));
					return Bbs.serialize([k_hat, c]);
				}
			}
		},

		async Verify(Hk: PointG1, PK: PointG1, sig: BufferSource, message: BufferSource): Promise<true> {
			const sig_u8 = toU8(sig);
			if (sig.byteLength !== 2 * octet_scalar_length) {
				throw new Error("Invalid signature");
			}
			const s = OS2IP(sig_u8.slice(0, octet_scalar_length));
			const c = OS2IP(sig_u8.slice(octet_scalar_length, octet_scalar_length * 2));
			if (s >= Fr.ORDER || c >= Fr.ORDER) {
				throw new Error("Invalid signature");
			}
			const R = Hk.multiply(s).subtract(PK.multiply(c));
			const cv = Fr.create(await hash(concat(serializeNoncePoint(R), message)));
			if (cv === c) {
				return true;
			}
			throw new Error(`Invalid signature: ${cv} != ${c}`);
		},

		async AdaptSig(sig: BufferSource, r_key: bigint, _message: BufferSource): Promise<BufferSource> {
			const sig_u8 = toU8(sig);
			if (sig.byteLength !== 2 * octet_scalar_length) {
				throw new Error("Invalid signature");
			}
			const s = OS2IP(sig_u8.slice(0, octet_scalar_length));
			const c = OS2IP(sig_u8.slice(octet_scalar_length, octet_scalar_length * 2));
			if (s >= Fr.ORDER || c >= Fr.ORDER) {
				throw new Error("Invalid signature");
			}
			return Bbs.serialize([Fr.add(s, Fr.mul(c, r_key)), c]);
		},

		signature_length: 2 * octet_scalar_length,
	};
}

function BlsSignatureScheme(
	Bbs: Bbs.CipherSuite,
	hash: (msg: BufferSource) => Promise<PointG2>,
	calculate_random_scalar: () => Promise<bigint>,
): SignatureScheme {
	const { params: { curves: { fields: { Fp12 }, pairing: h }, octet_point_length } } = Bbs;
	return {
		async KeyGen(Hk: PointG1): Promise<[bigint, PointG1]> {
			const SK = await calculate_random_scalar();
			return [SK, Hk.multiply(SK)];
		},

		async Sign(_Hk: PointG1, SK: bigint, message: BufferSource): Promise<BufferSource> {
			const R = await hash(message);
			return Bbs.serialize([R.multiply(SK)]);
		},

		async Verify(Hk: PointG1, PK: PointG1, sig: BufferSource, message: BufferSource): Promise<true> {
			const S = Bbs.octets_to_point_E2(sig);
			if (Fp12.eql(h(Hk, S), h(PK, await hash(message)))) {
				return true;
			}
			throw new Error("Invalid signature");
		},

		async AdaptSig(sig: BufferSource, r_key: bigint, message: BufferSource): Promise<BufferSource> {
			const S = Bbs.octets_to_point_E2(sig);
			return Bbs.serialize([S.add((await hash(message)).multiply(r_key))]);
		},

		signature_length: 2 * octet_point_length,
	};
}

export type CipherSuite = {
	id: SuiteId,
	params: Bbs.SuiteParams,
	Bbs: Bbs.CipherSuite,
	BlindBbs: BlindBbsSuite,
}

export type SuiteId = (Bbs.SuiteId
	| "BBS-SCHNORR_BLS12381G1_XMD:SHA-256_SSWU_RO_"
	| "BBS-BLS_BLS12381G1_XMD:SHA-256_SSWU_RO_"
);

export function getCipherSuite(
	suiteId: SuiteId,
	overrides?: {
		mocked_random_scalars_params?: { SEED: BufferSource, DST: BufferSource },
		create_generators_dsts?: Bbs.CreateGeneratorsDsts,
	},
): CipherSuite {
	let Sig: SignatureScheme;
	let BbsSuite: Bbs.CipherSuite;

	switch (suiteId) {
		case "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_": {
			BbsSuite = Bbs.getCipherSuite(suiteId, overrides);
			Sig = NullSignatureScheme();
			break;
		}

		case "BBS-SCHNORR_BLS12381G1_XMD:SHA-256_SSWU_RO_": {
			BbsSuite = Bbs.getCipherSuite("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_", overrides);
			Sig = SchnorrSignatureScheme(
				BbsSuite,
				async (msg) => OS2IP(await sha256(msg)),
				async () => (await BbsSuite.real_calculate_random_scalars(1))[0],
				null,
			);
			break;
		}

		case "BBS-BLS_BLS12381G1_XMD:SHA-256_SSWU_RO_": {
			BbsSuite = Bbs.getCipherSuite("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_", overrides);
			Sig = BlsSignatureScheme(
				BbsSuite,
				async (msg) => BbsSuite.params.curves.G2.hashToCurve(
					toU8(msg),
					{ DST: toUtf8('BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_') },
				),
				async () => (await BbsSuite.calculate_random_scalars(1))[0],
			);
			break;
		}

		default:
			throw new Error(`Unknown suite: ${suiteId}`, { cause: { suiteId } });
	}

	if (BbsSuite) {
		return {
			id: suiteId,
			params: BbsSuite.params,
			Bbs: BbsSuite,
			BlindBbs: createSuite(suiteId, BbsSuite, Sig),
		};
	} else {
		throw new Error(`Unknown suite: ${suiteId}`, { cause: { suiteId } });
	}
}
