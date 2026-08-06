import { assert, describe, it } from "vitest";

import { fromHex, toHex, toU8, toUtf8 } from "../utils/util";
import { asyncAssertThrows } from "../testutil";
import { DisclosureChoice, getCipherSuite, PointG1 } from "./blind_bbs";


describe("Suite:", () => {

	const suiteId = 'BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_';

	describe(suiteId, () => {

		const suite = getCipherSuite(suiteId);
		const {
			Bbs: {
				serialize,
				hash_to_scalar,
				messages_to_scalars,
			},
			params: {
				curves: { G1 },
			},
		} = suite;

		describe("Blind BBS", async () => {
			const { BlindBbs } = suite;

			describe("create_generators (non-blind)", () => {
				const { create_unblind_generators } = BlindBbs;

				it("passes test vectors", async () => {
					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-generators
					const count = 11;
					const generators = await create_unblind_generators(count);
					const [Q1, ...H] = generators;

					assert.equal(generators.length, count);
					assert.equal(toHex(Q1.toBytes()), "8aa0382ea3cd294680e3425bb0bb9293210a4d3e94d8ba59096fcb24eb9b56546645bea83e170b078ff3cc5aeac18c49");
					assert.equal(toHex(H[0].toBytes()), "8065ec88f9bbee345b44e7825b2d602c91b0398b7c885d722450459c26efb1619eb4249428644b9e3d8d11d469d0c62b");
					assert.equal(toHex(H[1].toBytes()), "b96f3af9abcd3ee2228fbe97d4e5a0ef10aaf655c6889e284f27a732492ecdb64a91f92dbaa93f2a7fb550659935985f");
					assert.equal(toHex(H[2].toBytes()), "a99d1b53cc51738a46a7e1fe9b9d89a57977154dcccb7ce741eb779bf69ff655b110f0e97c4715616401e5a47d2c373a");
					assert.equal(toHex(H[3].toBytes()), "9791c624fec3d688975f9c9143f066404115e0dcc1e318ef4f5290c0103ee4a2857dbf9347d997ee507ab629216797f6");
					assert.equal(toHex(H[4].toBytes()), "8a472740d4968c831a3ad3d3c55ada8aca8478e4d0698ece52eff445d15aec1a479332e34562e80831b9593c85b435ec");
					assert.equal(toHex(H[5].toBytes()), "b5102a6529b39de47c136de78a8697395e11013f8aa91f695f158009b52985adee67a63fc354846b7f4b944349295c95");
					assert.equal(toHex(H[6].toBytes()), "845df3031a580f6c58b6d324f42f2158088a924dab9e77151851408a8bda31c266000c10bc47cc38aa3ac24dad22462c");
					assert.equal(toHex(H[7].toBytes()), "b4296c820736cafb7c9229cf499788314a4578de69e88832ca39babe36c48073e61968ae320f9bae61079724a5271eac");
					assert.equal(toHex(H[8].toBytes()), "9253f55dacd9e144f6da37f4adb420773325d142d900a6ae7de851c2643532e0b9181ae3ee02fe8c123b10dd12822876");
					assert.equal(toHex(H[9].toBytes()), "979a52e753c367e3baa8826e7b74a23856abca5468ba5ce5719b4c57eb7e9ee879935f98fbd6959661d3e866477063b2");
				});
			});

			describe("create_generators (blind)", () => {
				const { create_blind_generators } = BlindBbs;

				it("passes test vectors", async () => {
					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-blind-generators
					const count = 6;
					const generators = await create_blind_generators(count);
					const [Q2, ...J] = generators;

					assert.equal(generators.length, count);
					assert.equal(toHex(Q2.toBytes()), "a347532dc0ba9b83e4f15f3eeb7dffd934f5fa4668d927fbcb68096d5a26f6e59f66681201be1c263af1a25b6749759c");
					assert.equal(toHex(J[0].toBytes()), "af590ba56aa0e526a0763ae6926347dce988ffb9cc1a0b4510ada06fe08816f5c36a6c7007cc8558e5793f9a2cbae462");
					assert.equal(toHex(J[1].toBytes()), "a9a6e5f3093823745734a2195d80886f47185be6a3e4d00df2bd5996aa9d664e34244ea15e9ad4c41d8825331fcfd5a3");
					assert.equal(toHex(J[2].toBytes()), "a6c1a8fd251a338e25d3ea4e09334ea250f0257783f2be4ce4406798ea9acbce41e7648c7fb1409fcd822396f652c4e7");
					assert.equal(toHex(J[3].toBytes()), "80d1232ee4a5623d7ac5a3912c555f9f6f34716edfe156ae40b6ac19afba58dd18556e49529e39da91aa806c9c55d493");
					assert.equal(toHex(J[4].toBytes()), "b8775d3d2f58cafd808d135de79367f34c9ad22a6a878631fd0b1383541999b16b6f3bae96ab51bb4ab25caf69462473");
				});
			});

			describe("commitment", () => {
				describe("is consistent:", async () => {
					const { BlindBbs } = getCipherSuite(
						suiteId,
						{
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-mocked-random-scalars
							// with
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-commitment
							mocked_random_scalars_params: {
								SEED: toUtf8("3.141592653589793238462643383279"),
								DST: toUtf8("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_"),
							},
						},
					);
					const { create_keybind_generators } = BlindBbs;

					const committed_messages = [
						fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
						fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
						fromHex("835889a40744813a892eff9deb1edaeb"),
						fromHex("e1ca9729410dc6ba"),
						fromHex(""),
					];

					const prover_blind_scalars = [
						await hash_to_scalar(toUtf8("prover_blind_scalars.0"), toUtf8("Holder-blind BBS test")),
						await hash_to_scalar(toUtf8("prover_blind_scalars.1"), toUtf8("Holder-blind BBS test")),
						await hash_to_scalar(toUtf8("prover_blind_scalars.2"), toUtf8("Holder-blind BBS test")),
					];
					const keybind_generators = await create_keybind_generators(prover_blind_scalars.length);
					const committed_points: PointG1[] = (
						prover_blind_scalars
							.map((k, i) => keybind_generators[i].multiply(k))
					);

					describe("Public API:", async () => {
						const { Commit, CommitInit, CoreCommitProve, CommitFinalize, CommitVerify } = BlindBbs;

						const committed_points_serialized: BufferSource[] = committed_points.map(K => serialize([K]));

						it("commitment with no messages", async () => {
							const [commitment_with_proof, secret_prover_blind] = await Commit([]);
							assert.notEqual(secret_prover_blind, null);
							assert(await CommitVerify(commitment_with_proof));
						});

						it("commitment with prover messages", async () => {
							const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages);
							assert.notEqual(secret_prover_blind, null);
							assert(await CommitVerify(commitment_with_proof));
						});

						it("staged commitment with no messages", async () => {
							const [state, secret_prover_blind,] = await CommitInit(null, null);
							const commitment_with_proof = await CommitFinalize(state, null);
							assert.notEqual(secret_prover_blind, null);
							assert(await CommitVerify(commitment_with_proof));
						});

						it("staged commitment with prover messages", async () => {
							const [state, secret_prover_blind,] = await CommitInit(committed_messages, null);
							const commitment_with_proof = await CommitFinalize(state, null);
							assert.notEqual(secret_prover_blind, null);
							assert(await CommitVerify(commitment_with_proof));
						});

						it("staged commitment with prover-blind messages", async () => {
							const [state, secret_prover_blind, challenge] = await CommitInit(null, committed_points_serialized);
							const commitment_with_proof = await CommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => serialize(await CoreCommitProve(k, keybind_generators[i], challenge)))),
							);
							assert.notEqual(secret_prover_blind, null);
							assert(await CommitVerify(commitment_with_proof));
						});

						it("staged commitment with prover messages and prover-blind messages", async () => {
							const [state, secret_prover_blind, challenge] = await CommitInit(committed_messages, committed_points_serialized);
							const commitment_with_proof = await CommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => serialize(await CoreCommitProve(k, keybind_generators[i], challenge)))),
							);
							assert.notEqual(secret_prover_blind, null);
							assert(await CommitVerify(commitment_with_proof));
						});
					});

					describe("Core API:", async () => {
						const { CoreCommitInit, CoreCommitProve, CoreCommitFinalize, CoreCommitVerify, create_blind_generators } = BlindBbs;
						const api_id = toUtf8("Holder-blind BBS test");

						const committed_message_scalars = await messages_to_scalars(committed_messages, api_id);
						const blind_generators = await create_blind_generators(committed_messages.length + 1);

						describe("commitment with no messages", async () => {
							const generators = blind_generators.slice(0, 1);
							const [state, , secret_prover_blind] = await CoreCommitInit(generators, [], [], [], api_id);
							const [commitment, proof] = await CoreCommitFinalize(state, []);

							it("is valid", async () => {
								const [, point_commitments] = commitment;
								assert.notEqual(secret_prover_blind, null);
								assert.deepEqual(point_commitments, []);
								assert(await CoreCommitVerify(commitment, proof, generators, [], api_id));
							});

							it("is not valid if commitment is modified", async () => {
								const [message_commitment,] = commitment;
								await asyncAssertThrows(
									() => CoreCommitVerify([message_commitment.multiply(2n), []], proof, generators, [], api_id),
									"Expected modified message commitment to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify([message_commitment, [message_commitment]], proof, generators, [], api_id),
									"Expected modified point commitments to fail verification",
								);
							});

							it("is not valid if proof is modified", async () => {
								const [s_tilde, , challenge,] = proof;
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde + 1n, [], challenge, []], generators, [], api_id),
									"Expected modified s_tilde to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, [s_tilde], challenge, []], generators, [], api_id),
									"Expected modified m_tilde to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, [], challenge + 1n, []], generators, [], api_id),
									"Expected modified challenge to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, [], challenge, [[s_tilde, challenge]]], generators, [], api_id),
									"Expected modified point proofs to fail verification",
								);
							});
						});

						describe("commitment with prover messages", async () => {
							const generators = blind_generators.slice(0, 1 + committed_messages.length);
							const [state, , secret_prover_blind] = await CoreCommitInit(generators, [], committed_message_scalars, [], api_id);
							const [commitment, proof] = await CoreCommitFinalize(state, []);

							it("is valid", async () => {
								const [, point_commitments] = commitment;
								assert.notEqual(secret_prover_blind, null);
								assert.deepEqual(point_commitments, []);
								assert(await CoreCommitVerify(commitment, proof, generators, [], api_id));
							});

							it("is not valid if commitment is modified", async () => {
								const [message_commitment,] = commitment;
								await asyncAssertThrows(
									() => CoreCommitVerify([message_commitment.multiply(2n), []], proof, generators, [], api_id),
									"Expected modified message commitment to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify([message_commitment, [message_commitment]], proof, generators, [], api_id),
									"Expected modified point commitments to fail verification",
								);
							});

							it("is not valid if proof is modified", async () => {
								const [s_tilde, m_tilde, challenge,] = proof;
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde + 1n, m_tilde, challenge, []], generators, [], api_id),
									"Expected modified s_tilde to fail verification",
								);
								await Promise.all(m_tilde.map((_, i) =>
									asyncAssertThrows(
										() => CoreCommitVerify(commitment, [s_tilde, m_tilde.map((m, ii) => m + (ii === i ? 1n : 0n)), challenge, []], generators, [], api_id),
										"Expected modified m_tilde to fail verification",
									)));
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, m_tilde, challenge + 1n, []], generators, [], api_id),
									"Expected modified challenge to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, m_tilde, challenge, [[s_tilde, challenge]]], generators, [], api_id),
									"Expected modified point proofs to fail verification",
								);
							});
						});

						describe("commitment with prover-blind messages", async () => {
							const generators = blind_generators.slice(0, 1);
							const [state, challenge, secret_prover_blind] = await CoreCommitInit(
								generators,
								keybind_generators,
								[],
								committed_points,
								api_id,
							);
							const [commitment, proof] = await CoreCommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => await CoreCommitProve(k, keybind_generators[i], challenge))),
							);

							it("is valid", async () => {
								const [, point_commitments] = commitment;
								assert.notEqual(secret_prover_blind, null);
								assert.deepEqual(point_commitments, committed_points);
								assert(await CoreCommitVerify(commitment, proof, generators, keybind_generators, api_id));
							});

							it("is not valid if commitment is modified", async () => {
								const [message_commitment, point_commitments] = commitment;
								await asyncAssertThrows(
									() => CoreCommitVerify([message_commitment.multiply(2n), point_commitments], proof, generators, keybind_generators, api_id),
									"Expected modified message commitment to fail verification",
								);
								await Promise.all(point_commitments.map((_, i) =>
									asyncAssertThrows(
										() => CoreCommitVerify([message_commitment, point_commitments.map((p, ii) => ii === i ? p.multiply(2n) : p)], proof, generators, keybind_generators, api_id),
										"Expected modified point commitments to fail verification",
									)
								));;
							});

							it("is not valid if proof is modified", async () => {
								const [s_tilde, m_tilde, challenge, point_proofs] = proof;
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde + 1n, [], challenge, point_proofs], generators, keybind_generators, api_id),
									"Expected modified s_tilde to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, [s_tilde], challenge, point_proofs], generators, keybind_generators, api_id),
									"Expected modified m_tilde to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, [], challenge + 1n, point_proofs], generators, keybind_generators, api_id),
									"Expected modified challenge to fail verification",
								);
								await Promise.all(point_proofs.map(async (_, i) => {
									await asyncAssertThrows(
										() => CoreCommitVerify(
											commitment,
											[
												s_tilde,
												m_tilde,
												challenge,
												point_proofs.map<[bigint, bigint]>(([k_hat, c], ii) => [ii === i ? k_hat + 1n : k_hat, c]),
											],
											generators,
											keybind_generators,
											api_id,
										),
										"Expected modified point proofs to fail verification",
									);
									await asyncAssertThrows(
										() => CoreCommitVerify(
											commitment,
											[
												s_tilde,
												m_tilde,
												challenge,
												point_proofs.map<[bigint, bigint]>(([k_hat, c], ii) => [k_hat, ii === i ? c + 1n : c]),
											],
											generators,
											keybind_generators,
											api_id,
										),
										"Expected modified point proofs to fail verification",
									);
								}));
							});
						});

						describe("commitment with prover messages and prover-blind messages", async () => {
							const [state, challenge, secret_prover_blind] = await CoreCommitInit(
								blind_generators,
								keybind_generators,
								committed_message_scalars,
								committed_points,
								api_id,
							);
							const [commitment, proof] = await CoreCommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => await CoreCommitProve(k, keybind_generators[i], challenge))),
							);

							it("is valid", async () => {
								const [, point_commitments] = commitment;
								assert.notEqual(secret_prover_blind, null);
								assert.deepEqual(point_commitments, committed_points);
								assert(await CoreCommitVerify(commitment, proof, blind_generators, keybind_generators, api_id));
							});

							it("is not valid if commitment is modified", async () => {
								const [message_commitment, point_commitments] = commitment;
								await asyncAssertThrows(
									() => CoreCommitVerify([message_commitment.multiply(2n), point_commitments], proof, blind_generators, keybind_generators, api_id),
									"Expected modified message commitment to fail verification",
								);
								await Promise.all(point_commitments.map((_, i) =>
									asyncAssertThrows(
										() => CoreCommitVerify([message_commitment, point_commitments.map((p, ii) => ii === i ? p.multiply(2n) : p)], proof, blind_generators, keybind_generators, api_id),
										"Expected modified point commitments to fail verification",
									)
								));;
							});

							it("is not valid if proof is modified", async () => {
								const [s_tilde, m_tilde, challenge, point_proofs] = proof;
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde + 1n, [], challenge, point_proofs], blind_generators, keybind_generators, api_id),
									"Expected modified s_tilde to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, [s_tilde], challenge, point_proofs], blind_generators, keybind_generators, api_id),
									"Expected modified m_tilde to fail verification",
								);
								await asyncAssertThrows(
									() => CoreCommitVerify(commitment, [s_tilde, [], challenge + 1n, point_proofs], blind_generators, keybind_generators, api_id),
									"Expected modified challenge to fail verification",
								);
								await Promise.all(point_proofs.map(async (_, i) => {
									await asyncAssertThrows(
										() => CoreCommitVerify(
											commitment,
											[
												s_tilde,
												m_tilde,
												challenge,
												point_proofs.map<[bigint, bigint]>(([k_hat, c], ii) => [ii === i ? k_hat + 1n : k_hat, c]),
											],
											blind_generators,
											keybind_generators,
											api_id,
										),
										"Expected modified point proofs to fail verification",
									);
									await asyncAssertThrows(
										() => CoreCommitVerify(
											commitment,
											[
												s_tilde,
												m_tilde,
												challenge,
												point_proofs.map<[bigint, bigint]>(([k_hat, c], ii) => [k_hat, ii === i ? c + 1n : c]),
											],
											blind_generators,
											keybind_generators,
											api_id,
										),
										"Expected modified point proofs to fail verification",
									);
								}));
							});
						});
					});
				});
			});

			describe("signature", () => {
				describe("is consistent:", async () => {
					const { BlindBbs } = getCipherSuite(
						suiteId,
						{
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-mocked-random-scalars
							// with
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-commitment
							mocked_random_scalars_params: {
								SEED: toUtf8("3.141592653589793238462643383279"),
								DST: toUtf8("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_COMMIT_MOCK_RANDOM_SCALARS_DST_"),
							},
						},
					);
					const { create_keybind_generators } = BlindBbs;

					const committed_messages = [
						fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
						fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
						fromHex("835889a40744813a892eff9deb1edaeb"),
						fromHex("e1ca9729410dc6ba"),
						fromHex(""),
					];

					const prover_blind_scalars = [
						await hash_to_scalar(toUtf8("prover_blind_scalars.0"), toUtf8("Holder-blind BBS test")),
						await hash_to_scalar(toUtf8("prover_blind_scalars.1"), toUtf8("Holder-blind BBS test")),
						await hash_to_scalar(toUtf8("prover_blind_scalars.2"), toUtf8("Holder-blind BBS test")),
					];
					const keybind_generators = await create_keybind_generators(prover_blind_scalars.length);
					const committed_points: PointG1[] = (
						prover_blind_scalars
							.map((k, i) => keybind_generators[i].multiply(k))
					);

					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-proof-test-vectors
					const SK = 0x60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fcn;
					const PK = fromHex(
						"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa1" +
						"36f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d46" +
						"0acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63a" +
						"ebc364cd55ded0c"
					);
					const header = fromHex("11223344556677889900aabbccddeeff");

					const messages = [
						"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
						"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
						"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
						"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
						"496694774c5604ab1b2544eababcf0f53278ff50",
						"515ae153e22aae04ad16f759e07237b4",
						"d183ddc6e2665aa4e2f088af",
						"ac55fb33a75909ed",
						"96012096",
						"",
					].map(fromHex);

					describe("Public API:", async () => {
						const { BlindSign, VerifyBlindSign, Commit, CommitInit, CoreCommitProve, CommitFinalize } = BlindBbs;

						const committed_points_serialized: BufferSource[] = committed_points.map(K => serialize([K]));

						it("signature with no commitment or messages", async () => {
							const signature = await BlindSign(SK, PK, null, header, null);
							assert(await VerifyBlindSign(PK, signature, header, null, null, null, null));
						});

						it("signature with empty commitment and no messages", async () => {
							const [commitment_with_proof, secret_prover_blind] = await Commit([]);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							assert(await VerifyBlindSign(PK, signature, header, null, null, 0, secret_prover_blind));
						});

						it("signature with prover messages", async () => {
							const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							assert(await VerifyBlindSign(PK, signature, header, committed_messages, null, 0, secret_prover_blind));
						});

						it("signature on staged commitment with no messages", async () => {
							const [state, secret_prover_blind,] = await CommitInit(null, null);
							const commitment_with_proof = await CommitFinalize(state, null);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							assert(await VerifyBlindSign(PK, signature, header, null, null, 0, secret_prover_blind));
						});

						it("signature on staged commitment with prover messages", async () => {
							const [state, secret_prover_blind,] = await CommitInit(committed_messages, null);
							const commitment_with_proof = await CommitFinalize(state, null);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							assert(await VerifyBlindSign(PK, signature, header, committed_messages, null, 0, secret_prover_blind));
						});

						describe("signature with prover-blind messages", async () => {
							const [state, secret_prover_blind, challenge] = await CommitInit(null, committed_points_serialized);
							const commitment_with_proof = await CommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => serialize(await CoreCommitProve(k, keybind_generators[i], challenge)))),
							);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);

							it("is valid", async () => {
								assert(await VerifyBlindSign(PK, signature, header, null, committed_points_serialized, 0, secret_prover_blind));
							});

							it("is not valid if committed points are modified", async () => {
								await asyncAssertThrows(
									() => VerifyBlindSign(PK, signature, header, null, [], 0, secret_prover_blind),
									"Expected modified committed points to fail verification",
								);
								await asyncAssertThrows(
									() => VerifyBlindSign(
										PK,
										signature,
										header,
										null,
										committed_points_serialized.map(p => serialize([G1.Point.fromBytes(toU8(p)).multiply(2n)])),
										0,
										secret_prover_blind,
									),
									"Expected modified committed points to fail verification",
								);
							});
						});

						it("signature with prover-blind messages and signer messages", async () => {
							const [state, secret_prover_blind, challenge] = await CommitInit(null, committed_points_serialized);
							const commitment_with_proof = await CommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => serialize(await CoreCommitProve(k, keybind_generators[i], challenge)))),
							);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, messages);
							assert(await VerifyBlindSign(
								PK,
								signature,
								header,
								messages,
								committed_points_serialized,
								messages.length,
								secret_prover_blind,
							));
						});

						it("signature with prover messages, prover-blind messages and signer messages", async () => {
							const [state, secret_prover_blind, challenge] = await CommitInit(committed_messages, committed_points_serialized);
							const commitment_with_proof = await CommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => serialize(await CoreCommitProve(k, keybind_generators[i], challenge)))),
							);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, messages);
							assert(await VerifyBlindSign(
								PK,
								signature,
								header,
								[...messages, ...committed_messages],
								committed_points_serialized,
								messages.length,
								secret_prover_blind,
							));
						});
					});
				});
			});

			describe("proof", () => {
				describe("is consistent:", async () => {
					const { BlindBbs } = getCipherSuite(
						suiteId,
						{
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-08.html#name-mocked-random-scalars
							// with
							// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-commitment
							mocked_random_scalars_params: {
								SEED: toUtf8("3.141592653589793238462643383279"),
								DST: toUtf8("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_PROOF_MOCK_RANDOM_SCALARS_DST_"),
							},
						},
					);
					const { create_keybind_generators } = BlindBbs;

					const committed_messages = [
						fromHex("5982967821da3c5983496214df36aa5e58de6fa25314af4cf4c00400779f08c3"),
						fromHex("a75d8b634891af92282cc81a675972d1929d3149863c1fc0"),
						fromHex("835889a40744813a892eff9deb1edaeb"),
						fromHex("e1ca9729410dc6ba"),
						fromHex(""),
					];

					const prover_blind_scalars = [
						await hash_to_scalar(toUtf8("prover_blind_scalars.0"), toUtf8("Holder-blind BBS test")),
						await hash_to_scalar(toUtf8("prover_blind_scalars.1"), toUtf8("Holder-blind BBS test")),
						await hash_to_scalar(toUtf8("prover_blind_scalars.2"), toUtf8("Holder-blind BBS test")),
					];
					const keybind_generators = await create_keybind_generators(prover_blind_scalars.length);
					const committed_points: PointG1[] = (
						prover_blind_scalars
							.map((k, i) => keybind_generators[i].multiply(k))
					);

					// https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-blind-signatures-02.html#name-proof-test-vectors
					const SK = 0x60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fcn;
					const PK = fromHex(
						"a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa1" +
						"36f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d46" +
						"0acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63a" +
						"ebc364cd55ded0c"
					);
					const header = fromHex("11223344556677889900aabbccddeeff");

					const messages = [
						"9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
						"c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
						"7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
						"77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
						"496694774c5604ab1b2544eababcf0f53278ff50",
						"515ae153e22aae04ad16f759e07237b4",
						"d183ddc6e2665aa4e2f088af",
						"ac55fb33a75909ed",
						"96012096",
						"",
					].map(fromHex);

					const presentation_header = fromHex("bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501");

					describe("Public API:", async () => {
						const {
							BlindSign,
							BlindProofGen,
							BlindProofGenInit,
							BlindProofGenFinalize,
							BlindProofVerify,
							Commit,
							CommitInit,
							CoreCommitProve,
							CommitFinalize,
							BlindProofGenKeyProve,
							BlindProofGenKeyProveBls,
						} = BlindBbs;

						const committed_points_serialized: BufferSource[] = committed_points.map(K => serialize([K]));

						it("proof with no commitment or messages", async () => {
							const signature = await BlindSign(SK, PK, null, header, null);
							const [proof] = await BlindProofGen(PK, signature, header, presentation_header, null, null, null, null, null);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, null, null, null));
						});

						it("proof with empty commitment and no messages", async () => {
							const [commitment_with_proof, secret_prover_blind] = await Commit([]);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							const [proof] = await BlindProofGen(
								PK, signature, header, presentation_header,
								null, null, null, null,
								secret_prover_blind,
							);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, null, null, null));
						});

						it("proof with all prover messages disclosed", async () => {
							const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							const committed_message_disclosures: DisclosureChoice[] = committed_messages.map(() => "DISCLOSE");
							const [proof] = await BlindProofGen(
								PK, signature, header, presentation_header,
								null, committed_messages, null, committed_message_disclosures,
								secret_prover_blind,
							);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, 0, committed_messages, committed_message_disclosures));
						});

						it("proof with all prover messages committed", async () => {
							const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							const committed_message_disclosures: DisclosureChoice[] = committed_messages.map(() => "COMMIT");
							const [proof] = await BlindProofGen(
								PK, signature, header, presentation_header,
								null, committed_messages, null, committed_message_disclosures,
								secret_prover_blind,
							);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, 0, [], committed_message_disclosures));
						});

						it("proof with all prover messages hidden", async () => {
							const [commitment_with_proof, secret_prover_blind] = await Commit(committed_messages);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							const committed_message_disclosures: DisclosureChoice[] = committed_messages.map(() => "HIDE");
							const [proof] = await BlindProofGen(
								PK, signature, header, presentation_header,
								null, committed_messages, null, committed_message_disclosures,
								secret_prover_blind,
							);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, 0, [], committed_message_disclosures));
						});

						it("proof on staged commitment with no messages", async () => {
							const [state, secret_prover_blind,] = await CommitInit(null, null);
							const commitment_with_proof = await CommitFinalize(state, null);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							const [proof] = await BlindProofGen(
								PK, signature, header, presentation_header,
								null, null, null, null,
								secret_prover_blind,
							);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, null, null, null));
						});

						it("proof on staged commitment with all prover messages disclosed", async () => {
							const [state, secret_prover_blind,] = await CommitInit(committed_messages, null);
							const commitment_with_proof = await CommitFinalize(state, null);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							const committed_message_disclosures: DisclosureChoice[] = committed_messages.map(() => "DISCLOSE");
							const [proof] = await BlindProofGen(
								PK, signature, header, presentation_header,
								null, committed_messages, null, committed_message_disclosures,
								secret_prover_blind,
							);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, 0, committed_messages, committed_message_disclosures));
						});

						it("proof on staged commitment with all prover messages committed", async () => {
							const [state, secret_prover_blind,] = await CommitInit(committed_messages, null);
							const commitment_with_proof = await CommitFinalize(state, null);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							const committed_message_disclosures: DisclosureChoice[] = committed_messages.map(() => "COMMIT");
							const [proof] = await BlindProofGen(
								PK, signature, header, presentation_header,
								null, committed_messages, null, committed_message_disclosures,
								secret_prover_blind,
							);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, 0, [], committed_message_disclosures));
						});

						it("proof on staged commitment with all prover messages hidden", async () => {
							const [state, secret_prover_blind,] = await CommitInit(committed_messages, null);
							const commitment_with_proof = await CommitFinalize(state, null);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, null);
							const committed_message_disclosures: DisclosureChoice[] = committed_messages.map(() => "HIDE");
							const [proof] = await BlindProofGen(
								PK, signature, header, presentation_header,
								null, committed_messages, null, committed_message_disclosures,
								secret_prover_blind,
							);
							assert(await BlindProofVerify(PK, proof, header, presentation_header, 0, [], committed_message_disclosures));
						});

						it("proof on staged commitment with mixed disclosures and multiple prover binding keys", async () => {
							const [state, secret_prover_blind, challenge] = await CommitInit(committed_messages, committed_points_serialized);
							const commitment_with_proof = await CommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => serialize(await CoreCommitProve(k, keybind_generators[i], challenge)))),
							);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, messages);
							const options: DisclosureChoice[] = ["DISCLOSE", "COMMIT", "HIDE"];
							const message_disclosures: DisclosureChoice[] = messages.map((_, i) => options[i % 4]);
							const committed_message_disclosures: DisclosureChoice[] = committed_messages.map((_, i) => options[i % 4]);
							const [proof_state,, dpk_challenges] = await BlindProofGenInit(
								PK, signature, header, presentation_header,
								messages, committed_messages, committed_points_serialized,
								message_disclosures, committed_message_disclosures,
								secret_prover_blind,
							);
							const proof = await BlindProofGenFinalize(
								proof_state,
								await Promise.all(prover_blind_scalars.map((dsk, i) =>
									BlindProofGenKeyProve(keybind_generators[i], dsk, dpk_challenges[i])
								)),
							);
							assert(await BlindProofVerify(
								PK,
								proof,
								header,
								presentation_header,
								messages.length,
								[
									...messages.filter((_, i) => message_disclosures[i] === "DISCLOSE"),
									...committed_messages.filter((_, i) => committed_message_disclosures[i] === "DISCLOSE"),
								],
								[...message_disclosures, ...committed_message_disclosures],
							));
						});

						it("proof on staged commitment with mixed disclosures and multiple prover binding keys with both Schnorr and BLS proofs", async () => {
							const [state, secret_prover_blind, challenge] = await CommitInit(committed_messages, committed_points_serialized);
							const commitment_with_proof = await CommitFinalize(
								state,
								await Promise.all(prover_blind_scalars.map(
									async (k, i) => serialize(await CoreCommitProve(k, keybind_generators[i], challenge)))),
							);
							const signature = await BlindSign(SK, PK, commitment_with_proof, header, messages);
							const options: DisclosureChoice[] = ["DISCLOSE", "COMMIT", "HIDE"];
							const message_disclosures: DisclosureChoice[] = messages.map((_, i) => options[i % 4]);
							const committed_message_disclosures: DisclosureChoice[] = committed_messages.map((_, i) => options[i % 4]);
							const [proof_state,, dpk_challenges] = await BlindProofGenInit(
								PK, signature, header, presentation_header,
								messages, committed_messages, committed_points_serialized,
								message_disclosures, committed_message_disclosures,
								secret_prover_blind,
							);
							const proof = await BlindProofGenFinalize(
								proof_state,
								await Promise.all(prover_blind_scalars.map((dsk, i) =>
									i === 1
									? BlindProofGenKeyProveBls(dsk, dpk_challenges[i])
									: BlindProofGenKeyProve(keybind_generators[i], dsk, dpk_challenges[i])
								)),
							);
							assert(await BlindProofVerify(
								PK,
								proof,
								header,
								presentation_header,
								messages.length,
								[
									...messages.filter((_, i) => message_disclosures[i] === "DISCLOSE"),
									...committed_messages.filter((_, i) => committed_message_disclosures[i] === "DISCLOSE"),
								],
								[...message_disclosures, ...committed_message_disclosures],
							));
						});
					});
				});
			});
		});
	});
});
